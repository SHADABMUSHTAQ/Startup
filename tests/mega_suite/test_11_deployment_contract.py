"""
Deployment contract checks for the WarSOC pilot gate.

These tests are intentionally surgical and non-destructive. They validate that the
architecture claimed in deployment/audit material is actually present in the code
paths that docker-compose will run. Run these before any container-kill chaos tests;
if this file fails, chaos tests would only prove known configuration drift.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8", errors="replace")


def _compose_worker_modules() -> set[str]:
    modules: set[str] = set()
    for compose_name in ("docker-compose.yml", "docker-compose.prod.yml"):
        text = _read(compose_name)
        modules.update(re.findall(r"python(?:\",)?\s*,?\s*\"?-m\"?,?\s*\"?([\w.]+)", text))
        modules.update(re.findall(r"python\s+-m\s+([\w.]+)", text))
    return {module for module in modules if ".workers." in module}


def _active_worker_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    pending = list(_compose_worker_modules())
    while pending:
        module = pending.pop()
        if module in sources:
            continue
        relative = Path(*module.split(".")).with_suffix(".py")
        path = ROOT / relative
        source = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        sources[module] = source
        if not source:
            continue
        tree = ast.parse(source, filename=module)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.workers."):
                pending.append(node.module)
            elif isinstance(node, ast.Import):
                pending.extend(
                    alias.name
                    for alias in node.names
                    if alias.name.startswith("app.workers.")
                )
    return sources


@pytest.mark.hardening
def test_compose_worker_modules_are_importable_from_exact_runtime_paths():
    missing = []
    for module in sorted(_compose_worker_modules()):
        relative = Path(*module.split(".")).with_suffix(".py")
        if not (ROOT / relative).exists():
            missing.append(f"{module} -> {relative}")

    assert not missing, (
        "docker-compose references worker modules that do not exist. "
        "Fix compose commands or move worker files into the runtime package: "
        + ", ".join(missing)
    )


@pytest.mark.hardening
def test_active_worker_files_compile():
    compile_errors = []
    for module, source in sorted(_active_worker_sources().items()):
        if not source:
            continue
        try:
            ast.parse(source, filename=module)
        except SyntaxError as exc:
            compile_errors.append(f"{module}: {exc}")

    assert not compile_errors, "Worker source syntax errors: " + "; ".join(compile_errors)


@pytest.mark.hardening
def test_stream_workers_have_dead_consumer_reclaim_logic():
    workers = _active_worker_sources()
    stream_workers = {
        module: source
        for module, source in workers.items()
        if any(name in module for name in ("siem_worker", "peca_worker", "fbr_worker"))
    }
    assert stream_workers, "No active SIEM/PECA/FBR worker modules found in compose."

    missing_reclaim = [
        module
        for module, source in stream_workers.items()
        if "xautoclaim" not in source.lower() and "xclaim" not in source.lower()
    ]
    assert not missing_reclaim, (
        "Redis Streams consumers need XAUTOCLAIM/XCLAIM recovery before worker-kill "
        "chaos tests can prove losslessness. Missing in: "
        + ", ".join(sorted(missing_reclaim))
    )


@pytest.mark.hardening
def test_stream_worker_consumer_names_are_instance_unique():
    stream_workers = {
        module: source
        for module, source in _active_worker_sources().items()
        if any(name in module for name in ("siem_worker", "peca_worker", "fbr_worker"))
    }
    fixed_names = []
    for module, source in stream_workers.items():
        has_env_consumer = "CONSUMER_NAME" in source and ("os.getenv" in source or "CONSUMER_NAME" in os.environ)
        if "CONSUMER_NAME" in source and not has_env_consumer:
            fixed_names.append(module)

    assert not fixed_names, (
        "Multiple worker instances must not share one hard-coded Redis consumer name. "
        "Make CONSUMER_NAME env-driven for: " + ", ".join(sorted(fixed_names))
    )


@pytest.mark.hardening
def test_compliance_workers_persist_to_dedicated_vault_collections():
    sources = _active_worker_sources()
    peca_source = "\n".join(source for module, source in sources.items() if module.endswith("peca_worker"))
    fbr_source = "\n".join(source for module, source in sources.items() if module.endswith("fbr_worker"))

    assert "peca_forensic_logs" in peca_source, (
        "PECA worker must persist evidence to peca_forensic_logs, not only generic logs."
    )
    assert "fbr_pos_logs" in fbr_source, (
        "FBR worker must persist evidence to fbr_pos_logs, not only generic logs."
    )


@pytest.mark.hardening
def test_dead_letter_queue_is_not_documentation_only():
    worker_text = "\n".join(_active_worker_sources().values()).lower()
    assert "dlq" in worker_text or "dead_letter" in worker_text, (
        "At least one active worker must implement poison-pill routing to DLQ/dead_letter_logs."
    )


@pytest.mark.hardening
def test_claimed_security_and_business_features_have_real_backend_surface():
    route_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in (ROOT / "app" / "routes").glob("*.py"))
    app_text = _read("app/main.py") if (ROOT / "app" / "main.py").exists() else ""
    all_backend = route_text + "\n" + app_text

    checks = {
        "WebSocket ticket auth": "/ws/ticket",
        "metrics protection": "metrics_allowlist" or "metrics_bearer",
        "agent activation code": "activation_code",
        "MFA/TOTP for SOC users": "totp",
        "VirusTotal API route": "virustotal",
    }
    missing = [name for name, needle in checks.items() if needle.lower() not in all_backend.lower()]
    assert not missing, (
        "Claimed deployment features are missing backend route/config surface: "
        + ", ".join(missing)
    )


@pytest.mark.hardening
def test_virustotal_route_is_not_a_mock_green_check():
    threat_route = ROOT / "app" / "routes" / "threat_intel.py"
    threat_utils = ROOT / "app" / "utils" / "threat_intel.py"

    route_text = threat_route.read_text(encoding="utf-8", errors="replace").lower()
    utils_text = threat_utils.read_text(encoding="utf-8", errors="replace").lower() if threat_utils.exists() else ""

    mock_markers = [
        "mock virustotal",
        '"virustotal_positives": 0',
        '"reputation": "clean"',
        "'reputation': 'clean'",
    ]
    assert not any(marker in route_text for marker in mock_markers), (
        "VirusTotal route is a mock/static response. Wire it to the real threat intel "
        "manager or remove the deployment claim until it is real."
    )

    combined = route_text + "\n" + utils_text
    assert "api/v3/ip_addresses" in combined or "api/v3/files" in combined or "vt_api_key" in combined, (
        "VirusTotal integration must use the configured VT API client/key, not only expose a named route."
    )


@pytest.mark.hardening
def test_core_backend_runtime_files_are_tracked_by_git():
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"git unavailable for tracking check: {exc}")

    tracked = set(result.stdout.splitlines())
    required = {
        "app/main.py",
        "app/database.py",
        "app/routes/auth.py",
        "app/routes/ingest_pulse.py",
        "app/routes/threat_intel.py",
        "app/workers/siem_worker.py",
        "app/workers/peca_worker.py",
        "app/workers/fbr_worker.py",
        "nginx/nginx.conf",
    }
    missing = sorted(required - tracked)
    assert not missing, (
        "Restored runtime files are not tracked by git. Commit/deploy can omit the backend: "
        + ", ".join(missing)
    )


@pytest.mark.hardening
def test_private_keys_and_generated_certificates_are_not_tracked_by_git():
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"git unavailable for tracking check: {exc}")

    tracked = set(result.stdout.splitlines())
    forbidden = {
        "agent/agent_private_key.pem",
        "nginx/ssl/server.key",
        "nginx/ssl/server.crt",
        ".env",
        ".env.prod",
        ".env.pilot",
    }
    leaked = sorted(forbidden & tracked)
    assert not leaked, (
        "Generated secrets/certs must not be tracked. Remove from git tracking and rotate: "
        + ", ".join(leaked)
    )


@pytest.mark.hardening
def test_chaos_compose_uses_persistent_redis_when_testing_restarts():
    e2e_compose = ROOT / "docker-compose.e2e.yml"
    assert e2e_compose.exists(), "Create a dedicated docker-compose.e2e.yml for destructive chaos tests."

    text = e2e_compose.read_text(encoding="utf-8", errors="replace").lower()
    assert "--appendonly" in text and "yes" in text, (
        "Redis restart chaos tests require AOF persistence enabled in docker-compose.e2e.yml. "
        "Do not use prod compose as the chaos target."
    )
    assert "/data" in text and "volume" in text, (
        "Redis AOF needs a mounted volume in docker-compose.e2e.yml; otherwise restart/recreate "
        "chaos does not prove durable queue recovery."
    )
