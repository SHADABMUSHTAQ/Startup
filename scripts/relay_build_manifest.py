"""
Relay Build Manifest: Gate 1 reproducibility tool.

Verifies the pinned build toolchain, runs build_relay.bat, computes the
SHA-256 of the artifact, and records a manifest. A subsequent run with
--verify compares against the recorded manifest to prove reproducibility.

Usage:
    # Build and record the manifest
    python scripts/relay_build_manifest.py

    # Build and verify against the recorded manifest (reproducibility check)
    python scripts/relay_build_manifest.py --verify

    # Verify only (no build)
    python scripts/relay_build_manifest.py --verify --no-build

Exit codes:
    0 = success (built, verified, or both)
    1 = toolchain mismatch
    2 = build failed
    3 = hash mismatch (non-reproducible build)
"""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "relay" / "dist" / "warsoc_relay.exe"
MANIFEST = ROOT / "relay" / "dist" / "build-manifest.json"

# Pinned toolchain — must match requirements-relay-build.txt
PINNED_PYTHON = "3.13"
PINNED_VERSIONS = {
    "pyinstaller": "6.21.0",
    "cryptography": "50.0.0",
    "pydantic": "2.13.4",
    "httpx": "0.28.1",
}


def _installed_version(module_name: str) -> str | None:
    try:
        module = __import__(module_name)
        return getattr(module, "__version__", None)
    except ImportError:
        return None


def verify_toolchain() -> list[str]:
    """Return a list of toolchain mismatch descriptions (empty = OK)."""
    errors = []

    if not sys.version.startswith(PINNED_PYTHON):
        errors.append(
            f"Python {PINNED_PYTHON}.x required, found {platform.python_version()}"
        )

    module_names = {
        "pyinstaller": "PyInstaller",
        "cryptography": "cryptography",
        "pydantic": "pydantic",
        "httpx": "httpx",
    }
    for pin_name, module_name in module_names.items():
        expected = PINNED_VERSIONS[pin_name]
        actual = _installed_version(module_name)
        if actual is None:
            errors.append(f"{pin_name} not installed (expected {expected})")
        elif actual != expected:
            errors.append(
                f"{pin_name}=={expected} required, found {actual}"
            )

    return errors


def sha256_of(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def run_build() -> bool:
    """Run build_relay.bat. Returns True on success."""
    result = subprocess.run(
        ["cmd", "/c", str(ROOT / "build_relay.bat")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("BUILD FAILED")
        print(result.stdout)
        print(result.stderr)
        return False
    print(result.stdout.strip())
    return True


def write_manifest(artifact_hash: str) -> None:
    manifest = {
        "artifact": "relay/dist/warsoc_relay.exe",
        "sha256": artifact_hash,
        "size_bytes": ARTIFACT.stat().st_size,
        "toolchain": {
            "python": platform.python_version(),
            **{k: v for k, v in PINNED_VERSIONS.items()},
        },
        "platform": platform.platform(),
        "built_at": datetime.now(timezone.utc).isoformat(),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Manifest written: {MANIFEST}")
    print(f"  SHA-256: {artifact_hash}")
    print(f"  Size: {manifest['size_bytes']:,} bytes")


def verify_manifest() -> int:
    """Compare current artifact hash against the recorded manifest."""
    if not MANIFEST.exists():
        print("ERROR: No manifest found. Run without --verify first.")
        return 3
    if not ARTIFACT.exists():
        print("ERROR: Artifact not found. Run the build first.")
        return 2

    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    recorded_hash = recorded.get("sha256", "")
    actual_hash = sha256_of(ARTIFACT)

    print(f"Recorded SHA-256: {recorded_hash}")
    print(f"Actual   SHA-256: {actual_hash}")

    if actual_hash == recorded_hash:
        print("REPRODUCIBLE: hashes match.")
        return 0

    print("NOT REPRODUCIBLE: hashes differ.")
    print("This is expected if PyInstaller, Python, or source files changed.")
    print("If the change is intentional, re-run without --verify to update the manifest.")
    return 3


def main() -> int:
    parser = argparse.ArgumentParser(description="WarSOC relay build manifest tool")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify artifact hash against the recorded manifest",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip the build (only meaningful with --verify)",
    )
    args = parser.parse_args()

    # 1. Always verify the toolchain
    errors = verify_toolchain()
    if errors:
        print("TOOLCHAIN MISMATCH:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("Toolchain OK:")
    print(f"  Python {platform.python_version()}")
    for name, version in PINNED_VERSIONS.items():
        print(f"  {name}=={version}")

    # 2. Build (unless --verify --no-build)
    if not args.no_build:
        if not run_build():
            return 2
        if not ARTIFACT.exists():
            print("ERROR: Build reported success but artifact is missing.")
            return 2

    # 3. Verify or record
    if args.verify:
        return verify_manifest()

    artifact_hash = sha256_of(ARTIFACT)
    write_manifest(artifact_hash)
    return 0


if __name__ == "__main__":
    sys.exit(main())
