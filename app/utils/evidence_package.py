"""Deterministic signed evidence packages and offline verification."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.utils.compliance_chain import evidence_record_digest
from app.utils.evidence_custody import canonical_bytes, verify_custody_chain


PACKAGE_SCHEMA_VERSION = "warsoc-evidence-package-v1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_item_filename(case_item_id: str) -> str:
    value = "".join(char for char in str(case_item_id) if char.isalnum() or char in "-_")
    if not value:
        raise ValueError("Evidence case item ID cannot form a safe package path")
    return f"evidence/{value}.json"


def _load_private_key(private_key_pem: bytes, password: bytes | None = None):
    key = serialization.load_pem_private_key(private_key_pem, password=password)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("Evidence package signing requires RSA-2048 or stronger")
    return key


def build_evidence_package(
    package_dir: Path,
    *,
    case: dict,
    items: list[dict],
    evidence_records: dict[str, dict],
    custody_events: list[dict],
    private_key_pem: bytes,
    signing_key_id: str,
    signing_key_version: int,
    private_key_password: bytes | None = None,
) -> dict:
    """Write a signed package containing exact stored evidence representations."""

    package_dir = Path(package_dir).resolve()
    package_dir.mkdir(parents=True, exist_ok=False)
    (package_dir / "evidence").mkdir()

    files = []
    item_manifest = []
    package_paths: set[str] = set()
    for item in sorted(items, key=lambda value: str(value.get("case_item_id") or "")):
        case_item_id = str(item.get("case_item_id") or "")
        if case_item_id not in evidence_records:
            raise ValueError(f"Evidence record is missing for {case_item_id}")
        relative_path = _safe_item_filename(case_item_id)
        if relative_path in package_paths:
            raise ValueError("Evidence case item IDs collide after path normalization")
        package_paths.add(relative_path)
        evidence_record = evidence_records[case_item_id]
        payload = canonical_bytes(evidence_record)
        target = package_dir / relative_path
        target.write_bytes(payload)
        file_hash = _sha256(payload)
        expected_record_hash = str(item.get("evidence_record_hash") or "")
        actual_record_hash = evidence_record_digest(str(item.get("collection") or ""), evidence_record)
        if not expected_record_hash or actual_record_hash != expected_record_hash:
            raise ValueError(f"Evidence record hash mismatch for {case_item_id}")
        item_manifest.append(
            {
                "case_item_id": case_item_id,
                "collection": item.get("collection"),
                "document_id": item.get("document_id"),
                "event_uid": item.get("event_uid"),
                "evidence_record_hash": expected_record_hash,
                "package_file": relative_path,
                "package_file_sha256": file_hash,
            }
        )
        files.append({"path": relative_path, "sha256": file_hash, "bytes": len(payload)})

    committed_custody = [
        event for event in custody_events if event.get("state") == "COMMITTED"
    ]
    custody_verification = verify_custody_chain(committed_custody)
    if not custody_verification["verified"]:
        raise ValueError("Custody chain is not verified")
    custody_payload = canonical_bytes(committed_custody)
    (package_dir / "custody.json").write_bytes(custody_payload)
    files.append(
        {
            "path": "custody.json",
            "sha256": _sha256(custody_payload),
            "bytes": len(custody_payload),
        }
    )

    manifest = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "case_id": case.get("case_id"),
        "tenant_id": case.get("tenant_id"),
        "case_status": case.get("status"),
        "custody_head_hash": custody_verification["head_hash"],
        "custody_event_count": custody_verification["event_count"],
        "signing": {
            "algorithm": "RSA-PSS-SHA256",
            "key_id": signing_key_id,
            "key_version": int(signing_key_version),
        },
        "items": item_manifest,
        "files": sorted(files, key=lambda value: value["path"]),
    }
    manifest_bytes = canonical_bytes(manifest)
    private_key = _load_private_key(private_key_pem, private_key_password)
    signature = private_key.sign(
        manifest_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    (package_dir / "manifest.json").write_bytes(manifest_bytes)
    (package_dir / "manifest.sig").write_text(
        base64.b64encode(signature).decode("ascii"),
        encoding="ascii",
    )
    return manifest


def verify_evidence_package(package_dir: Path, trusted_public_key_pem: bytes) -> dict:
    package_dir = Path(package_dir).resolve()
    manifest_path = package_dir / "manifest.json"
    signature_path = package_dir / "manifest.sig"
    if not manifest_path.is_file() or not signature_path.is_file():
        return {"status": "MISSING", "verified": False}

    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if canonical_bytes(manifest) != manifest_bytes:
            return {"status": "MANIFEST_INVALID", "verified": False}
        if manifest.get("schema_version") != PACKAGE_SCHEMA_VERSION:
            return {"status": "MANIFEST_INVALID", "verified": False}
        files = manifest.get("files")
        items = manifest.get("items")
        if not isinstance(files, list) or not files or not isinstance(items, list):
            return {"status": "MANIFEST_INVALID", "verified": False}
        paths = [str(item.get("path") or "") for item in files]
        if paths != sorted(set(paths)):
            return {"status": "MANIFEST_INVALID", "verified": False}
        file_entries = {str(item.get("path") or ""): item for item in files}
        item_ids = [str(item.get("case_item_id") or "") for item in items]
        item_paths = [str(item.get("package_file") or "") for item in items]
        if (
            len(item_ids) != len(set(item_ids))
            or len(item_paths) != len(set(item_paths))
            or any(not item_id for item_id in item_ids)
            or any(path not in file_entries for path in item_paths)
            or set(item_paths) != {path for path in paths if path.startswith("evidence/")}
        ):
            return {"status": "MANIFEST_INVALID", "verified": False}
        for relative in paths:
            candidate = (package_dir / relative).resolve()
            if package_dir not in candidate.parents or candidate == package_dir:
                return {"status": "MANIFEST_INVALID", "verified": False}
    except Exception:
        return {"status": "MANIFEST_INVALID", "verified": False}

    try:
        public_key = serialization.load_pem_public_key(trusted_public_key_pem)
        signature = base64.b64decode(signature_path.read_text(encoding="ascii"), validate=True)
        public_key.verify(
            signature,
            manifest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError):
        return {"status": "SIGNATURE_INVALID", "verified": False}

    missing = []
    altered = []
    expected_paths = {"manifest.json", "manifest.sig"}
    for entry in manifest["files"]:
        relative = entry["path"]
        expected_paths.add(relative)
        target = package_dir / relative
        if not target.is_file():
            missing.append(relative)
            continue
        payload = target.read_bytes()
        if len(payload) != int(entry.get("bytes") or -1) or _sha256(payload) != entry.get("sha256"):
            altered.append(relative)
    for item in manifest["items"]:
        relative = item["package_file"]
        target = package_dir / relative
        if not target.is_file() or relative in altered:
            continue
        try:
            evidence_record = json.loads(target.read_bytes())
            actual_record_hash = evidence_record_digest(
                str(item.get("collection") or ""),
                evidence_record,
            )
        except Exception:
            altered.append(relative)
            continue
        if actual_record_hash != str(item.get("evidence_record_hash") or ""):
            altered.append(relative)
    actual_paths = {
        str(path.relative_to(package_dir)).replace("\\", "/")
        for path in package_dir.rglob("*")
        if path.is_file()
    }
    if actual_paths - expected_paths:
        return {
            "status": "MANIFEST_INVALID",
            "verified": False,
            "unexpected_files": sorted(actual_paths - expected_paths),
        }
    if missing:
        return {"status": "MISSING", "verified": False, "missing_files": missing}
    if altered:
        return {"status": "ALTERED", "verified": False, "altered_files": altered}
    return {
        "status": "VERIFIED",
        "verified": True,
        "case_id": manifest.get("case_id"),
        "tenant_id": manifest.get("tenant_id"),
        "file_count": len(manifest["files"]),
        "signing_key_id": (manifest.get("signing") or {}).get("key_id"),
        "signing_key_version": (manifest.get("signing") or {}).get("key_version"),
    }
