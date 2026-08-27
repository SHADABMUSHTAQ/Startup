import copy
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.utils.compliance_chain import evidence_record_digest
from app.utils.evidence_custody import CUSTODY_CHAIN_VERSION, custody_event_hash
from app.utils.evidence_package import build_evidence_package, verify_evidence_package


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _package(tmp_path):
    private_pem, public_pem = _keypair()
    evidence = {
        "tenant_id": "TENANT-A",
        "event_uid": "EVENT-A",
        "event_id": "4625",
        "timestamp": "2026-08-20T12:00:00+00:00",
        "raw_event_data": "fernet-v1:ciphertext",
    }
    item = {
        "case_item_id": "ITEM-A",
        "collection": "siem_cold_vault",
        "document_id": "record-a",
        "event_uid": "EVENT-A",
        "evidence_record_hash": evidence_record_digest("siem_cold_vault", evidence),
    }
    event = {
        "custody_event_id": "CUSTODY-A",
        "chain_version": CUSTODY_CHAIN_VERSION,
        "tenant_id": "TENANT-A",
        "case_id": "CASE-A",
        "case_item_id": None,
        "sequence": 1,
        "action": "CASE_CREATED",
        "actor_user_id": "user-a",
        "actor_email": "admin@example.com",
        "actor_role": "admin",
        "reason": "Evidence case created for an authorized investigation.",
        "request_id": "request-a",
        "metadata": {},
        "occurred_at": datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc),
        "previous_custody_hash": "0" * 64,
    }
    event["current_custody_hash"] = custody_event_hash(event)
    event["state"] = "COMMITTED"
    package_dir = tmp_path / "package"
    build_evidence_package(
        package_dir,
        case={"case_id": "CASE-A", "tenant_id": "TENANT-A", "status": "OPEN"},
        items=[item],
        evidence_records={"ITEM-A": evidence},
        custody_events=[event],
        private_key_pem=private_pem,
        signing_key_id="warsoc-evidence-signing",
        signing_key_version=1,
    )
    return package_dir, public_pem


def test_clean_evidence_package_verifies_offline(tmp_path):
    package_dir, public_pem = _package(tmp_path)
    result = verify_evidence_package(package_dir, public_pem)
    assert result["status"] == "VERIFIED"
    assert result["verified"] is True


def test_one_byte_change_is_reported_as_altered(tmp_path):
    package_dir, public_pem = _package(tmp_path)
    evidence_file = package_dir / "evidence" / "ITEM-A.json"
    evidence_file.write_bytes(evidence_file.read_bytes() + b"x")
    assert verify_evidence_package(package_dir, public_pem)["status"] == "ALTERED"


def test_missing_file_is_reported(tmp_path):
    package_dir, public_pem = _package(tmp_path)
    (package_dir / "custody.json").unlink()
    assert verify_evidence_package(package_dir, public_pem)["status"] == "MISSING"


def test_wrong_public_key_is_reported(tmp_path):
    package_dir, _public_pem = _package(tmp_path)
    _other_private, other_public = _keypair()
    assert verify_evidence_package(package_dir, other_public)["status"] == "SIGNATURE_INVALID"


def test_noncanonical_or_reordered_manifest_is_rejected(tmp_path):
    package_dir, public_pem = _package(tmp_path)
    manifest_path = package_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    assert verify_evidence_package(package_dir, public_pem)["status"] == "MANIFEST_INVALID"
