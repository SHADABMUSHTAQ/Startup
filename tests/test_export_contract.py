import json

from cryptography.fernet import Fernet

from app.routes import export


def test_compliance_csv_export_decrypts_sensitive_fields(monkeypatch):
    fernet = Fernet(Fernet.generate_key())
    monkeypatch.setattr(export, "_fernet", fernet)
    source = {
        "event_id": "FBR-INV-MOD",
        "message": fernet.encrypt(b"invoice changed").decode(),
        "processed_data": fernet.encrypt(
            json.dumps({"invoice_id": "INV-42"}).encode()
        ).decode(),
        "raw_data": {"already_plain": True},
    }

    prepared = export._prepare_csv_export_doc(source, decrypt_sensitive=True)

    assert prepared["message"] == "invoice changed"
    assert prepared["processed_data"] == {"invoice_id": "INV-42"}
    assert prepared["raw_data"] == {"already_plain": True}
    assert source["message"] != prepared["message"]


def test_non_compliance_csv_export_does_not_decrypt_fields(monkeypatch):
    fernet = Fernet(Fernet.generate_key())
    encrypted = fernet.encrypt(b"leave encrypted").decode()
    monkeypatch.setattr(export, "_fernet", fernet)

    prepared = export._prepare_csv_export_doc(
        {"message": encrypted},
        decrypt_sensitive=False,
    )

    assert prepared["message"] == encrypted
