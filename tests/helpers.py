import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def ed25519_keypair_pem() -> tuple[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


async def provision_and_login_admin(
    client,
    prefix: str,
    *,
    api_prefix: str = "/api/v1",
    max_agents: int = 10,
) -> dict:
    unique = uuid.uuid4().hex[:8]
    username = f"{prefix}_{unique}"
    email = f"{username}@example.com"
    password = f"Ws!{uuid.uuid4().hex}9A"
    admin_key = os.environ["SUPER_ADMIN_API_KEY"]

    provision = await client.post(
        f"{api_prefix}/admin/provision",
        headers={"X-Admin-Key": admin_key},
        json={
            "company_name": f"{prefix} Test Tenant",
            "plan_type": "Enterprise",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "max_agents": max_agents,
            "admin_email": email,
            "admin_name": f"{prefix} Administrator",
            "admin_password": password,
            "retention_days": 365,
        },
    )
    assert provision.status_code == 200, provision.text

    login = await client.post(
        f"{api_prefix}/auth/login",
        json={"username": email, "password": password},
    )
    assert login.status_code == 200, login.text
    token = login.cookies.get("warsoc_token")
    csrf_token = login.json().get("csrf_token") or login.cookies.get("csrf_token")
    if token:
        client.cookies.set("warsoc_token", token)
    if csrf_token:
        client.cookies.set("csrf_token", csrf_token)
        client.headers.update({"x-csrf-token": csrf_token})

    return {
        "tenant_id": provision.json()["tenant_id"],
        "username": username,
        "email": email,
        "password": password,
        "token": token,
        "csrf_token": csrf_token,
    }
