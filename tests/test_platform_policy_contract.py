from pathlib import Path
import os

import pytest
from pydantic import ValidationError

from app.routes.admin import MAX_DAILY_INGEST_QUOTA_BYTES, ProvisionRequest
from app.routes.auth import InviteUserRequest, UpgradePlan, UserCreate
from app.routes.sales import QuoteRequest
from app.utils.pricing import calculate_package_price
from app.utils.security_policy import (
    PLATFORM_MAX_AGENTS,
    effective_agent_limit,
    validate_strong_password,
)


STRONG_PASSWORD = "WarSOC-Pilot-2026!"


def test_agent_ceiling_is_hard_capped_at_50():
    assert PLATFORM_MAX_AGENTS == 50
    assert effective_agent_limit(1000) == 50
    assert effective_agent_limit(50) == 50
    assert effective_agent_limit(15) == 15


@pytest.mark.parametrize(
    "password",
    [
        "Short1!",
        "alllowercase-2026!",
        "ALLUPPERCASE-2026!",
        "NoNumbersAllowed!!",
        "NoSymbolPassword2026",
    ],
)
def test_password_policy_rejects_weak_new_passwords(password):
    with pytest.raises(ValueError):
        validate_strong_password(password)


def test_all_new_account_models_share_strong_password_policy():
    assert validate_strong_password(STRONG_PASSWORD) == STRONG_PASSWORD

    UserCreate(
        username="policy-user",
        email="policy-user@example.com",
        password=STRONG_PASSWORD,
        full_name="Policy User",
    )
    ProvisionRequest(
        company_name="Policy Co",
        plan_type="Enterprise",
        max_agents=50,
        admin_email="admin@example.com",
        admin_name="Policy Admin",
        admin_password=STRONG_PASSWORD,
    )
    InviteUserRequest(
        email="analyst@example.com",
        role="analyst",
    )

    with pytest.raises(ValidationError):
        UserCreate(
            username="weak-user",
            email="weak@example.com",
            password="Password123!",
            full_name="Weak User",
        )


def test_every_commercial_contract_rejects_51_endpoints():
    with pytest.raises(ValidationError):
        ProvisionRequest(
            company_name="Too Large",
            plan_type="Enterprise",
            max_agents=51,
            admin_email="admin@example.com",
            admin_name="Policy Admin",
            admin_password=STRONG_PASSWORD,
        )
    with pytest.raises(ValidationError):
        UpgradePlan(
            plan_type="Enterprise",
            compliance_packs=[],
            endpoints=51,
            storage_gb=100,
            retention_months=12,
        )
    with pytest.raises(ValidationError):
        QuoteRequest(
            contact_name="Buyer",
            contact_email="buyer@example.com",
            company_name="Too Large",
            plan_type="Custom Platform",
            endpoints=51,
            compliance_packs=[],
            billing_cycle="monthly",
            frontend_calculated_total=0,
        )
    with pytest.raises(ValueError):
        calculate_package_price(
            endpoints=51,
            compliance_packs=[],
            billing_cycle="monthly",
        )


def test_admin_provisioning_rejects_oversized_daily_ingest_quota():
    ProvisionRequest(
        company_name="Quota OK",
        plan_type="Customized",
        max_agents=50,
        admin_email="quota-ok@example.com",
        admin_name="Quota Admin",
        admin_password=STRONG_PASSWORD,
        daily_ingest_quota_bytes=MAX_DAILY_INGEST_QUOTA_BYTES,
    )

    with pytest.raises(ValidationError):
        ProvisionRequest(
            company_name="Quota Too High",
            plan_type="Customized",
            max_agents=50,
            admin_email="quota-too-high@example.com",
            admin_name="Quota Admin",
            admin_password=STRONG_PASSWORD,
            daily_ingest_quota_bytes=MAX_DAILY_INGEST_QUOTA_BYTES + 1,
        )


@pytest.mark.asyncio
async def test_admin_provisioning_api_rejects_oversized_daily_ingest_quota(async_client, db):
    email = "quota-api-too-high@example.com"

    response = await async_client.post(
        "/api/v1/admin/provision",
        headers={"X-Admin-Key": os.environ["SUPER_ADMIN_API_KEY"]},
        json={
            "company_name": "Quota API Too High",
            "plan_type": "Customized",
            "compliance_packs": ["fbr_pos", "peca_forensic"],
            "max_agents": 50,
            "admin_email": email,
            "admin_name": "Quota Admin",
            "admin_password": STRONG_PASSWORD,
            "daily_ingest_quota_bytes": MAX_DAILY_INGEST_QUOTA_BYTES + 1,
        },
    )

    assert response.status_code == 422
    assert await db["users"].count_documents({"email": email}) == 0
    assert await db["tenants"].count_documents({"company_name": "Quota API Too High"}) == 0


def test_fifty_seat_enrollment_rate_limits_are_not_ten_per_minute():
    source = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "routes"
        / "agent_orchestration.py"
    ).read_text(encoding="utf-8")
    assert source.count('@limiter.limit("60/minute")') >= 2
    assert '@limiter.limit("120/minute")' in source
