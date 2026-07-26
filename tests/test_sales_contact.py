import json

import pytest

from app.workers.email_daemon import _build_message
from app.main import app as fastapi_app
from app.utils.pricing import PRICING_VERSION


from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_public_pricing_catalog_exposes_the_approved_contract(async_client):
    response = await async_client.get("/api/v1/sales/pricing")

    assert response.status_code == 200
    assert response.json() == {
        "version": PRICING_VERSION,
        "currency": "PKR",
        "taxes_included": False,
        "minimum_endpoints": 10,
        "maximum_endpoints": 50,
        "endpoint_monthly_price": 2_000,
        "one_time_setup_fee": 5_000,
        "annual_months": 12,
        "retention_months": [3, 6, 9, 12],
        "retention_included": True,
        "compliance_pack_monthly_prices": {
            "fbr_pos": 20_000,
            "peca_forensic": 25_000,
        },
    }

@pytest.mark.asyncio
@patch("redis.asyncio.client.Redis.lpush", new_callable=AsyncMock)
async def test_homepage_contact_lead_is_stored_and_queued(mock_lpush, async_client, db, redis_client):
    await db["sales_leads"].delete_many({})
    await redis_client.delete("email_alert_queue")

    response = await async_client.post(
        "/api/v1/sales/contact",
        json={
            "name": "Ayesha Khan",
            "email": "ayesha@example.com",
            "company": "Northstar Retail",
            "inquiry_type": "demo",
            "message": "We need a WarSOC demo for endpoint monitoring and FBR compliance.",
        },
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Request received successfully. Our team will contact you shortly."

    lead = await db["sales_leads"].find_one({"source": "homepage_contact"})
    assert lead is not None
    assert lead["lead_type"] == "general_inquiry"
    assert lead["contact_email"] == "ayesha@example.com"
    assert lead["company_name"] == "Northstar Retail"
    assert lead["inquiry_type"] == "demo"
    assert lead["status"] == "pending_sales_call"

    assert mock_lpush.call_count == 2
    call_args_list = mock_lpush.call_args_list
    job_types = {json.loads(call[0][1])["type"] for call in call_args_list}
    assert job_types == {"sales_contact", "sales_contact_confirmation"}


@pytest.mark.asyncio
async def test_homepage_contact_honeypot_does_not_store_or_queue(async_client, db, redis_client):
    await db["sales_leads"].delete_many({})
    await redis_client.delete("email_alert_queue")

    response = await async_client.post(
        "/api/v1/sales/contact",
        json={
            "name": "Bot User",
            "email": "bot@example.com",
            "company": "Spam Co",
            "inquiry_type": "demo",
            "message": "This should look valid but the hidden website field is filled.",
            "website": "https://spam.example.com",
        },
    )

    assert response.status_code == 200
    assert await db["sales_leads"].count_documents({"source": "homepage_contact"}) == 0
    assert await redis_client.llen("email_alert_queue") == 0


@pytest.mark.asyncio
async def test_quote_is_persisted_when_email_queue_is_unavailable(async_client, db):
    await db["sales_leads"].delete_many({})
    redis = fastapi_app.state.redis
    fastapi_app.state.redis = None
    try:
        response = await async_client.post(
            "/api/v1/sales/request-quote",
            json={
                "contact_name": "Pilot Buyer",
                "contact_email": "buyer@example.com",
                "company_name": "Pilot Company",
                "plan_type": "WarSOC Deployment",
                "endpoints": 15,
                "compliance_packs": ["fbr_pos", "peca_forensic"],
                "billing_cycle": "monthly",
                "pricing_version": PRICING_VERSION,
                "customization": {"endpoints": 15, "retentionMonths": 12},
            },
        )
    finally:
        fastapi_app.state.redis = redis

    assert response.status_code == 200, response.text
    assert response.json()["estimate"]["estimated_first_invoice"] == 80_000
    lead = await db["sales_leads"].find_one({"contact_email": "buyer@example.com"})
    assert lead["commercial_model"] == "public_list_price_manual_invoice"
    assert lead["pricing_version"] == PRICING_VERSION
    assert lead["server_estimate"]["monthly_recurring"] == 75_000
    assert lead["requested_retention_months"] == 12
    assert "backend_true_mrr" not in lead


@pytest.mark.asyncio
async def test_quote_rejects_a_stale_pricing_catalog(async_client):
    response = await async_client.post(
        "/api/v1/sales/request-quote",
        json={
            "contact_name": "Pilot Buyer",
            "contact_email": "stale-buyer@example.com",
            "company_name": "Pilot Company",
            "plan_type": "WarSOC Deployment",
            "endpoints": 15,
            "compliance_packs": ["fbr_pos"],
            "billing_cycle": "monthly",
            "pricing_version": "old-price-version",
            "customization": {"endpoints": 15, "retentionMonths": 3},
        },
    )

    assert response.status_code == 409


def test_email_daemon_builds_homepage_contact_messages():
    sales_message = _build_message(
        {
            "type": "sales_contact",
            "recipient": "sales@example.com",
            "payload": {
                "contact_name": "Ayesha Khan",
                "contact_email": "ayesha@example.com",
                "company_name": "Northstar Retail",
                "inquiry_type": "demo",
                "message": "Please schedule a platform demo.",
                "created_at": "2026-06-20T12:00:00Z",
            },
        }
    )
    confirmation_message = _build_message(
        {
            "type": "sales_contact_confirmation",
            "recipient": "ayesha@example.com",
            "payload": {
                "contact_name": "Ayesha Khan",
                "company_name": "Northstar Retail",
                "inquiry_type": "demo",
            },
        }
    )

    assert sales_message["To"] == "sales@example.com"
    assert sales_message["Subject"] == "CONTACT LEAD: Northstar Retail - Demo"
    assert "Please schedule a platform demo." in sales_message.get_content()
    assert confirmation_message["To"] == "ayesha@example.com"
    assert confirmation_message["Subject"] == "We received your WarSOC request"


def test_quote_emails_include_server_price_and_escape_html():
    estimate = {
        "pricing_version": PRICING_VERSION,
        "currency": "PKR",
        "recurring_total": 145_000,
        "one_time_setup_fee": 5_000,
        "estimated_first_invoice": 150_000,
    }
    sales_message = _build_message(
        {
            "type": "sales_quote",
            "recipient": "sales@example.com",
            "payload": {
                "contact_name": "Ayesha Khan",
                "contact_email": "ayesha@example.com",
                "company_name": "Northstar Retail",
                "plan_type": "WarSOC Deployment",
                "endpoints": 50,
                "compliance_packs": ["fbr_pos", "peca_forensic"],
                "billing_preference": "monthly",
                "customization": {"retention_months": 12},
                "server_estimate": estimate,
            },
        }
    )
    confirmation = _build_message(
        {
            "type": "sales_quote_confirmation",
            "recipient": "ayesha@example.com",
            "payload": {
                "contact_name": "<script>alert(1)</script>",
                "company_name": "Northstar Retail",
                "plan_type": "WarSOC Deployment",
                "endpoints": 50,
                "compliance_packs": ["fbr_pos", "peca_forensic"],
                "billing_preference": "monthly",
                "customization": {"retention_months": 12},
                "estimate": estimate,
            },
        }
    )

    assert "Requested General Archive: 12 months" in sales_message.get_content()
    assert "Recurring Estimate: PKR 145,000" in sales_message.get_content()
    assert "Estimated First Invoice: PKR 150,000" in sales_message.get_content()
    assert "Payment Method: Manual invoice" in sales_message.get_content()
    html = confirmation.get_body(preferencelist=("html",)).get_content()
    assert "Requested General Archive:</strong> 12 months" in html
    assert "Recurring Estimate:</strong> PKR 145,000" in html
    assert "Estimated First Invoice:</strong> PKR 150,000" in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_older_queued_quote_email_does_not_claim_a_zero_price():
    message = _build_message(
        {
            "type": "sales_quote",
            "recipient": "sales@example.com",
            "payload": {
                "contact_name": "Earlier Lead",
                "contact_email": "earlier@example.com",
                "company_name": "Earlier Company",
                "plan_type": "Earlier Request",
                "endpoints": 15,
                "compliance_packs": [],
                "billing_preference": "monthly",
                "customization": {"retention_months": 3},
            },
        }
    )

    body = message.get_content()
    assert "Manual review required for this earlier request" in body
    assert "PKR 0" not in body
