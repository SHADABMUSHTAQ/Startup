import json

import pytest

from app.workers.email_daemon import _build_message


from unittest.mock import AsyncMock, patch

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
