from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from datetime import datetime, timezone
import json
import logging
import os
from typing import Literal

from app.database import get_db
from app.utils.limiter import limiter
from app.utils.pricing import normalize_billing_cycle, normalize_compliance_packs
from app.utils.security_policy import PLATFORM_MAX_AGENTS

router = APIRouter()
logger = logging.getLogger(__name__)

class QuoteCustomization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoints: int | None = Field(default=None, ge=10, le=PLATFORM_MAX_AGENTS)
    retentionMonths: int = Field(default=0, ge=0, le=72)

    def normalized(self, fallback_endpoints: int) -> dict:
        retention_months = int(self.retentionMonths or 0)
        return {
            "endpoints": int(self.endpoints or fallback_endpoints),
            "retention_months": retention_months,
            "retention_days": retention_months * 30,
            "cold_archive_requested": retention_months > 0,
        }


class QuoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contact_name: str
    contact_email: EmailStr
    contact_phone: str | None = None
    company_name: str
    plan_type: str
    endpoints: int = Field(ge=10, le=PLATFORM_MAX_AGENTS)
    compliance_packs: list[str]
    billing_cycle: str
    # Accepted for compatibility with older frontend deployments only. The
    # public request endpoint never treats a browser-supplied price as a quote.
    frontend_calculated_total: float | None = None
    customization: QuoteCustomization = Field(default_factory=QuoteCustomization)


class ContactRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    company: str = Field(min_length=2, max_length=160)
    inquiry_type: Literal["demo", "compliance", "incident", "partnership"]
    message: str = Field(min_length=10, max_length=5000)
    website: str | None = Field(default=None, max_length=200)

@router.post("/request-quote")
@limiter.limit("3/minute")
async def request_quote(
    request: Request,
    data: QuoteRequest,
    db=Depends(get_db)
):
    """
    B2B Flow: Stores requested scope for manual commercial review and queues
    notifications. It does not create a price, invoice, or billing record.
    """
    redis = getattr(request.app.state, "redis", None)

    normalized_packs = normalize_compliance_packs(data.compliance_packs)
    billing_preference = normalize_billing_cycle(data.billing_cycle)
    customization = data.customization.normalized(fallback_endpoints=data.endpoints)
    
    # 2. Build the structured Lead Document
    lead_doc = {
        "contact_name": data.contact_name,
        "contact_email": data.contact_email,
        "contact_phone": data.contact_phone,
        "company_name": data.company_name,
        "plan_type": data.plan_type,
        "endpoints": data.endpoints,
        "compliance_packs": normalized_packs,
        "billing_preference": billing_preference,
        "commercial_model": "custom_contract_manual_invoice",
        "client_estimate_ignored": data.frontend_calculated_total,
        "customization": customization,
        "requested_retention_months": customization["retention_months"],
        "requested_retention_days": customization["retention_days"],
        "status": "pending_sales_call",
        "created_at": datetime.now(timezone.utc)
    }
    
    # Persist securely in MongoDB (The Vault)
    try:
        await db["sales_leads"].insert_one(lead_doc)
    except Exception as e:
        logger.error("Database unavailable: failed to save sales lead: %s", e)
        raise HTTPException(status_code=500, detail="Unable to submit the request right now.")

    if not redis:
        logger.error("Quote lead saved but the email queue is unavailable.")
        return {"message": "Quote request received successfully. Our team will contact you shortly."}

    # Queue the lead email to the sales team
    lead_job = {
        "type": "sales_quote",
        "recipient": os.getenv("SALES_EMAIL", "sales@warsoc.local"),
        "payload": {
            **{k: v for k, v in lead_doc.items() if k not in ["_id", "created_at"]},
            "created_at": lead_doc["created_at"].isoformat()
        }
    }
    
    # Also queue a confirmation email to the prospect
    prospect_job = {
        "type": "sales_quote_confirmation",
        "recipient": data.contact_email,
        "payload": {
            "contact_name": data.contact_name,
            "plan_type": data.plan_type,
            "company_name": data.company_name,
            "endpoints": data.endpoints,
            "compliance_packs": normalized_packs,
            "billing_preference": billing_preference,
            "customization": customization,
        }
    }

    try:
        await redis.lpush("email_alert_queue", json.dumps(lead_job))
        await redis.lpush("email_alert_queue", json.dumps(prospect_job))
    except Exception as e:
        logger.error("Failed to queue quote request: %s", e)
        # We don't throw 500 here because the lead is safely captured in the DB!
        
    return {"message": "Quote request received successfully. Our team will contact you shortly."}


@router.post("/contact")
@limiter.limit("5/minute")
async def contact_sales(
    request: Request,
    data: ContactRequest,
    db=Depends(get_db),
):
    """
    Public homepage contact flow. Captures general sales/demo/security inquiries
    in the WarSOC backend instead of relying on a third-party frontend form key.
    """
    if data.website and data.website.strip():
        return {"message": "Request received successfully. Our team will contact you shortly."}

    now = datetime.now(timezone.utc)
    lead_doc = {
        "source": "homepage_contact",
        "lead_type": "general_inquiry",
        "contact_name": data.name.strip(),
        "contact_email": str(data.email),
        "company_name": data.company.strip(),
        "inquiry_type": data.inquiry_type,
        "message": data.message.strip(),
        "status": "pending_sales_call",
        "created_at": now,
        "client_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }

    try:
        await db["sales_leads"].insert_one(lead_doc)
    except Exception as exc:
        logger.error("Database unavailable: failed to save contact lead: %s", exc)
        raise HTTPException(status_code=500, detail="Unable to submit the request right now.")

    redis = getattr(request.app.state, "redis", None)
    if not redis:
        logger.error("Redis unavailable: contact lead saved but email queue is offline.")
        return {"message": "Request received successfully. Our team will contact you shortly."}

    payload = {
        **{k: v for k, v in lead_doc.items() if k not in ["_id", "created_at"]},
        "created_at": now.isoformat(),
    }
    sales_job = {
        "type": "sales_contact",
        "recipient": os.getenv("SALES_EMAIL", "sales@warsoc.local"),
        "payload": payload,
    }
    confirmation_job = {
        "type": "sales_contact_confirmation",
        "recipient": str(data.email),
        "payload": {
            "contact_name": data.name.strip(),
            "company_name": data.company.strip(),
            "inquiry_type": data.inquiry_type,
        },
    }

    try:
        await redis.lpush("email_alert_queue", json.dumps(sales_job))
        await redis.lpush("email_alert_queue", json.dumps(confirmation_job))
    except Exception as exc:
        logger.error("Contact lead saved but failed to queue emails: %s", exc)

    return {"message": "Request received successfully. Our team will contact you shortly."}

