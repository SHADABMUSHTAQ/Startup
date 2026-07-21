from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import get_db
from app.routes.auth import get_current_user
from app.utils.totp import (
    TOTP_DIGITS,
    TOTP_INTERVAL_SECONDS,
    TOTP_ISSUER,
    build_otpauth_uri,
    generate_totp_secret,
    protect_totp_secret,
    reveal_totp_secret,
    verify_totp,
)

router = APIRouter()

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    bio: Optional[str] = None
    avatar: Optional[str] = None
    billing_alerts: Optional[bool] = None
    product_updates: Optional[bool] = None


class TwoFactorCode(BaseModel):
    code: str


def _profile_from_user(user: dict) -> dict:
    return {
        "full_name": user.get("full_name") or user.get("name") or user.get("username") or "User",
        "email": user.get("email") or "",
        "phone": user.get("phone") or "",
        "company": user.get("company") or "",
        "role": user.get("role") or "user",
        "location": user.get("location") or "",
        "website": user.get("website") or "",
        "bio": user.get("bio") or "",
        "avatar": user.get("avatar") or "",
        "billing_alerts": bool(user.get("billing_alerts", True)),
        "product_updates": bool(user.get("product_updates", False)),
        "two_factor_enabled": bool(user.get("two_factor_enabled", False)),
    }


def _normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or "@" not in normalized:
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    return normalized


@router.get("/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    profile = _profile_from_user(current_user)
    return {
        "profile": profile,
        "plan_type": current_user.get("plan_type", "Free"),
        "role": profile["role"],
        "security": {
            "two_factor_enabled": profile["two_factor_enabled"],
            "billing_alerts": profile["billing_alerts"],
            "product_updates": profile["product_updates"],
        },
    }


@router.put("/profile")
async def update_profile(
    payload: ProfileUpdate,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    updates = {}
    for field in ("full_name", "phone", "company", "location", "website", "bio", "avatar"):
        value = getattr(payload, field)
        if value is not None:
            updates[field] = value.strip() if isinstance(value, str) else value

    if payload.email is not None:
        normalized_email = _normalize_email(str(payload.email))
        existing = await db["users"].find_one(
            {
                "email": normalized_email,
                "_id": {"$ne": current_user["_id"]},
            }
        )
        if existing:
            raise HTTPException(status_code=400, detail="Email address already in use")
        updates["email"] = normalized_email

    if payload.billing_alerts is not None:
        updates["billing_alerts"] = bool(payload.billing_alerts)

    if payload.product_updates is not None:
        updates["product_updates"] = bool(payload.product_updates)

    if updates:
        await db["users"].update_one({"_id": current_user["_id"]}, {"$set": updates})

    fresh_user = await db["users"].find_one({"_id": current_user["_id"]})
    if not fresh_user:
        raise HTTPException(status_code=404, detail="User not found")

    profile = _profile_from_user(fresh_user)
    response = {
        "profile": profile,
        "plan_type": fresh_user.get("plan_type", "Free"),
        "role": profile["role"],
        "security": {
            "two_factor_enabled": profile["two_factor_enabled"],
            "billing_alerts": profile["billing_alerts"],
            "product_updates": profile["product_updates"],
        },
    }

    return response


@router.get("/2fa/status")
async def two_factor_status(current_user: dict = Depends(get_current_user)):
    return {
        "two_factor_enabled": bool(current_user.get("two_factor_enabled", False)),
        "configured": bool(current_user.get("two_factor_secret")),
    }


@router.post("/2fa/setup")
async def setup_two_factor(
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if current_user.get("two_factor_enabled"):
        return {
            "two_factor_enabled": True,
            "message": "Two-factor protection is already enabled.",
        }

    secret = generate_totp_secret()
    username = current_user.get("email") or current_user.get("username") or "user"
    uri = build_otpauth_uri(username, secret)

    await db["users"].update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {
                "two_factor_pending_secret": protect_totp_secret(secret),
                "two_factor_pending_at": datetime.now(timezone.utc),
                "two_factor_enabled": False,
            }
        },
    )

    return {
        "two_factor_enabled": False,
        "secret": secret,
        "otpauth_uri": uri,
        "issuer": TOTP_ISSUER,
        "digits": TOTP_DIGITS,
        "period": TOTP_INTERVAL_SECONDS,
    }


@router.post("/2fa/verify")
async def verify_two_factor(
    payload: TwoFactorCode,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    pending_secret = current_user.get("two_factor_pending_secret")
    active_secret = current_user.get("two_factor_secret")
    stored_secret = pending_secret or active_secret

    if not stored_secret:
        raise HTTPException(status_code=400, detail="Two-factor setup has not been initiated")

    try:
        secret = reveal_totp_secret(stored_secret)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Two-factor verification is unavailable") from exc

    if not verify_totp(secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid verification code")

    await db["users"].update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {
                "two_factor_enabled": True,
                "two_factor_secret": protect_totp_secret(secret),
                "two_factor_verified_at": datetime.now(timezone.utc),
            },
            "$unset": {
                "two_factor_pending_secret": "",
                "two_factor_pending_at": "",
            },
        },
    )

    return {
        "two_factor_enabled": True,
        "message": "Two-factor protection enabled.",
    }


@router.post("/2fa/disable")
async def disable_two_factor(
    payload: TwoFactorCode,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    stored_secret = current_user.get("two_factor_secret")
    if not stored_secret:
        raise HTTPException(status_code=400, detail="Two-factor protection is not enabled")

    try:
        secret = reveal_totp_secret(stored_secret)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Two-factor verification is unavailable") from exc

    if not verify_totp(secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid verification code")

    await db["users"].update_one(
        {"_id": current_user["_id"]},
        {
            "$set": {"two_factor_enabled": False},
            "$unset": {
                "two_factor_secret": "",
                "two_factor_pending_secret": "",
                "two_factor_pending_at": "",
                "two_factor_verified_at": "",
            },
        },
    )

    return {
        "two_factor_enabled": False,
        "message": "Two-factor protection disabled.",
    }
