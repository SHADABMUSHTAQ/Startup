"""Source-preserving FBR reconciliation contracts.

This module does not submit invoices to FBR and does not implement a database
or licensed-integrator connector. It defines and tests the reconciliation
boundary those future authenticated sources must satisfy.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


RECONCILIATION_VERSION = "fbr-reconciliation-contract-v1"


class ReconciliationOutcome(str, Enum):
    MATCHED = "MATCHED"
    MISMATCH = "MISMATCH"
    REJECTED = "REJECTED"
    PENDING = "PENDING"
    MISSING_LOCAL = "MISSING_LOCAL"
    MISSING_EXTERNAL = "MISSING_EXTERNAL"
    UNVERIFIED = "UNVERIFIED"


class FBRSourceEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    tenant_id: str = Field(min_length=1, max_length=100)
    invoice_id: str = Field(min_length=1, max_length=200)
    source_type: Literal["POS", "DB", "EXTERNAL"]
    source_identity: str = Field(min_length=1, max_length=200)
    source_record_id: str = Field(min_length=1, max_length=300)
    observed_at: datetime
    received_at: datetime
    raw_sha256: str
    replay_detected: bool = False

    seller_id: str | None = Field(default=None, max_length=100)
    buyer_id: str | None = Field(default=None, max_length=100)
    gross_amount: Decimal | None = None
    tax_amount: Decimal | None = None
    transaction_type: str | None = Field(default=None, max_length=100)
    invoice_timestamp: datetime | None = None
    submission_status: Literal["ACCEPTED", "REJECTED", "PENDING", "OFFLINE", "RETRYING"] | None = None
    external_reference: str | None = Field(default=None, max_length=300)

    @field_validator("raw_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("raw_sha256 must be 64-character lowercase hexadecimal")
        return normalized

    @field_validator("observed_at", "received_at", "invoice_timestamp")
    @classmethod
    def normalize_timestamp(cls, value):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("gross_amount", "tax_amount")
    @classmethod
    def non_negative_amount(cls, value):
        if value is not None and value < 0:
            raise ValueError("amounts cannot be negative")
        return value

    @model_validator(mode="after")
    def validate_source_contract(self):
        if self.source_type in {"POS", "DB"}:
            required = (
                self.seller_id,
                self.gross_amount,
                self.tax_amount,
                self.transaction_type,
                self.invoice_timestamp,
            )
            if any(value is None or value == "" for value in required):
                raise ValueError("POS and DB evidence require normalized invoice business fields")
            if self.submission_status is not None or self.external_reference is not None:
                raise ValueError("submission outcome fields belong only to EXTERNAL evidence")
        else:
            if self.submission_status is None:
                raise ValueError("EXTERNAL evidence requires submission_status")
            if self.submission_status in {"ACCEPTED", "REJECTED"} and not self.external_reference:
                raise ValueError("final external outcomes require external_reference")
        return self


def _decimal_string(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value.normalize(), "f")


def semantic_fingerprint(evidence: FBRSourceEvidence) -> str | None:
    if evidence.source_type == "EXTERNAL":
        return None
    payload = {
        "invoice_id": evidence.invoice_id,
        "seller_id": evidence.seller_id,
        "buyer_id": evidence.buyer_id,
        "gross_amount": _decimal_string(evidence.gross_amount),
        "tax_amount": _decimal_string(evidence.tax_amount),
        "transaction_type": evidence.transaction_type,
        "invoice_timestamp": evidence.invoice_timestamp.isoformat()
        if evidence.invoice_timestamp
        else None,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def reconcile_fbr_evidence(
    records: list[FBRSourceEvidence],
    *,
    late_db_after: timedelta = timedelta(hours=24),
) -> dict:
    if not records:
        return {
            "version": RECONCILIATION_VERSION,
            "outcome": ReconciliationOutcome.UNVERIFIED.value,
            "reasons": ["NO_EVIDENCE"],
            "confidence": "UNVERIFIED",
            "sources": [],
        }
    tenant_ids = {record.tenant_id for record in records}
    invoice_ids = {record.invoice_id for record in records}
    if len(tenant_ids) != 1 or len(invoice_ids) != 1:
        return {
            "version": RECONCILIATION_VERSION,
            "outcome": ReconciliationOutcome.UNVERIFIED.value,
            "reasons": ["MIXED_TENANT_OR_INVOICE"],
            "confidence": "UNVERIFIED",
            "sources": sorted({record.source_type for record in records}),
        }

    grouped = {
        source_type: [record for record in records if record.source_type == source_type]
        for source_type in ("POS", "DB", "EXTERNAL")
    }
    reasons = []
    if any(len(source_records) > 1 for source_records in grouped.values()):
        reasons.append("DUPLICATE_SOURCE_RECORD")
    if any(record.replay_detected for record in records):
        reasons.append("SOURCE_REPLAY_DETECTED")
    identities = [(record.source_type, record.source_identity, record.source_record_id) for record in records]
    if len(identities) != len(set(identities)):
        reasons.append("DUPLICATE_SOURCE_IDENTITY")
    if reasons:
        outcome = ReconciliationOutcome.UNVERIFIED
        confidence = "UNVERIFIED"
    else:
        pos = grouped["POS"][0] if grouped["POS"] else None
        database = grouped["DB"][0] if grouped["DB"] else None
        external = grouped["EXTERNAL"][0] if grouped["EXTERNAL"] else None
        pos_fingerprint = semantic_fingerprint(pos) if pos else None
        db_fingerprint = semantic_fingerprint(database) if database else None

        if pos is None or database is None:
            outcome = ReconciliationOutcome.MISSING_LOCAL
            confidence = "INCOMPLETE"
            if pos is None:
                reasons.append("POS_EVIDENCE_MISSING")
            if database is None:
                reasons.append("DB_EVIDENCE_MISSING")
        elif external and external.submission_status == "REJECTED":
            outcome = ReconciliationOutcome.REJECTED
            confidence = "OBSERVED"
            reasons.append("EXTERNAL_SUBMISSION_REJECTED")
            if pos_fingerprint != db_fingerprint:
                reasons.append("LOCAL_SEMANTIC_MISMATCH")
        elif pos_fingerprint != db_fingerprint:
            outcome = ReconciliationOutcome.MISMATCH
            confidence = "OBSERVED"
            reasons.append("LOCAL_SEMANTIC_MISMATCH")
        elif external is None:
            outcome = ReconciliationOutcome.MISSING_EXTERNAL
            confidence = "INCOMPLETE"
            reasons.append("EXTERNAL_EVIDENCE_MISSING")
        elif external.submission_status in {"PENDING", "OFFLINE", "RETRYING"}:
            outcome = ReconciliationOutcome.PENDING
            confidence = "INCOMPLETE"
            reasons.append(f"EXTERNAL_{external.submission_status}")
        elif external.submission_status == "ACCEPTED":
            outcome = ReconciliationOutcome.MATCHED
            confidence = "VERIFIED"
            reasons.append("LOCAL_SEMANTICS_MATCH_AND_EXTERNAL_ACCEPTED")
        else:
            outcome = ReconciliationOutcome.UNVERIFIED
            confidence = "UNVERIFIED"
            reasons.append("EXTERNAL_STATUS_UNSUPPORTED")

        if pos and database and database.observed_at - pos.observed_at > late_db_after:
            reasons.append("LATE_DB_EVIDENCE")
            if outcome == ReconciliationOutcome.MATCHED:
                confidence = "DEGRADED"

    fingerprints = {
        source_type: semantic_fingerprint(source_records[0])
        for source_type, source_records in grouped.items()
        if len(source_records) == 1 and source_type != "EXTERNAL"
    }
    return {
        "version": RECONCILIATION_VERSION,
        "tenant_id": records[0].tenant_id,
        "invoice_id": records[0].invoice_id,
        "outcome": outcome.value,
        "reasons": reasons,
        "confidence": confidence,
        "sources": sorted(source_type for source_type, values in grouped.items() if values),
        "raw_hashes": {record.source_type: record.raw_sha256 for record in records},
        "semantic_fingerprints": fingerprints,
        "production_claim": "CONTRACT_LAB_PROVEN_ONLY",
    }
