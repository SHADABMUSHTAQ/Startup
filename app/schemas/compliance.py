from pydantic import BaseModel
from typing import Any, Optional


class VerifyEvidenceRequest(BaseModel):
    raw_event: Optional[Any] = None  # Can be a dict or a string representing the payload
    digital_signature: str
    signed_payload: Optional[str] = None
