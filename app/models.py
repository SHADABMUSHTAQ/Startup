from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class AnalysisRequest(BaseModel):
    file_type: str = "auto"

class AnalysisMetadata(BaseModel):
    file_name: str
    file_path: str
    file_type: str
    file_size: int
    analysis_duration: float
    analyzed_at: str
    analyzer_version: str

class AnalysisStatistics(BaseModel):
    total_events: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_type: Dict[str, int]
    events_processed_per_second: float

class Finding(BaseModel):
    id: str
    attack_type: str
    summary: str
    explanation: str
    severity: str
    evidence: List[str]
    source_ips: Optional[List[str]] = []
    confidence: float
    event_timestamp: Optional[str] = None
    count: Optional[int] = None

class AnalysisResponse(BaseModel):
    metadata: AnalysisMetadata
    statistics: AnalysisStatistics
    findings: List[Finding]
    status: str
    analysis_id: Optional[str] = None

class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str 
