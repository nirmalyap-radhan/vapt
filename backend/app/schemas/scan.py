from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Any, Dict

class ScanRequest(BaseModel):
    url: HttpUrl

class HeaderFinding(BaseModel):
    name: str
    status: str
    severity: str
    description: str
    recommendation: str
    value: Optional[str] = None

class ScanResponse(BaseModel):
    target_url: str
    final_url: str
    status_code: int
    findings: List[HeaderFinding]

class ScanHistoryOut(BaseModel):
    id: int
    target_url: str
    scan_type: str
    score: Optional[int]
    risk_level: Optional[str]
    created_at: Any
    class Config:
        from_attributes = True
