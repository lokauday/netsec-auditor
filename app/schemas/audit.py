"""Schemas for security audit operations."""
from datetime import datetime
from typing import List, Dict, Any, Optional

from pydantic import BaseModel

from app.schemas.findings import SecurityFinding


class AuditBreakdown(BaseModel):
    """Breakdown of findings by severity."""
    critical: int
    high: int
    medium: int
    low: int


class AuditResponse(BaseModel):
    """Security audit response schema."""
    config_file_id: int
    vendor: str
    filename: str
    risk_score: int
    total_findings: int
    breakdown: AuditBreakdown
    summary: str
    findings: List[Dict[str, Any]]  # List of SecurityFinding dicts
    ai_enabled: bool = False
    ai_findings_count: int = 0


class AuditRecordSummary(BaseModel):
    """Summary schema for audit record in list views."""
    id: int
    config_file_id: int
    risk_score: int
    summary: str
    created_at: datetime
    
    model_config = {"from_attributes": True}


class AuditRecordResponse(BaseModel):
    """Response schema for a single audit record with full details."""
    id: int
    config_file_id: int
    risk_score: int
    summary: str
    breakdown: AuditBreakdown
    findings: List[Dict[str, Any]]
    created_at: datetime
    
    model_config = {"from_attributes": True}


class AuditHistoryResponse(BaseModel):
    """Response schema for audit history list."""
    items: List[AuditRecordSummary]
    total: int


class AuditHistoryItem(BaseModel):
    """Schema for audit history item with config metadata."""
    config_id: int
    filename: str
    vendor: str
    device_name: Optional[str] = None
    environment: Optional[str] = None
    uploaded_at: datetime
    risk_score: int
    total_findings: int


class AuditHistoryListResponse(BaseModel):
    """Response schema for filtered audit history."""
    items: List[AuditHistoryItem]
    total: int


class AuditSummaryResponse(BaseModel):
    """Response schema for audit summary/analytics."""
    total_configs_audited: int
    findings_by_severity: Dict[str, int]  # {"critical": 10, "high": 5, ...}
    average_risk_score: float
    findings_over_time: List[Dict[str, Any]]  # [{"date": "2024-01-01", "critical": 2, "high": 1, ...}, ...]
