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

