"""
Security findings schemas for audit results.
"""
from typing import List
from pydantic import BaseModel


class SecurityFinding(BaseModel):
    """Structured security finding from rule-based or AI analysis."""
    severity: str  # "low", "medium", "high", "critical"
    code: str  # e.g., "ACL_ANY_ANY_INBOUND"
    description: str
    affected_objects: List[str]
    recommendation: str


class AuditResultResponse(BaseModel):
    """Structured audit result response."""
    risk_score: int  # 0-100
    summary: str  # Short human-readable summary
    findings: List[SecurityFinding]

