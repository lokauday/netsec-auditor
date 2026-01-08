"""
Security findings schemas for audit results.
"""
from typing import List, Optional
from pydantic import BaseModel


class SecurityFinding(BaseModel):
    """Structured security finding from rule-based or AI analysis."""
    severity: str  # "low", "medium", "high", "critical"
    code: str  # e.g., "ACL_ANY_ANY_INBOUND"
    description: str
    affected_objects: List[str]
    recommendation: str
    
    # AI explainability fields (optional, populated when AI is enabled)
    ai_explanation: Optional[str] = None  # Detailed explanation of the finding
    business_impact: Optional[str] = None  # Business/operational impact
    attack_path: Optional[str] = None  # Potential attack scenario
    remediation_steps: Optional[str] = None  # Step-by-step remediation guidance


class AuditResultResponse(BaseModel):
    """Structured audit result response."""
    risk_score: int  # 0-100
    summary: str  # Short human-readable summary
    findings: List[SecurityFinding]

