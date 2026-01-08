"""
Rule model for custom security rules.
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Enum
from sqlalchemy.sql import func
import enum

from app.core.database import Base


class RuleSeverity(str, enum.Enum):
    """Rule severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleCategory(str, enum.Enum):
    """Rule categories."""
    ACL = "acl"
    NAT = "nat"
    VPN = "vpn"
    ROUTING = "routing"
    INTERFACE = "interface"
    CRYPTO = "crypto"
    AUTHENTICATION = "authentication"
    GENERAL = "general"


class Rule(Base):
    """Custom security rule model."""
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Rule matching criteria
    vendor = Column(String(50), nullable=True, index=True)  # cisco_asa, cisco_ios, fortinet, palo_alto, or null for all
    category = Column(Enum(RuleCategory), nullable=False, default=RuleCategory.GENERAL, index=True)
    match_criteria = Column(JSON, nullable=False)  # Flexible JSON structure for rule patterns
    
    # Rule metadata
    severity = Column(Enum(RuleSeverity), nullable=False, default=RuleSeverity.MEDIUM, index=True)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, nullable=True)  # API key ID or user ID
    updated_by = Column(Integer, nullable=True)
    
    # Optional: link to previous version for versioning
    previous_rule_id = Column(Integer, nullable=True)

