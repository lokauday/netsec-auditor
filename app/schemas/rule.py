"""Schemas for rule management."""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

from app.models.rule import RuleSeverity, RuleCategory


class RuleMatchCriteria(BaseModel):
    """Match criteria structure for rules."""
    # Pattern matching options
    pattern: Optional[str] = None  # Text pattern to search for in config
    pattern_type: Optional[str] = Field(None, description="regex, contains, equals, starts_with, ends_with")
    
    # ACL-specific matching
    acl_source: Optional[str] = None  # Source address pattern
    acl_destination: Optional[str] = None  # Destination address pattern
    acl_protocol: Optional[str] = None  # Protocol (tcp, udp, ip, etc.)
    acl_action: Optional[str] = None  # permit, deny
    
    # NAT-specific matching
    nat_source: Optional[str] = None
    nat_destination: Optional[str] = None
    
    # VPN-specific matching
    vpn_type: Optional[str] = None
    vpn_crypto: Optional[str] = None
    
    # Interface-specific matching
    interface_name: Optional[str] = None
    interface_type: Optional[str] = None
    
    # General matching
    config_section: Optional[str] = None  # Section of config to check
    field_name: Optional[str] = None  # Specific field to check
    field_value: Optional[str] = None  # Expected value


class RuleCreateRequest(BaseModel):
    """Request schema for creating a new rule."""
    name: str = Field(..., min_length=1, max_length=255, description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    vendor: Optional[str] = Field(None, description="Vendor filter (cisco_asa, cisco_ios, fortinet, palo_alto, or null for all)")
    category: RuleCategory = Field(RuleCategory.GENERAL, description="Rule category")
    match_criteria: Dict[str, Any] = Field(..., description="Match criteria (JSON)")
    severity: RuleSeverity = Field(RuleSeverity.MEDIUM, description="Rule severity")
    enabled: bool = Field(True, description="Whether rule is enabled")
    
    @field_validator("vendor")
    @classmethod
    def validate_vendor(cls, v: Optional[str]) -> Optional[str]:
        """Validate vendor string."""
        if v is None:
            return None
        valid_vendors = ["cisco_asa", "cisco_ios", "fortinet", "palo_alto"]
        if v.lower() not in valid_vendors:
            raise ValueError(f"Vendor must be one of: {', '.join(valid_vendors)}")
        return v.lower()


class RuleUpdateRequest(BaseModel):
    """Request schema for updating a rule."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    vendor: Optional[str] = None
    category: Optional[RuleCategory] = None
    match_criteria: Optional[Dict[str, Any]] = None
    severity: Optional[RuleSeverity] = None
    enabled: Optional[bool] = None
    
    @field_validator("vendor")
    @classmethod
    def validate_vendor(cls, v: Optional[str]) -> Optional[str]:
        """Validate vendor string."""
        if v is None:
            return None
        valid_vendors = ["cisco_asa", "cisco_ios", "fortinet", "palo_alto"]
        if v.lower() not in valid_vendors:
            raise ValueError(f"Vendor must be one of: {', '.join(valid_vendors)}")
        return v.lower() if v else None


class RuleResponse(BaseModel):
    """Response schema for rule."""
    id: int
    name: str
    description: Optional[str] = None
    vendor: Optional[str] = None
    category: RuleCategory
    match_criteria: Dict[str, Any]
    severity: RuleSeverity
    enabled: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[int] = None
    updated_by: Optional[int] = None
    
    model_config = {"from_attributes": True}


class RuleListResponse(BaseModel):
    """Response schema for rule list."""
    items: list[RuleResponse]
    total: int

