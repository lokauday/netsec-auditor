"""Schemas for rule pack management."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class RulePackRuleResponse(BaseModel):
    """Response schema for a rule in a pack."""
    id: int
    name: str
    description: Optional[str] = None
    severity: str
    category: str
    enabled: bool
    
    model_config = {"from_attributes": True}


class RulePackResponse(BaseModel):
    """Response schema for rule pack."""
    id: int
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    is_builtin: bool
    enabled: bool
    rule_count: int = 0
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class RulePackDetailResponse(RulePackResponse):
    """Extended response with rules."""
    rules: List[RulePackRuleResponse] = []


class RulePackListResponse(BaseModel):
    """Response schema for rule pack list."""
    items: List[RulePackResponse]
    total: int


class DeviceRulePackResponse(BaseModel):
    """Response schema for device-rule pack association."""
    id: int
    device_id: int
    rule_pack_id: int
    rule_pack_name: str
    enabled: bool
    created_at: datetime
    
    model_config = {"from_attributes": True}


class DeviceRulePackUpdateRequest(BaseModel):
    """Request schema for updating device-rule pack association."""
    enabled: bool = Field(True, description="Whether the pack is enabled for this device")

