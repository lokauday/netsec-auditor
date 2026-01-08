"""Schemas for API key management."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator

from app.core.roles import VALID_ROLES, normalize_role


class APIKeyCreateRequest(BaseModel):
    """Request schema for creating a new API key."""
    name: str = Field(..., min_length=1, max_length=255, description="Label/name for the API key")
    role: str = Field(..., description="Role: viewer, operator, security_analyst, auditor, or admin")
    
    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        """Normalize and validate role."""
        return normalize_role(v)


class APIKeyResponse(BaseModel):
    """Response schema for API key (safe fields only)."""
    id: int
    name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None
    key_masked: Optional[str] = None  # First 8 chars + "..."
    
    model_config = {"from_attributes": True}


class APIKeyUpdateRequest(BaseModel):
    """Request schema for updating an API key."""
    label: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    
    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        """Normalize and validate role if provided."""
        if v is None:
            return None
        return normalize_role(v)


class APIKeyCreateResponse(BaseModel):
    """Response schema for API key creation (includes full key once)."""
    id: int
    name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    key: str  # Full key - only returned once on creation


class APIKeyListResponse(BaseModel):
    """Response schema for listing API keys."""
    items: list[APIKeyResponse]
    total: int

