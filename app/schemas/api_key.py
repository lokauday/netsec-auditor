"""Schemas for API key management."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class APIKeyCreateRequest(BaseModel):
    """Request schema for creating a new API key."""
    name: str = Field(..., min_length=1, max_length=255, description="Label/name for the API key")
    role: str = Field(..., description="Role: 'admin' or 'read_only'")


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

