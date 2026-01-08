"""Schemas for device management."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.models.device import EnvironmentType
from app.models.config_file import VendorType


class DeviceCreateRequest(BaseModel):
    """Request schema for creating a new device."""
    hostname: str = Field(..., min_length=1, max_length=255, description="Device hostname")
    mgmt_ip: Optional[str] = Field(None, description="Management IP address")
    vendor: Optional[VendorType] = Field(None, description="Device vendor")
    model: Optional[str] = Field(None, max_length=255, description="Device model")
    site: Optional[str] = Field(None, max_length=255, description="Site or data center name")
    environment: Optional[EnvironmentType] = Field(None, description="Environment type")
    owner: Optional[str] = Field(None, max_length=255, description="Owner or team")
    tags: Optional[List[str]] = Field(None, description="Tags as list of strings")


class DeviceUpdateRequest(BaseModel):
    """Request schema for updating a device."""
    hostname: Optional[str] = Field(None, min_length=1, max_length=255)
    mgmt_ip: Optional[str] = None
    vendor: Optional[VendorType] = None
    model: Optional[str] = Field(None, max_length=255)
    site: Optional[str] = Field(None, max_length=255)
    environment: Optional[EnvironmentType] = None
    owner: Optional[str] = Field(None, max_length=255)
    tags: Optional[List[str]] = None


class DeviceResponse(BaseModel):
    """Response schema for device."""
    id: int
    hostname: str
    mgmt_ip: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    site: Optional[str] = None
    environment: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    last_audit_id: Optional[int] = None
    last_risk_score: Optional[float] = None
    last_policy_hygiene_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class DeviceDetailResponse(DeviceResponse):
    """Extended device response with related configs and audits."""
    config_count: int = 0
    latest_config_id: Optional[int] = None
    latest_config_uploaded_at: Optional[datetime] = None


class DeviceListResponse(BaseModel):
    """Response schema for device list."""
    items: List[DeviceResponse]
    total: int

