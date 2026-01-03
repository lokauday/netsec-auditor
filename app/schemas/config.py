"""Schemas for configuration file operations."""
from datetime import datetime
from typing import Optional, Dict, List, Any
from pydantic import BaseModel


class ConfigFileResponse(BaseModel):
    """Response schema for uploaded config file."""
    id: int
    filename: str
    vendor: str
    original_filename: str
    file_size: int
    uploaded_at: datetime
    parsed_at: Optional[datetime] = None
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    
    model_config = {"from_attributes": True}


class ConfigParseResponse(BaseModel):
    """Response schema for parsed config file."""
    config_file_id: int
    parsed: bool
    parsed_at: Optional[datetime]
    elements_parsed: Dict[str, int]


# Schemas for list and detail endpoints

class ConfigListItem(BaseModel):
    """Schema for a single config item in the list."""
    id: int
    filename: str
    vendor: str
    created_at: datetime
    has_parsed_data: bool
    has_audit_result: bool
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None


class ConfigListResponse(BaseModel):
    """Response schema for config list endpoint."""
    items: List[ConfigListItem]
    total: int
    limit: int
    offset: int


class ParsedDataDetail(BaseModel):
    """Schema for parsed data detail."""
    acls: List[Dict[str, Any]]
    nat_rules: List[Dict[str, Any]]
    vpns: List[Dict[str, Any]]
    interfaces: List[Dict[str, Any]]
    routes: List[Dict[str, Any]]


class ConfigDetailResponse(BaseModel):
    """Response schema for config detail endpoint."""
    id: int
    filename: str
    vendor: str
    original_filename: str
    file_size: int
    created_at: datetime
    parsed_at: Optional[datetime] = None
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    raw_content: Optional[str] = None
    raw_content_truncated: bool = False
    parsed_data: Optional[ParsedDataDetail] = None
    audit_result: Optional[Dict[str, Any]] = None

