"""Schemas for activity log."""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class ActivityLogResponse(BaseModel):
    """Response schema for activity log entry."""
    id: int
    timestamp: datetime
    actor_id: Optional[int] = None
    actor_source: str
    actor_role: str
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    model_config = {"from_attributes": True}


class ActivityLogListResponse(BaseModel):
    """Response schema for activity log list."""
    items: List[ActivityLogResponse]
    total: int
    limit: int
    offset: int

