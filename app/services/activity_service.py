"""
Activity logging service for audit trail.
"""
import logging
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import Request

from app.models.activity_log import ActivityLog
from app.core.auth import APIClient

logger = logging.getLogger(__name__)


def log_activity(
    db: Session,
    client: APIClient,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> ActivityLog:
    """
    Log an activity to the audit trail.
    
    Args:
        db: Database session
        client: Authenticated API client
        action: Action name (e.g., "config_upload", "audit_run", "rule_create")
        resource_type: Type of resource affected (e.g., "config_file", "audit", "rule")
        resource_id: ID of the affected resource
        details: Additional JSON details about the action
        request: FastAPI request object (for IP/user agent extraction)
        
    Returns:
        Created ActivityLog record
    """
    # Extract IP and user agent from request if available
    ip_address = None
    user_agent = None
    if request:
        # Get client IP (handles proxies)
        if request.client:
            ip_address = request.client.host
        # Check for X-Forwarded-For header (common in proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        user_agent = request.headers.get("User-Agent")
    
    activity = ActivityLog(
        actor_id=client.api_key_id,
        actor_source=client.source,
        actor_role=client.role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    
    db.add(activity)
    db.commit()
    db.refresh(activity)
    
    logger.debug(f"Logged activity: {action} by {client.role} ({client.source})")
    
    return activity


# Common action constants
class ActivityAction:
    """Constants for activity actions."""
    CONFIG_UPLOAD = "config_upload"
    CONFIG_PARSE = "config_parse"
    AUDIT_RUN = "audit_run"
    AUDIT_EXPORT = "audit_export"
    API_KEY_CREATE = "api_key_create"
    API_KEY_UPDATE = "api_key_update"
    API_KEY_DEACTIVATE = "api_key_deactivate"
    RULE_CREATE = "rule_create"  # For future use
    RULE_UPDATE = "rule_update"  # For future use
    RULE_DELETE = "rule_delete"  # For future use


# Common resource types
class ResourceType:
    """Constants for resource types."""
    CONFIG_FILE = "config_file"
    AUDIT = "audit"
    API_KEY = "api_key"
    RULE = "rule"  # For future use
    DEVICE = "device"  # For future use

