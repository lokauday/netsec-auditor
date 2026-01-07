"""
API key authentication and RBAC for protected endpoints.
"""
import logging
from typing import Optional, Dict, Any
from fastapi import HTTPException, status, Security, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.api_key import APIKey

logger = logging.getLogger(__name__)

# Define the API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class APIClient:
    """Simple object representing an authenticated API client."""
    def __init__(self, source: str, role: str):
        self.source = source  # "static" or "db"
        self.role = role  # "admin" or "read_only" or "unknown"


def get_current_api_client(
    api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db)
) -> APIClient:
    """
    Dependency to verify API key and return API client info.
    
    Supports two modes:
    1. Static API key from environment (config.API_KEY)
    2. Database-backed API keys
    
    If config.API_KEY is set, accepts either the static key OR a DB API key.
    If config.API_KEY is not set, authentication is disabled (for testing/dev).
    
    Args:
        api_key: API key from X-API-Key header
        db: Database session
        
    Returns:
        APIClient object with source and role
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    # If API_KEY is not configured, skip authentication (for testing/dev)
    if not settings.API_KEY or settings.API_KEY.strip() == "":
        logger.debug("API_KEY not configured - authentication is disabled (TESTING mode)")
        return APIClient(source="static", role="admin")  # Default to admin in testing mode
    
    # Check if API key is provided
    if not api_key:
        logger.warning("API key missing from request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # First, check if it matches the static API key
    if api_key == settings.API_KEY:
        logger.debug("Authenticated with static API key")
        return APIClient(source="static", role="admin")
    
    # Then, check database API keys (using hash comparison)
    from app.api.v1.endpoints.api_keys import hash_api_key, verify_api_key_hash
    
    # Get all active keys and verify hash
    active_keys = db.query(APIKey).filter(APIKey.is_active == True).all()
    db_key = None
    
    for key in active_keys:
        if verify_api_key_hash(api_key, key.key_hash):
            db_key = key
            break
    
    if db_key:
        # Update last_used_at
        from datetime import datetime, timezone
        db_key.last_used_at = datetime.now(timezone.utc)
        db.commit()
        
        logger.debug(f"Authenticated with DB API key: {db_key.label or db_key.id} (role: {db_key.role})")
        return APIClient(source="db", role=db_key.role)
    
    # Invalid API key
    logger.warning(f"Invalid API key attempted: {api_key[:4]}...")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_role(min_role: str = "read_only"):
    """
    Dependency factory for role-based access control.
    
    Args:
        min_role: Minimum required role ("read_only" or "admin")
        
    Returns:
        Dependency function that checks role permissions
    """
    role_hierarchy = {
        "read_only": 1,
        "admin": 2,
    }
    
    def check_role(client: APIClient = Depends(get_current_api_client)) -> APIClient:
        """
        Check if the API client has the required role.
        
        Args:
            client: API client from get_current_api_client
            
        Returns:
            APIClient if authorized
            
        Raises:
            HTTPException: If client doesn't have required role
        """
        client_level = role_hierarchy.get(client.role, 0)
        required_level = role_hierarchy.get(min_role, 0)
        
        if client_level < required_level:
            logger.warning(
                f"Access denied: client role '{client.role}' does not meet minimum requirement '{min_role}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {min_role}",
            )
        
        return client
    
    return check_role


# Backward compatibility: keep verify_api_key for endpoints that haven't been updated yet
def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db)
) -> str:
    """
    Legacy dependency to verify API key (backward compatibility).
    
    Use get_current_api_client or require_role instead for new code.
    """
    client = get_current_api_client(api_key=api_key, db=db)
    return api_key or ""
