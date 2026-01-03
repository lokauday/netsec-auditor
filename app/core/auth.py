"""
API key authentication for protected endpoints.
"""
import logging
from fastapi import HTTPException, status, Security
from fastapi.security import APIKeyHeader

from app.core.config import settings

logger = logging.getLogger(__name__)

# Define the API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Dependency to verify API key from X-API-Key header.
    
    Args:
        api_key: API key from X-API-Key header
        
    Returns:
        The API key if valid
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    # If API_KEY is not configured, skip authentication
    if not settings.API_KEY or settings.API_KEY.strip() == "":
        logger.warning("API_KEY not configured - authentication is disabled")
        return ""
    
    # Check if API key is provided
    if not api_key:
        logger.warning("API key missing from request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Verify API key matches
    if api_key != settings.API_KEY:
        logger.warning(f"Invalid API key attempted: {api_key[:4]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    return api_key

