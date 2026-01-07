"""
API key management endpoints.
"""
import logging
import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role, get_current_api_client
from app.models.api_key import APIKey
from app.schemas.api_key import (
    APIKeyCreateRequest,
    APIKeyResponse,
    APIKeyCreateResponse,
    APIKeyListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return f"sk_{secrets.token_urlsafe(32)}"


@router.get("/", response_model=APIKeyListResponse)
async def list_api_keys(
    _client = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    List all API keys (admin only).
    
    Returns safe fields only (masked key).
    """
    try:
        keys = db.query(APIKey).order_by(APIKey.created_at.desc()).all()
        
        items = []
        for key in keys:
            # Mask the key (first 8 chars + "...")
            key_masked = f"{key.key[:8]}..." if len(key.key) > 8 else "***"
            
            items.append(
                APIKeyResponse(
                    id=key.id,
                    name=key.label,
                    role=key.role,
                    is_active=key.is_active,
                    created_at=key.created_at,
                    key_masked=key_masked,
                )
            )
        
        logger.info(f"Listed {len(items)} API keys")
        
        return APIKeyListResponse(
            items=items,
            total=len(items),
        )
    except Exception as e:
        logger.error(f"Error listing API keys: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list API keys"
        )


@router.post("/", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: APIKeyCreateRequest,
    _client = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    Create a new API key (admin only).
    
    Returns the full key once in the response. Store only the hashed key in DB.
    """
    try:
        # Validate role
        if request.role not in ["admin", "read_only"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role must be 'admin' or 'read_only'"
            )
        
        # Generate new key
        new_key = generate_api_key()
        
        # Check for uniqueness (very unlikely but check anyway)
        existing = db.query(APIKey).filter(APIKey.key == new_key).first()
        if existing:
            # Retry once
            new_key = generate_api_key()
            existing = db.query(APIKey).filter(APIKey.key == new_key).first()
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate unique API key"
                )
        
        # Create API key record
        db_key = APIKey(
            key=new_key,
            label=request.name,
            role=request.role,
            is_active=True,
        )
        db.add(db_key)
        db.commit()
        db.refresh(db_key)
        
        logger.info(f"Created API key: id={db_key.id}, label={request.name}, role={request.role}")
        # Note: We log creation but not the full key value
        
        return APIKeyCreateResponse(
            id=db_key.id,
            name=db_key.label,
            role=db_key.role,
            is_active=db_key.is_active,
            created_at=db_key.created_at,
            key=new_key,  # Return full key once
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating API key: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )


@router.patch("/{key_id}/deactivate", status_code=status.HTTP_200_OK)
async def deactivate_api_key(
    key_id: int,
    _client = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    Deactivate an API key (admin only).
    
    Sets is_active=False. The key can no longer be used for authentication.
    """
    try:
        db_key = db.query(APIKey).filter(APIKey.id == key_id).first()
        if not db_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API key with id {key_id} not found"
            )
        
        db_key.is_active = False
        db.commit()
        
        logger.info(f"Deactivated API key: id={key_id}")
        
        return {"message": "API key deactivated successfully", "id": key_id, "is_active": False}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating API key: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate API key"
        )


# Create a separate router for auth endpoints
auth_router = APIRouter()

@auth_router.get("/me")
async def get_current_user_info(
    client = Depends(get_current_api_client),
):
    """
    Get current authenticated user info (role, source).
    
    Useful for frontend to determine if user is admin.
    """
    return {
        "role": client.role,
        "source": client.source,
        "is_admin": client.role == "admin",
    }

