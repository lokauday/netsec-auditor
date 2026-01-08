"""
API key management endpoints.
"""
import logging
import secrets
import hashlib
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.database import get_db
from app.core.auth import require_role, get_current_api_client, APIClient
from app.models.api_key import APIKey
from app.services.activity_service import log_activity, ActivityAction, ResourceType
from app.schemas.api_key import (
    APIKeyCreateRequest,
    APIKeyResponse,
    APIKeyCreateResponse,
    APIKeyListResponse,
    APIKeyUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return f"sk_{secrets.token_urlsafe(32)}"


def hash_api_key(key: str) -> str:
    """Hash an API key using SHA-256 with salt."""
    # Use a simple salt (in production, use a proper secret)
    salt = "netsec_auditor_salt_2024"  # In production, read from env
    return hashlib.sha256(f"{salt}{key}".encode()).hexdigest()


def verify_api_key_hash(raw_key: str, key_hash: str) -> bool:
    """Verify a raw API key against its hash."""
    return hash_api_key(raw_key) == key_hash


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
            # Mask the key hash (first 8 chars + "...")
            key_masked = f"{key.key_hash[:8]}..." if len(key.key_hash) > 8 else "***"
            
            items.append(
                APIKeyResponse(
                    id=key.id,
                    name=key.label,
                    role=key.role,
                    is_active=key.is_active,
                    created_at=key.created_at,
                    last_used_at=key.last_used_at,
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
    client: APIClient = Depends(require_role("admin")),
    http_request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Create a new API key (admin only).
    
    Returns the full key once in the response. Store only the hashed key in DB.
    """
    try:
        # Role is validated and normalized by schema validator
        # No additional validation needed here
        
        # Generate new key
        new_key = generate_api_key()
        key_hash = hash_api_key(new_key)
        
        # Check for uniqueness (very unlikely but check anyway)
        existing = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
        if existing:
            # Retry once
            new_key = generate_api_key()
            key_hash = hash_api_key(new_key)
            existing = db.query(APIKey).filter(APIKey.key_hash == key_hash).first()
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate unique API key"
                )
        
        # Create API key record (store hash only)
        db_key = APIKey(
            key_hash=key_hash,
            label=request.name,
            role=request.role,
            is_active=True,
        )
        db.add(db_key)
        db.commit()
        db.refresh(db_key)
        
        logger.info(f"Created API key: id={db_key.id}, label={request.name}, role={request.role}")
        # Note: We log creation but not the full key value
        
        # Log activity
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.API_KEY_CREATE,
            resource_type=ResourceType.API_KEY,
            resource_id=db_key.id,
            details={
                "label": request.name,
                "role": request.role,
            },
            request=http_request,
        )
        
        return APIKeyCreateResponse(
            id=db_key.id,
            name=db_key.label,
            role=db_key.role,
            is_active=db_key.is_active,
            created_at=db_key.created_at,
            key=new_key,  # Return full key once (never stored)
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


@router.patch("/{key_id}", status_code=status.HTTP_200_OK)
async def update_api_key(
    key_id: int,
    request: APIKeyUpdateRequest,
    client: APIClient = Depends(require_role("admin")),
    http_request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Update an API key (admin only).
    
    Can update label, role, and is_active status.
    """
    try:
        db_key = db.query(APIKey).filter(APIKey.id == key_id).first()
        if not db_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API key with id {key_id} not found"
            )
        
        # Update fields if provided
        if request.label is not None:
            db_key.label = request.label
        if request.role is not None:
            # Role is validated and normalized by schema validator
            db_key.role = request.role
        if request.is_active is not None:
            db_key.is_active = request.is_active
        
        db.commit()
        db.refresh(db_key)
        
        logger.info(f"Updated API key: id={key_id}")
        
        # Log activity
        update_details = {}
        if request.label is not None:
            update_details["label"] = request.label
        if request.role is not None:
            update_details["role"] = request.role
        if request.is_active is not None:
            update_details["is_active"] = request.is_active
        
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.API_KEY_UPDATE,
            resource_type=ResourceType.API_KEY,
            resource_id=key_id,
            details=update_details,
            request=http_request,
        )
        
        return APIKeyResponse(
            id=db_key.id,
            name=db_key.label,
            role=db_key.role,
            is_active=db_key.is_active,
            created_at=db_key.created_at,
            last_used_at=db_key.last_used_at,
            key_masked=f"{db_key.key_hash[:8]}..." if len(db_key.key_hash) > 8 else "***",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating API key: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update API key"
        )


@router.delete("/{key_id}", status_code=status.HTTP_200_OK)
async def delete_api_key(
    key_id: int,
    client: APIClient = Depends(require_role("admin")),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Soft-delete an API key (admin only).
    
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
        
        logger.info(f"Deleted (deactivated) API key: id={key_id}")
        
        # Log activity
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.API_KEY_DEACTIVATE,
            resource_type=ResourceType.API_KEY,
            resource_id=key_id,
            details={},
            request=request,
        )
        
        return {"message": "API key deleted successfully", "id": key_id, "is_active": False}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete API key"
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
        "api_key_id": client.api_key_id,
    }

