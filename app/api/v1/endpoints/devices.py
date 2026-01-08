"""
Device management endpoints.
"""
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.core.database import get_db
from app.core.auth import require_role, APIClient
from app.models.device import Device, EnvironmentType
from app.models.config_file import ConfigFile, VendorType
from app.schemas.device import (
    DeviceCreateRequest,
    DeviceUpdateRequest,
    DeviceResponse,
    DeviceDetailResponse,
    DeviceListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=DeviceListResponse)
async def list_devices(
    site: Optional[str] = Query(None, description="Filter by site"),
    environment: Optional[EnvironmentType] = Query(None, description="Filter by environment"),
    vendor: Optional[VendorType] = Query(None, description="Filter by vendor"),
    min_risk_score: Optional[float] = Query(None, ge=0, le=100, description="Minimum risk score"),
    max_risk_score: Optional[float] = Query(None, ge=0, le=100, description="Maximum risk score"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of devices to return"),
    offset: int = Query(0, ge=0, description="Number of devices to skip"),
    client: APIClient = Depends(require_role("viewer")),  # Viewers can see devices
    db: Session = Depends(get_db),
):
    """
    List all devices with optional filters.
    
    Available to viewers and above.
    """
    try:
        query = db.query(Device)
        
        # Apply filters
        if site:
            query = query.filter(Device.site == site)
        if environment:
            query = query.filter(Device.environment == environment)
        if vendor:
            query = query.filter(Device.vendor == vendor)
        if min_risk_score is not None:
            query = query.filter(Device.last_risk_score >= min_risk_score)
        if max_risk_score is not None:
            query = query.filter(Device.last_risk_score <= max_risk_score)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering (by risk score descending, then by hostname)
        devices = query.order_by(
            Device.last_risk_score.desc().nulls_last(),
            Device.hostname.asc()
        ).offset(offset).limit(limit).all()
        
        return DeviceListResponse(
            items=[DeviceResponse.model_validate(device) for device in devices],
            total=total,
        )
    except Exception as e:
        logger.error(f"Error listing devices: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve devices"
        )


@router.get("/{device_id}", response_model=DeviceDetailResponse)
async def get_device(
    device_id: int,
    client: APIClient = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get a specific device by ID with related configs and audits.
    """
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with id {device_id} not found"
            )
        
        # Get config count and latest config
        configs = db.query(ConfigFile).filter(ConfigFile.device_id == device_id).order_by(
            ConfigFile.uploaded_at.desc()
        ).all()
        
        config_count = len(configs)
        latest_config = configs[0] if configs else None
        
        device_dict = DeviceResponse.model_validate(device).model_dump()
        device_dict["config_count"] = config_count
        device_dict["latest_config_id"] = latest_config.id if latest_config else None
        device_dict["latest_config_uploaded_at"] = latest_config.uploaded_at if latest_config else None
        
        return DeviceDetailResponse(**device_dict)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving device: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device"
        )


@router.post("/", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    request: DeviceCreateRequest,
    client: APIClient = Depends(require_role("operator")),  # operator or above
    db: Session = Depends(get_db),
):
    """
    Create a new device (operator or above).
    """
    try:
        # Check for duplicate hostname
        existing = db.query(Device).filter(Device.hostname == request.hostname).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Device with hostname '{request.hostname}' already exists"
            )
        
        # Create device
        device = Device(
            hostname=request.hostname,
            mgmt_ip=request.mgmt_ip,
            vendor=request.vendor,
            model=request.model,
            site=request.site,
            environment=request.environment,
            owner=request.owner,
            tags=request.tags,
        )
        
        db.add(device)
        db.commit()
        db.refresh(device)
        
        logger.info(f"Created device: id={device.id}, hostname={request.hostname}")
        
        return DeviceResponse.model_validate(device)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating device: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create device"
        )


@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int,
    request: DeviceUpdateRequest,
    client: APIClient = Depends(require_role("operator")),  # operator or above
    db: Session = Depends(get_db),
):
    """
    Update an existing device (operator or above).
    """
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with id {device_id} not found"
            )
        
        # Check for duplicate hostname if changing it
        if request.hostname and request.hostname != device.hostname:
            existing = db.query(Device).filter(Device.hostname == request.hostname).first()
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Device with hostname '{request.hostname}' already exists"
                )
        
        # Update fields if provided
        if request.hostname is not None:
            device.hostname = request.hostname
        if request.mgmt_ip is not None:
            device.mgmt_ip = request.mgmt_ip
        if request.vendor is not None:
            device.vendor = request.vendor
        if request.model is not None:
            device.model = request.model
        if request.site is not None:
            device.site = request.site
        if request.environment is not None:
            device.environment = request.environment
        if request.owner is not None:
            device.owner = request.owner
        if request.tags is not None:
            device.tags = request.tags
        
        db.commit()
        db.refresh(device)
        
        logger.info(f"Updated device: id={device_id}")
        
        return DeviceResponse.model_validate(device)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update device"
        )


@router.delete("/{device_id}", status_code=status.HTTP_200_OK)
async def delete_device(
    device_id: int,
    client: APIClient = Depends(require_role("admin")),  # admin only
    db: Session = Depends(get_db),
):
    """
    Delete a device (admin only).
    
    Note: This will also delete associated config files due to cascade.
    """
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with id {device_id} not found"
            )
        
        db.delete(device)
        db.commit()
        
        logger.info(f"Deleted device: id={device_id}")
        
        return {"message": "Device deleted successfully", "id": device_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete device"
        )

