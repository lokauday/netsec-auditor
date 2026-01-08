"""
Rule pack management endpoints.
"""
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role, APIClient
from app.models.rule_pack import RulePack, DeviceRulePack
from app.models.device import Device
from app.schemas.rule_pack import (
    RulePackResponse,
    RulePackDetailResponse,
    RulePackListResponse,
    DeviceRulePackResponse,
    DeviceRulePackUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=RulePackListResponse)
async def list_rule_packs(
    is_builtin: Optional[bool] = Query(None, description="Filter by built-in status"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    client: APIClient = Depends(require_role("viewer")),  # Viewers can see packs
    db: Session = Depends(get_db),
):
    """
    List all rule packs with optional filters.
    
    Available to viewers and above.
    """
    try:
        query = db.query(RulePack)
        
        # Apply filters
        if is_builtin is not None:
            query = query.filter(RulePack.is_builtin == is_builtin)
        if enabled is not None:
            query = query.filter(RulePack.enabled == enabled)
        if category:
            query = query.filter(RulePack.category == category)
        
        # Get total count
        total = query.count()
        
        # Apply ordering (built-in first, then by name)
        packs = query.order_by(RulePack.is_builtin.desc(), RulePack.name.asc()).all()
        
        # Build response with rule counts
        pack_responses = []
        for pack in packs:
            pack_dict = {
                "id": pack.id,
                "name": pack.name,
                "description": pack.description,
                "category": pack.category,
                "is_builtin": pack.is_builtin,
                "enabled": pack.enabled,
                "rule_count": len(pack.rules),
                "created_at": pack.created_at,
                "updated_at": pack.updated_at,
            }
            pack_responses.append(RulePackResponse(**pack_dict))
        
        return RulePackListResponse(
            items=pack_responses,
            total=total,
        )
    except Exception as e:
        logger.error(f"Error listing rule packs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rule packs"
        )


@router.get("/{pack_id}", response_model=RulePackDetailResponse)
async def get_rule_pack(
    pack_id: int,
    client: APIClient = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get a specific rule pack by ID with its rules.
    """
    try:
        pack = db.query(RulePack).filter(RulePack.id == pack_id).first()
        if not pack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule pack with id {pack_id} not found"
            )
        
        # Build response with rules
        from app.schemas.rule_pack import RulePackRuleResponse
        rules = [
            RulePackRuleResponse(
                id=rule.id,
                name=rule.name,
                description=rule.description,
                severity=rule.severity.value,
                category=rule.category.value,
                enabled=rule.enabled,
            )
            for rule in pack.rules
        ]
        
        pack_dict = {
            "id": pack.id,
            "name": pack.name,
            "description": pack.description,
            "category": pack.category,
            "is_builtin": pack.is_builtin,
            "enabled": pack.enabled,
            "rule_count": len(pack.rules),
            "created_at": pack.created_at,
            "updated_at": pack.updated_at,
            "rules": rules,
        }
        
        return RulePackDetailResponse(**pack_dict)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving rule pack: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rule pack"
        )


@router.get("/device/{device_id}", response_model=List[DeviceRulePackResponse])
async def get_device_rule_packs(
    device_id: int,
    client: APIClient = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get all rule packs associated with a device.
    """
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with id {device_id} not found"
            )
        
        device_packs = db.query(DeviceRulePack).filter(DeviceRulePack.device_id == device_id).all()
        
        return [
            DeviceRulePackResponse(
                id=dp.id,
                device_id=dp.device_id,
                rule_pack_id=dp.rule_pack_id,
                rule_pack_name=dp.rule_pack.name,
                enabled=dp.enabled,
                created_at=dp.created_at,
            )
            for dp in device_packs
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving device rule packs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device rule packs"
        )


@router.post("/device/{device_id}/pack/{pack_id}", response_model=DeviceRulePackResponse, status_code=status.HTTP_201_CREATED)
async def attach_rule_pack_to_device(
    device_id: int,
    pack_id: int,
    client: APIClient = Depends(require_role("operator")),  # operator or above
    db: Session = Depends(get_db),
):
    """
    Attach a rule pack to a device (operator or above).
    """
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Device with id {device_id} not found"
            )
        
        pack = db.query(RulePack).filter(RulePack.id == pack_id).first()
        if not pack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule pack with id {pack_id} not found"
            )
        
        # Check if already attached
        existing = db.query(DeviceRulePack).filter(
            DeviceRulePack.device_id == device_id,
            DeviceRulePack.rule_pack_id == pack_id
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Rule pack {pack_id} is already attached to device {device_id}"
            )
        
        # Create association
        device_pack = DeviceRulePack(
            device_id=device_id,
            rule_pack_id=pack_id,
            enabled=True,
        )
        db.add(device_pack)
        db.commit()
        db.refresh(device_pack)
        
        logger.info(f"Attached rule pack {pack_id} to device {device_id}")
        
        return DeviceRulePackResponse(
            id=device_pack.id,
            device_id=device_pack.device_id,
            rule_pack_id=device_pack.rule_pack_id,
            rule_pack_name=pack.name,
            enabled=device_pack.enabled,
            created_at=device_pack.created_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error attaching rule pack to device: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to attach rule pack to device"
        )


@router.put("/device/{device_id}/pack/{pack_id}", response_model=DeviceRulePackResponse)
async def update_device_rule_pack(
    device_id: int,
    pack_id: int,
    request: DeviceRulePackUpdateRequest,
    client: APIClient = Depends(require_role("operator")),  # operator or above
    db: Session = Depends(get_db),
):
    """
    Update device-rule pack association (enable/disable pack for device).
    """
    try:
        device_pack = db.query(DeviceRulePack).filter(
            DeviceRulePack.device_id == device_id,
            DeviceRulePack.rule_pack_id == pack_id
        ).first()
        
        if not device_pack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule pack {pack_id} is not attached to device {device_id}"
            )
        
        device_pack.enabled = request.enabled
        db.commit()
        db.refresh(device_pack)
        
        logger.info(f"Updated device-rule pack association: device={device_id}, pack={pack_id}, enabled={request.enabled}")
        
        return DeviceRulePackResponse(
            id=device_pack.id,
            device_id=device_pack.device_id,
            rule_pack_id=device_pack.rule_pack_id,
            rule_pack_name=device_pack.rule_pack.name,
            enabled=device_pack.enabled,
            created_at=device_pack.created_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device-rule pack: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update device-rule pack"
        )


@router.delete("/device/{device_id}/pack/{pack_id}", status_code=status.HTTP_200_OK)
async def detach_rule_pack_from_device(
    device_id: int,
    pack_id: int,
    client: APIClient = Depends(require_role("operator")),  # operator or above
    db: Session = Depends(get_db),
):
    """
    Detach a rule pack from a device (operator or above).
    """
    try:
        device_pack = db.query(DeviceRulePack).filter(
            DeviceRulePack.device_id == device_id,
            DeviceRulePack.rule_pack_id == pack_id
        ).first()
        
        if not device_pack:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule pack {pack_id} is not attached to device {device_id}"
            )
        
        db.delete(device_pack)
        db.commit()
        
        logger.info(f"Detached rule pack {pack_id} from device {device_id}")
        
        return {"message": "Rule pack detached successfully", "device_id": device_id, "pack_id": pack_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error detaching rule pack from device: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to detach rule pack from device"
        )

