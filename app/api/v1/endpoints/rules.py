"""
Rule management endpoints.
"""
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role, get_current_api_client, APIClient
from app.models.rule import Rule, RuleSeverity, RuleCategory
from app.services.activity_service import log_activity, ActivityAction, ResourceType
from app.schemas.rule import (
    RuleCreateRequest,
    RuleUpdateRequest,
    RuleResponse,
    RuleListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=RuleListResponse)
async def list_rules(
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    severity: Optional[RuleSeverity] = Query(None, description="Filter by severity"),
    category: Optional[RuleCategory] = Query(None, description="Filter by category"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of rules to return"),
    offset: int = Query(0, ge=0, description="Number of rules to skip"),
    client: APIClient = Depends(require_role("viewer")),  # Viewers can see rules
    db: Session = Depends(get_db),
):
    """
    List all rules with optional filters.
    
    Available to viewers and above.
    """
    try:
        query = db.query(Rule)
        
        # Apply filters
        if vendor:
            query = query.filter(Rule.vendor == vendor)
        if enabled is not None:
            query = query.filter(Rule.enabled == enabled)
        if severity:
            query = query.filter(Rule.severity == severity)
        if category:
            query = query.filter(Rule.category == category)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering (newest first)
        rules = query.order_by(Rule.created_at.desc()).offset(offset).limit(limit).all()
        
        return RuleListResponse(
            items=[RuleResponse.model_validate(rule) for rule in rules],
            total=total,
        )
    except Exception as e:
        logger.error(f"Error listing rules: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rules"
        )


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: int,
    client: APIClient = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get a specific rule by ID.
    """
    try:
        rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule with id {rule_id} not found"
            )
        
        return RuleResponse.model_validate(rule)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving rule: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rule"
        )


@router.post("/", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: RuleCreateRequest,
    client: APIClient = Depends(require_role("security_analyst")),  # security_analyst or admin
    http_request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Create a new rule (security_analyst or admin only).
    """
    try:
        # Create rule
        rule = Rule(
            name=request.name,
            description=request.description,
            vendor=request.vendor,
            category=request.category,
            match_criteria=request.match_criteria,
            severity=request.severity,
            enabled=request.enabled,
            created_by=client.api_key_id,
        )
        
        db.add(rule)
        db.commit()
        db.refresh(rule)
        
        logger.info(f"Created rule: id={rule.id}, name={request.name}, severity={request.severity}")
        
        # Log activity
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.RULE_CREATE,
            resource_type=ResourceType.RULE,
            resource_id=rule.id,
            details={
                "name": request.name,
                "severity": request.severity.value,
                "category": request.category.value,
            },
            request=http_request,
        )
        
        return RuleResponse.model_validate(rule)
    except Exception as e:
        logger.error(f"Error creating rule: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create rule"
        )


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: int,
    request: RuleUpdateRequest,
    client: APIClient = Depends(require_role("security_analyst")),  # security_analyst or admin
    http_request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Update an existing rule (security_analyst or admin only).
    """
    try:
        rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule with id {rule_id} not found"
            )
        
        # Update fields if provided
        if request.name is not None:
            rule.name = request.name
        if request.description is not None:
            rule.description = request.description
        if request.vendor is not None:
            rule.vendor = request.vendor
        if request.category is not None:
            rule.category = request.category
        if request.match_criteria is not None:
            rule.match_criteria = request.match_criteria
        if request.severity is not None:
            rule.severity = request.severity
        if request.enabled is not None:
            rule.enabled = request.enabled
        
        rule.updated_by = client.api_key_id
        
        db.commit()
        db.refresh(rule)
        
        logger.info(f"Updated rule: id={rule_id}")
        
        # Log activity
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.RULE_UPDATE,
            resource_type=ResourceType.RULE,
            resource_id=rule_id,
            details={},
            request=http_request,
        )
        
        return RuleResponse.model_validate(rule)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating rule: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update rule"
        )


@router.delete("/{rule_id}", status_code=status.HTTP_200_OK)
async def delete_rule(
    rule_id: int,
    client: APIClient = Depends(require_role("security_analyst")),  # security_analyst or admin
    request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Soft-delete a rule by disabling it (security_analyst or admin only).
    
    Sets enabled=False instead of actually deleting the record.
    """
    try:
        rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule with id {rule_id} not found"
            )
        
        rule.enabled = False
        rule.updated_by = client.api_key_id
        
        db.commit()
        
        logger.info(f"Disabled rule: id={rule_id}")
        
        # Log activity
        log_activity(
            db=db,
            client=client,
            action=ActivityAction.RULE_DELETE,
            resource_type=ResourceType.RULE,
            resource_id=rule_id,
            details={},
            request=request,
        )
        
        return {"message": "Rule disabled successfully", "id": rule_id, "enabled": False}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error disabling rule: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable rule"
        )

