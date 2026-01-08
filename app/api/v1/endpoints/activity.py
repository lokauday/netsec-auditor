"""
Activity log endpoints for audit trail.
"""
import logging
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.core.database import get_db
from app.core.auth import require_role, APIClient
from app.models.activity_log import ActivityLog
from app.schemas.activity import ActivityLogResponse, ActivityLogListResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=ActivityLogListResponse)
async def list_activity_logs(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of logs to return"),
    offset: int = Query(0, ge=0, description="Number of logs to skip"),
    start_date: Optional[datetime] = Query(None, description="Filter logs from this date"),
    end_date: Optional[datetime] = Query(None, description="Filter logs until this date"),
    actor_id: Optional[int] = Query(None, description="Filter by API key ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    client: APIClient = Depends(require_role("viewer")),  # Viewer can see audit trail
    db: Session = Depends(get_db),
):
    """
    List activity logs with optional filters.
    
    Available to viewers and above for audit trail visibility.
    """
    try:
        # Build query
        query = db.query(ActivityLog)
        
        # Apply filters
        if start_date:
            query = query.filter(ActivityLog.timestamp >= start_date)
        if end_date:
            query = query.filter(ActivityLog.timestamp <= end_date)
        if actor_id:
            query = query.filter(ActivityLog.actor_id == actor_id)
        if action:
            query = query.filter(ActivityLog.action == action)
        if resource_type:
            query = query.filter(ActivityLog.resource_type == resource_type)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering (newest first)
        logs = query.order_by(ActivityLog.timestamp.desc()).offset(offset).limit(limit).all()
        
        return ActivityLogListResponse(
            items=[ActivityLogResponse.model_validate(log) for log in logs],
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        logger.error(f"Error listing activity logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve activity logs"
        )


@router.get("/{log_id}", response_model=ActivityLogResponse)
async def get_activity_log(
    log_id: int,
    client: APIClient = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get a specific activity log entry by ID.
    """
    try:
        log = db.query(ActivityLog).filter(ActivityLog.id == log_id).first()
        if not log:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Activity log with id {log_id} not found"
            )
        
        return ActivityLogResponse.model_validate(log)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving activity log: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve activity log"
        )

