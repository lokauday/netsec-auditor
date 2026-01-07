"""
Audit history endpoints.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_role
from app.models.audit_record import AuditRecord
from app.schemas.audit import AuditRecordResponse, AuditBreakdown

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{audit_id}", response_model=AuditRecordResponse)
async def get_audit_record(
    audit_id: int,
    _client = Depends(require_role("read_only")),
    db: Session = Depends(get_db),
):
    """
    Get a single audit record by ID.
    
    Returns the full audit record including findings and breakdown.
    """
    try:
        audit_record = db.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
        
        if not audit_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Audit record with id {audit_id} not found"
            )
        
        # Convert breakdown JSON to AuditBreakdown model
        breakdown = AuditBreakdown(**audit_record.breakdown)
        
        logger.info(f"Retrieved audit record {audit_id} for config_file_id={audit_record.config_file_id}")
        
        return AuditRecordResponse(
            id=audit_record.id,
            config_file_id=audit_record.config_file_id,
            risk_score=audit_record.risk_score,
            summary=audit_record.summary,
            breakdown=breakdown,
            findings=audit_record.findings,
            created_at=audit_record.created_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving audit record {audit_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit record"
        )
