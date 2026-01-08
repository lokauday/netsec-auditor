"""
Audit history endpoints.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from app.core.database import get_db
from app.core.auth import require_role
from app.models.audit_record import AuditRecord
from app.models.config_file import ConfigFile, VendorType
from app.schemas.audit import (
    AuditRecordResponse,
    AuditBreakdown,
    AuditHistoryListResponse,
    AuditHistoryItem,
    AuditSummaryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# IMPORTANT: Static routes must be defined BEFORE path parameters
# Otherwise FastAPI will try to parse "summary" and "history" as audit_id integers


@router.get("/summary", response_model=AuditSummaryResponse)
async def get_audit_summary(
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    _client = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get aggregated audit statistics.
    
    Returns total configs audited, findings by severity, average risk score,
    and findings over time (by day).
    
    Supports filtering by date range, vendor, and environment.
    """
    try:
        # Build query with joins for filtering
        query = (
            db.query(AuditRecord, ConfigFile)
            .join(ConfigFile, AuditRecord.config_file_id == ConfigFile.id)
        )
        
        # Apply filters
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                query = query.filter(ConfigFile.uploaded_at >= start_dt)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid start_date format. Use YYYY-MM-DD"
                )
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                # Add one day to include the entire end date
                end_dt = end_dt + timedelta(days=1)
                query = query.filter(ConfigFile.uploaded_at < end_dt)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid end_date format. Use YYYY-MM-DD"
                )
        
        if vendor:
            try:
                vendor_enum = VendorType(vendor.lower())
                query = query.filter(ConfigFile.vendor == vendor_enum)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid vendor. Must be one of: {', '.join([v.value for v in VendorType])}"
                )
        
        if environment:
            query = query.filter(ConfigFile.environment == environment)
        
        # Get all matching audit records
        results = query.all()
        all_audits = [audit_record for audit_record, _ in results]
        total_configs = len(set(audit.config_file_id for audit in all_audits))
        
        # Aggregate findings by severity
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_risk_score = 0
        
        for audit in all_audits:
            if audit.breakdown:
                breakdown = audit.breakdown
                findings_by_severity["critical"] += breakdown.get("critical", 0)
                findings_by_severity["high"] += breakdown.get("high", 0)
                findings_by_severity["medium"] += breakdown.get("medium", 0)
                findings_by_severity["low"] += breakdown.get("low", 0)
            total_risk_score += audit.risk_score
        
        average_risk_score = total_risk_score / len(all_audits) if all_audits else 0.0
        
        # Findings over time (group by day)
        findings_over_time = []
        if all_audits:
            # Group audits by date
            audits_by_date = {}
            for audit in all_audits:
                date_str = audit.created_at.date().isoformat()
                if date_str not in audits_by_date:
                    audits_by_date[date_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                if audit.breakdown:
                    audits_by_date[date_str]["critical"] += audit.breakdown.get("critical", 0)
                    audits_by_date[date_str]["high"] += audit.breakdown.get("high", 0)
                    audits_by_date[date_str]["medium"] += audit.breakdown.get("medium", 0)
                    audits_by_date[date_str]["low"] += audit.breakdown.get("low", 0)
            
            # Convert to list sorted by date
            for date_str in sorted(audits_by_date.keys()):
                findings_over_time.append({
                    "date": date_str,
                    **audits_by_date[date_str]
                })
        
        logger.info(f"Generated audit summary: {total_configs} configs, {len(all_audits)} audits")
        
        return AuditSummaryResponse(
            total_configs_audited=total_configs,
            findings_by_severity=findings_by_severity,
            average_risk_score=round(average_risk_score, 2),
            findings_over_time=findings_over_time,
        )
    except Exception as e:
        logger.error(f"Error generating audit summary: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate audit summary"
        )


@router.get("/history", response_model=AuditHistoryListResponse)
async def get_audit_history(
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    _client = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """
    Get audit history with filtering options.
    
    Returns a list of recent audits with config metadata, filtered by:
    - Date range (start_date, end_date)
    - Vendor
    - Environment
    
    Results are sorted by uploaded_at descending.
    """
    try:
        # Build query with joins
        query = (
            db.query(AuditRecord, ConfigFile)
            .join(ConfigFile, AuditRecord.config_file_id == ConfigFile.id)
        )
        
        # Apply filters
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                query = query.filter(ConfigFile.uploaded_at >= start_dt)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid start_date format. Use YYYY-MM-DD"
                )
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                # Add one day to include the entire end date
                end_dt = end_dt + timedelta(days=1)
                query = query.filter(ConfigFile.uploaded_at < end_dt)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid end_date format. Use YYYY-MM-DD"
                )
        
        if vendor:
            try:
                vendor_enum = VendorType(vendor.lower())
                query = query.filter(ConfigFile.vendor == vendor_enum)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid vendor. Must be one of: {', '.join([v.value for v in VendorType])}"
                )
        
        if environment:
            query = query.filter(ConfigFile.environment == environment)
        
        # Get total count
        total = query.count()
        
        # Apply ordering and pagination
        results = (
            query.order_by(ConfigFile.uploaded_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        
        # Build response items
        items = []
        for audit_record, config_file in results:
            # Calculate total findings from breakdown
            total_findings = 0
            if audit_record.breakdown:
                breakdown = audit_record.breakdown
                total_findings = (
                    breakdown.get("critical", 0) +
                    breakdown.get("high", 0) +
                    breakdown.get("medium", 0) +
                    breakdown.get("low", 0)
                )
            
            items.append(
                AuditHistoryItem(
                    config_id=config_file.id,
                    filename=config_file.filename,
                    vendor=config_file.vendor.value,
                    device_name=config_file.device_name,
                    environment=config_file.environment,
                    uploaded_at=config_file.uploaded_at,
                    risk_score=audit_record.risk_score,
                    total_findings=total_findings,
                )
            )
        
        logger.info(f"Retrieved {len(items)} audit history items (total: {total})")
        
        return AuditHistoryListResponse(
            items=items,
            total=total,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving audit history: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit history"
        )


@router.get("/{audit_id}", response_model=AuditRecordResponse)
async def get_audit_record(
    audit_id: int,
    _client = Depends(require_role("viewer")),
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
