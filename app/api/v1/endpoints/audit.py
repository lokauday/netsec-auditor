"""
Security audit endpoint.
"""
import io
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings
from app.core.auth import require_role
from app.models.config_file import ConfigFile
from app.models.audit_record import AuditRecord
from app.services.audit_service import AuditService
from app.schemas.audit import AuditResponse
from app.utils.pdf_generator import PDFReportBuilder

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/{config_file_id}", response_model=AuditResponse)
async def audit_config_file(
    config_file_id: int,
    _client = Depends(require_role("read_only")),
    db: Session = Depends(get_db)
):
    """
    Perform AI-powered security audit on a parsed configuration file.
    
    Returns a JSON report with security risks and recommended fixes.
    """
    try:
        service = AuditService(db)
        audit_result = service.audit_config(config_file_id)
        
        ai_used = settings.is_openai_available()
        logger.info(
            f"Audit completed: config_id={config_file_id}, "
            f"vendor={audit_result.get('vendor')}, "
            f"risk_score={audit_result['risk_score']}, "
            f"findings_count={len(audit_result.get('findings', []))}, "
            f"ai_enabled={ai_used}"
        )
        
        return AuditResponse(**audit_result)
    except ValueError as e:
        logger.error(f"Audit error: config_id={config_file_id}, error={e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Database error during audit: config_id={config_file_id}, error={e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform security audit"
        )


@router.get("/{config_file_id}/report")
async def get_audit_report(
    config_file_id: int,
    _client = Depends(require_role("read_only")),
    db: Session = Depends(get_db)
):
    """
    Generate and download a PDF security audit report for a configuration.
    
    The configuration must be parsed before generating the report.
    If the config is not parsed, returns HTTP 400.
    """
    try:
        # Look up config file
        config_file = db.query(ConfigFile).filter(ConfigFile.id == config_file_id).first()
        if not config_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Config file with id {config_file_id} not found"
            )
        
        # Check if config has been parsed
        if not config_file.parsed_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Audit not found for this config. Run /api/v1/upload/{id}/parse first to parse the configuration, then /api/v1/audit/{id} to generate audit results."
            )
        
        # Run audit to get results (audits are generated on-demand)
        audit_service = AuditService(db)
        audit_result = audit_service.audit_config(config_file_id)
        
        # Generate PDF using PDFReportBuilder
        try:
            builder = PDFReportBuilder(config_file, audit_result)
            pdf_bytes = builder.build()
            
            # Generate filename
            filename = f"audit_{config_file_id}.pdf"
            
            logger.info(f"Generated PDF report for config_id={config_file_id}, size={len(pdf_bytes)} bytes")
            
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        except Exception as e:
            logger.error(f"Error generating PDF for config_id={config_file_id}: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate PDF report"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating audit report: config_id={config_file_id}, error={e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate audit report"
        )

