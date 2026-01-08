"""
Health check endpoint for monitoring and diagnostics.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint that verifies:
    - API is running
    - Database connection works (SELECT 1)
    
    Returns:
        {
            "ok": true,
            "db": true
        }
    """
    db_ok = False
    
    try:
        # Test database connectivity with a simple query
        result = db.execute(text("SELECT 1"))
        result.fetchone()
        db_ok = True
    except SQLAlchemyError as e:
        logger.error(f"Database health check failed: {e}", exc_info=True)
        db_ok = False
    except Exception as e:
        logger.error(f"Unexpected error during health check: {e}", exc_info=True)
        db_ok = False
    
    # Return health status
    # If DB is down, return 503 Service Unavailable
    if not db_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed"
        )
    
    return {
        "ok": True,
        "db": True,
        "environment": settings.APP_ENV,
    }

