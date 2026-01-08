"""
Main FastAPI application entry point.
"""
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base, SessionLocal
from app.core.logging_config import setup_logging
from app.api.v1.router import api_router
from app.middleware.request_logging import RequestLoggingMiddleware

# Import all models to ensure they register with Base.metadata
# This ensures all tables are created when Base.metadata.create_all() is called
from app.models import (
    ConfigFile,
    ACL,
    NATRule,
    VPN,
    Interface,
    Route,
    AuditRecord,
    APIKey,
    ActivityLog,
    Rule,
    Device,
    RulePack,
    DeviceRulePack,
)

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    # Startup
    logger.info("Starting up NetSec Auditor API...")
    
    # Run Alembic migrations if DATABASE_URL is set (Railway/cloud deployment)
    # Migrations are idempotent and will only run once per deployment
    import os
    if os.getenv("DATABASE_URL"):
        try:
            from alembic.config import Config
            from alembic import command
            
            logger.info("[MIGRATION] DATABASE_URL detected, running Alembic migrations (idempotent)...")
            alembic_cfg = Config("alembic.ini")
            # Run migrations - idempotent ENUM creation prevents duplicate errors
            command.upgrade(alembic_cfg, "head")
            logger.info("[MIGRATION] Alembic migrations completed successfully (or already up-to-date)")
        except Exception as e:
            # Log error but don't fail startup - migrations may have already run
            # or database may not be ready yet (Railway sometimes has timing issues)
            error_msg = str(e)
            trace_id = str(uuid.uuid4())
            logger.warning(
                f"[MIGRATION] [{trace_id}] Alembic migration check failed: {error_msg}. "
                "This is OK if migrations already ran or database is not ready yet. "
                "Check logs if you see database errors."
            )
            logger.debug(f"[MIGRATION] [{trace_id}] Migration error details:", exc_info=True)
    else:
        logger.info("[MIGRATION] DATABASE_URL not set, skipping migrations (local dev mode)")
    
    # Ensure database tables are created (fallback for local dev without Alembic)
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created/verified successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}", exc_info=True)
        logger.warning(
            "Database tables creation failed. "
            "If using Alembic, ensure migrations are applied. "
            "Otherwise, check DATABASE_URL and database connectivity."
        )
        # Don't fail startup - let the health endpoint report the issue
    
    # Test database connectivity
    try:
        db = SessionLocal()
        try:
            # Simple connectivity test
            db.execute(text("SELECT 1"))
            db.commit()
            logger.info("Database connectivity verified")
        finally:
            db.close()
    except Exception as e:
        trace_id = str(uuid.uuid4())
        logger.error(
            f"[{trace_id}] Database connectivity test failed: {e}", 
            exc_info=True
        )
        logger.warning(
            f"[{trace_id}] Database may not be accessible. "
            "Check DATABASE_URL configuration and ensure the database is running. "
            f"Trace ID: {trace_id}"
        )
    
    # Seed built-in rule packs
    try:
        from app.services.rule_pack_seeder import ensure_rule_packs_seeded
        db = SessionLocal()
        try:
            ensure_rule_packs_seeded(db)
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Failed to seed rule packs: {e}. Continuing without seed data.")
    
    yield
    # Shutdown
    logger.info("Shutting down NetSec Auditor API...")


app = FastAPI(
    title="NetSec Auditor API",
    description="Network Security Configuration Auditor - Upload and analyze router/firewall configurations",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    redirect_slashes=False,  # Disable automatic trailing slash redirects to prevent POST->GET redirect issues in production
)

# CORS middleware - support ALLOWED_ORIGINS or CORS_ORIGINS env var for cloud deployment
allowed_origins = os.getenv("ALLOWED_ORIGINS") or os.getenv("CORS_ORIGINS")
if allowed_origins:
    # Parse as comma-separated string or JSON array
    if allowed_origins.startswith("["):
        try:
            allowed_origins = json.loads(allowed_origins)
        except json.JSONDecodeError:
            allowed_origins = [origin.strip() for origin in allowed_origins.split(",")]
    else:
        allowed_origins = [origin.strip() for origin in allowed_origins.split(",") if origin.strip()]
else:
    # Use settings.CORS_ORIGINS as fallback
    allowed_origins = settings.CORS_ORIGINS

# Request logging middleware (must be added before other middleware)
app.add_middleware(RequestLoggingMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors with trace_id."""
    # Get trace_id from request state (set by middleware)
    trace_id = getattr(request.state, "trace_id", str(uuid.uuid4()))
    
    # Log full exception with trace_id
    logger.error(
        f"[{trace_id}] Unhandled exception: {type(exc).__name__}: {exc}",
        exc_info=True
    )
    
    # Determine error details based on exception type
    if isinstance(exc, SQLAlchemyError):
        error_detail = "Database error: check DATABASE_URL / migrations"
        error_type = "DatabaseError"
    elif isinstance(exc, HTTPException):
        # Re-raise HTTPException as-is (FastAPI handles these)
        raise
    else:
        error_detail = str(exc) if settings.DEBUG else "Internal Server Error"
        error_type = type(exc).__name__
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": error_detail,
            "trace_id": trace_id,
            "error": error_type,
            "message": str(exc) if settings.DEBUG else "An unexpected error occurred",
        },
    )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "NetSec Auditor API",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    """
    Health check endpoint for Railway/load balancer.
    
    Returns 200 immediately without DB checks to ensure service is marked healthy.
    Use /health/db for database readiness checks.
    """
    return {"status": "ok"}


@app.get("/health/db")
async def health_check_db():
    """
    Database health check endpoint.
    
    Returns 200 if database is accessible, 503 if not.
    Use this for database readiness checks, not for general health.
    """
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            db.commit()
            return {"status": "ok", "database": "connected"}
        finally:
            db.close()
    except Exception as e:
        trace_id = str(uuid.uuid4())
        logger.warning(f"[{trace_id}] Database health check failed: {e}")
        from fastapi import status
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "database": "disconnected",
                "trace_id": trace_id,
            }
        )

