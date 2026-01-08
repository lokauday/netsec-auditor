"""
Main FastAPI application entry point.
"""
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, Base
from app.core.logging_config import setup_logging
from app.api.v1.router import api_router

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
)

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    # Startup
    logger.info("Starting up NetSec Auditor API...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")
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
    """Global exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
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
    """Health check endpoint."""
    return {"status": "ok"}

