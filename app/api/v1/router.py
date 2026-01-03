"""
API v1 router.
"""
from fastapi import APIRouter

from app.api.v1.endpoints import upload, audit, configs, audits

api_router = APIRouter()

api_router.include_router(configs.router, prefix="/configs", tags=["configs"])
api_router.include_router(upload.router, prefix="/upload", tags=["upload"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(audits.router, prefix="/audits", tags=["audits"])

