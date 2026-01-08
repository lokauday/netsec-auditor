"""
API v1 router.
"""
from fastapi import APIRouter

from app.api.v1.endpoints import upload, audit, configs, audits, api_keys, activity, rules, devices, rule_packs, rules_ai, health
from app.api.v1.endpoints.api_keys import auth_router

api_router = APIRouter()

# Health check endpoint (no prefix, so it's /api/v1/health)
api_router.include_router(health.router, tags=["health"])

api_router.include_router(configs.router, prefix="/configs", tags=["configs"])
api_router.include_router(upload.router, prefix="/upload", tags=["upload"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(audits.router, prefix="/audits", tags=["audits"])
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["api-keys"])
api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(activity.router, prefix="/activity", tags=["activity"])
api_router.include_router(rules.router, prefix="/rules", tags=["rules"])
api_router.include_router(rules_ai.router, prefix="/rules", tags=["rules"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(rule_packs.router, prefix="/rule-packs", tags=["rule-packs"])

