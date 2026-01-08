"""
Role definitions and permission matrix for RBAC.

Roles in hierarchy (lowest to highest):
- viewer: Read-only access to audits/summary/history
- operator: Upload configs + run audits
- security_analyst: Manage rules, baselines, annotations
- auditor: Export reports, view evidence
- admin: Full access including user/key/tenant management
"""
from enum import Enum
from typing import Dict, Set


class Role(str, Enum):
    """User roles with hierarchy."""
    VIEWER = "viewer"
    OPERATOR = "operator"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    ADMIN = "admin"


# Role hierarchy (numeric levels for comparison)
ROLE_HIERARCHY: Dict[str, int] = {
    Role.VIEWER: 1,
    Role.OPERATOR: 2,
    Role.SECURITY_ANALYST: 3,
    Role.AUDITOR: 4,
    Role.ADMIN: 5,
}

# Backward compatibility: map old roles to new ones
LEGACY_ROLE_MAP: Dict[str, str] = {
    "read_only": Role.VIEWER,  # read_only -> viewer
    "admin": Role.ADMIN,  # admin stays admin
}

# Valid roles list
VALID_ROLES: Set[str] = {r.value for r in Role}


def normalize_role(role: str) -> str:
    """
    Normalize role string, handling legacy roles.
    
    Args:
        role: Role string (may be legacy like "read_only")
        
    Returns:
        Normalized role string from Role enum
    """
    role_lower = role.lower().strip()
    
    # Check if it's a legacy role
    if role_lower in LEGACY_ROLE_MAP:
        return LEGACY_ROLE_MAP[role_lower].value
    
    # Check if it's already a valid role
    if role_lower in VALID_ROLES:
        return role_lower
    
    # Default to viewer for unknown roles
    return Role.VIEWER.value


def has_permission(user_role: str, required_role: str) -> bool:
    """
    Check if user role has permission for required role.
    
    Args:
        user_role: User's role
        required_role: Minimum required role
        
    Returns:
        True if user has sufficient permissions
    """
    user_level = ROLE_HIERARCHY.get(normalize_role(user_role), 0)
    required_level = ROLE_HIERARCHY.get(normalize_role(required_role), 0)
    return user_level >= required_level


# Permission matrix: which roles can access which endpoints
PERMISSION_MATRIX = {
    # Viewer: read audits/summary/history only
    "viewer": {
        "allowed_endpoints": [
            "GET /api/v1/audits/summary",
            "GET /api/v1/audits/history",
            "GET /api/v1/configs/{id}",
            "GET /api/v1/configs/",
        ],
    },
    # Operator: upload configs + run audits
    "operator": {
        "allowed_endpoints": [
            "POST /api/v1/upload/",
            "POST /api/v1/upload/{id}/parse",
            "POST /api/v1/audit/{id}",
            "GET /api/v1/audits/summary",
            "GET /api/v1/audits/history",
            "GET /api/v1/configs/{id}",
            "GET /api/v1/configs/",
        ],
    },
    # Security Analyst: manage rules, baselines, annotations
    "security_analyst": {
        "allowed_endpoints": [
            # All operator endpoints
            "POST /api/v1/upload/",
            "POST /api/v1/upload/{id}/parse",
            "POST /api/v1/audit/{id}",
            "GET /api/v1/audits/summary",
            "GET /api/v1/audits/history",
            "GET /api/v1/configs/{id}",
            "GET /api/v1/configs/",
            # Plus rule management (when implemented)
            # "GET /api/v1/rules/",
            # "POST /api/v1/rules/",
            # "PUT /api/v1/rules/{id}",
            # "DELETE /api/v1/rules/{id}",
        ],
    },
    # Auditor: export reports, view evidence
    "auditor": {
        "allowed_endpoints": [
            # All operator endpoints
            "POST /api/v1/upload/",
            "POST /api/v1/upload/{id}/parse",
            "POST /api/v1/audit/{id}",
            "GET /api/v1/audits/summary",
            "GET /api/v1/audits/history",
            "GET /api/v1/configs/{id}",
            "GET /api/v1/configs/",
            # Plus report exports
            "GET /api/v1/audit/{id}/report",
        ],
    },
    # Admin: full access
    "admin": {
        "allowed_endpoints": ["*"],  # All endpoints
    },
}

