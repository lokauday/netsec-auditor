"""Database models."""
from app.models.config_file import ConfigFile
from app.models.acl import ACL
from app.models.nat_rule import NATRule
from app.models.vpn import VPN
from app.models.interface import Interface
from app.models.routing import Route
from app.models.audit_record import AuditRecord

__all__ = [
    "ConfigFile",
    "ACL",
    "NATRule",
    "VPN",
    "Interface",
    "Route",
    "AuditRecord",
]

