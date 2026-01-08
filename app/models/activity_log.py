"""
Activity log model for audit trail.
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class ActivityLog(Base):
    """Activity log model for tracking all system actions."""
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Actor information
    actor_id = Column(Integer, ForeignKey("api_keys.id"), nullable=True, index=True)  # API key ID if from DB
    actor_source = Column(String(50), nullable=False)  # "static" or "db"
    actor_role = Column(String(50), nullable=False)  # Role at time of action
    
    # Action details
    action = Column(String(100), nullable=False, index=True)  # e.g., "config_upload", "audit_run", "rule_create"
    resource_type = Column(String(50), nullable=True, index=True)  # e.g., "config_file", "audit", "rule", "api_key"
    resource_id = Column(Integer, nullable=True, index=True)  # ID of the affected resource
    
    # Additional details (JSON)
    details = Column(JSON, nullable=True)  # Flexible JSON for action-specific data
    
    # Request metadata
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(String(255), nullable=True)
    
    # Optional relationship to API key
    api_key = relationship("APIKey", foreign_keys=[actor_id])

