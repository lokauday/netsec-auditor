"""
Device model for CMDB-style device inventory.
"""
from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base
from app.models.config_file import VendorType


class EnvironmentType(str, enum.Enum):
    """Device environment types."""
    PROD = "prod"
    DEV = "dev"
    TEST = "test"
    STAGING = "staging"
    LAB = "lab"
    CLOUD = "cloud"
    DMZ = "dmz"


class Device(Base):
    """Device model for centralized device inventory."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    
    # Basic device info
    hostname = Column(String(255), nullable=False, index=True)
    mgmt_ip = Column(String(45), nullable=True, index=True)  # IPv4 or IPv6
    
    # Device characteristics
    vendor = Column(Enum(VendorType), nullable=True, index=True)
    model = Column(String(255), nullable=True)
    
    # Location and environment
    site = Column(String(255), nullable=True, index=True)  # Site or data center name
    environment = Column(Enum(EnvironmentType), nullable=True, index=True)
    
    # Ownership
    owner = Column(String(255), nullable=True)  # Team or person responsible
    tags = Column(JSON, nullable=True)  # Flexible tags as JSON array
    
    # Audit tracking
    last_audit_id = Column(Integer, ForeignKey("audit_records.id"), nullable=True)
    last_risk_score = Column(Float, nullable=True)  # 0-100 risk score from last audit
    last_policy_hygiene_score = Column(Float, nullable=True)  # 0-100 hygiene score (for EPIC D)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    config_files = relationship("ConfigFile", back_populates="device", cascade="all, delete-orphan")
    last_audit = relationship("AuditRecord", foreign_keys=[last_audit_id])
    device_rule_packs = relationship("DeviceRulePack", back_populates="device", cascade="all, delete-orphan")

