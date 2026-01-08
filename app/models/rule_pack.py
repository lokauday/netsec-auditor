"""
Rule pack model for grouping rules into policy packs.
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Table, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base

# Association table for many-to-many relationship between RulePack and Rule
rule_pack_rules = Table(
    "rule_pack_rules",
    Base.metadata,
    Column("rule_pack_id", Integer, ForeignKey("rule_packs.id"), primary_key=True),
    Column("rule_id", Integer, ForeignKey("rules.id"), primary_key=True),
)


class RulePack(Base):
    """Rule pack model for grouping rules into policy packs."""
    __tablename__ = "rule_packs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True, index=True)  # e.g., "internet_exposure", "compliance", "crypto"
    
    # Pack metadata
    is_builtin = Column(Boolean, default=False, nullable=False, index=True)  # True for system packs
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    rules = relationship("Rule", secondary=rule_pack_rules, back_populates="rule_packs")
    device_packs = relationship("DeviceRulePack", back_populates="rule_pack", cascade="all, delete-orphan")


# Association table for many-to-many relationship between Device and RulePack
# Note: We use DeviceRulePack model instead of a simple Table for additional metadata


class DeviceRulePack(Base):
    """Association model for device-rule pack relationships (with additional metadata)."""
    __tablename__ = "device_rule_packs"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    rule_pack_id = Column(Integer, ForeignKey("rule_packs.id"), nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    device = relationship("Device", back_populates="device_rule_packs")
    rule_pack = relationship("RulePack", back_populates="device_packs")

