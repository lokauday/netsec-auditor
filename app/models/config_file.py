"""Config file database model."""
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class VendorType(str, enum.Enum):
    """Supported vendor types."""
    CISCO_ASA = "cisco_asa"
    CISCO_IOS = "cisco_ios"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"


class ConfigFile(Base):
    """Configuration file model."""
    __tablename__ = "config_files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False, index=True)
    vendor = Column(Enum(VendorType), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    parsed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Device metadata
    device_name = Column(String(255), nullable=True, index=True)
    device_ip = Column(String(255), nullable=True)
    environment = Column(String(50), nullable=True, index=True)  # e.g., prod, dev, lab
    location = Column(String(255), nullable=True, index=True)  # site or DC name
    
    # Relationships
    acls = relationship("ACL", back_populates="config_file", cascade="all, delete-orphan")
    nat_rules = relationship("NATRule", back_populates="config_file", cascade="all, delete-orphan")
    vpns = relationship("VPN", back_populates="config_file", cascade="all, delete-orphan")
    interfaces = relationship("Interface", back_populates="config_file", cascade="all, delete-orphan")
    routes = relationship("Route", back_populates="config_file", cascade="all, delete-orphan")

