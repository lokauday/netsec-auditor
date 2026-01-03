"""ACL database model."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class ACLDirection(str, enum.Enum):
    """ACL direction."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class ACL(Base):
    """Access Control List model."""
    __tablename__ = "acls"

    id = Column(Integer, primary_key=True, index=True)
    config_file_id = Column(Integer, ForeignKey("config_files.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    direction = Column(Enum(ACLDirection), nullable=False)
    rule_number = Column(Integer, nullable=True)
    source = Column(String(255), nullable=True)
    destination = Column(String(255), nullable=True)
    protocol = Column(String(50), nullable=True)
    port = Column(String(100), nullable=True)
    action = Column(String(50), nullable=False)  # permit, deny, etc.
    description = Column(Text, nullable=True)
    raw_config = Column(Text, nullable=True)  # Original config line
    
    # Relationships
    config_file = relationship("ConfigFile", back_populates="acls")

