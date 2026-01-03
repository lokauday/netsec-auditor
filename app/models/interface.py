"""Interface database model."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.core.database import Base


class Interface(Base):
    """Network interface model."""
    __tablename__ = "interfaces"

    id = Column(Integer, primary_key=True, index=True)
    config_file_id = Column(Integer, ForeignKey("config_files.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(255), nullable=True)
    subnet_mask = Column(String(255), nullable=True)
    vlan_id = Column(Integer, nullable=True)
    speed = Column(String(50), nullable=True)
    duplex = Column(String(50), nullable=True)
    status = Column(String(50), nullable=True)  # up, down, administratively down
    description = Column(Text, nullable=True)
    is_shutdown = Column(Boolean, default=False)
    raw_config = Column(Text, nullable=True)
    
    # Relationships
    config_file = relationship("ConfigFile", back_populates="interfaces")

