"""Routing database model."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Integer as IntCol
from sqlalchemy.orm import relationship

from app.core.database import Base


class Route(Base):
    """Routing table entry model."""
    __tablename__ = "routes"

    id = Column(Integer, primary_key=True, index=True)
    config_file_id = Column(Integer, ForeignKey("config_files.id"), nullable=False, index=True)
    network = Column(String(255), nullable=False, index=True)
    subnet_mask = Column(String(255), nullable=True)
    next_hop = Column(String(255), nullable=True)
    interface = Column(String(255), nullable=True)
    protocol = Column(String(50), nullable=True)  # static, ospf, bgp, etc.
    administrative_distance = Column(IntCol, nullable=True)
    metric = Column(IntCol, nullable=True)
    description = Column(Text, nullable=True)
    raw_config = Column(Text, nullable=True)
    
    # Relationships
    config_file = relationship("ConfigFile", back_populates="routes")

