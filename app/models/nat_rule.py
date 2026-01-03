"""NAT rule database model."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class NATRule(Base):
    """NAT (Network Address Translation) rule model."""
    __tablename__ = "nat_rules"

    id = Column(Integer, primary_key=True, index=True)
    config_file_id = Column(Integer, ForeignKey("config_files.id"), nullable=False, index=True)
    rule_name = Column(String(255), nullable=True, index=True)
    rule_number = Column(Integer, nullable=True)
    source_original = Column(String(255), nullable=True)
    source_translated = Column(String(255), nullable=True)
    destination_original = Column(String(255), nullable=True)
    destination_translated = Column(String(255), nullable=True)
    interface = Column(String(255), nullable=True)
    protocol = Column(String(50), nullable=True)
    port = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    raw_config = Column(Text, nullable=True)
    
    # Relationships
    config_file = relationship("ConfigFile", back_populates="nat_rules")

