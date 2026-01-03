"""VPN database model."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class VPN(Base):
    """VPN configuration model."""
    __tablename__ = "vpns"

    id = Column(Integer, primary_key=True, index=True)
    config_file_id = Column(Integer, ForeignKey("config_files.id"), nullable=False, index=True)
    vpn_name = Column(String(255), nullable=False, index=True)
    vpn_type = Column(String(100), nullable=True)  # site-to-site, remote-access, etc.
    peer_address = Column(String(255), nullable=True)
    pre_shared_key = Column(String(255), nullable=True)  # Should be encrypted in production
    encryption = Column(String(100), nullable=True)
    authentication = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    raw_config = Column(Text, nullable=True)
    
    # Relationships
    config_file = relationship("ConfigFile", back_populates="vpns")

