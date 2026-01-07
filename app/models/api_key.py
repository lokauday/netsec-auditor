"""API key database model."""
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func

from app.core.database import Base


class APIKey(Base):
    """API key model for database-backed authentication."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)  # Hashed API key
    label = Column(String(255), nullable=True)
    role = Column(String(50), nullable=False, default="read_only")  # "admin" or "read_only"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)  # Track last usage
    
    # Backward compatibility: keep 'key' as a property that references key_hash
    @property
    def key(self):
        """Backward compatibility property."""
        return self.key_hash
    
    @key.setter
    def key(self, value):
        """Backward compatibility setter."""
        self.key_hash = value

