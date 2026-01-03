"""Audit record database model."""
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AuditRecord(Base):
    """Audit record model for storing audit history."""
    __tablename__ = "audit_records"

    id = Column(Integer, primary_key=True, index=True)
    config_file_id = Column(Integer, ForeignKey("config_files.id", ondelete="CASCADE"), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    summary = Column(Text, nullable=False)
    breakdown = Column(JSON, nullable=False)  # Store breakdown as JSON: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = Column(JSON, nullable=False)  # Store findings as JSON
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    config_file = relationship("ConfigFile", backref="audit_records")

