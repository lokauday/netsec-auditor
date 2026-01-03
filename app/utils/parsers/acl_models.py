"""
Pydantic models for structured ACL representation.
"""
from typing import Optional
from pydantic import BaseModel


class ParsedACLEntry(BaseModel):
    """Structured representation of a parsed ACL entry."""
    name: str
    sequence: Optional[int] = None
    action: str  # e.g., "permit" / "deny"
    protocol: str
    src: str
    src_port: Optional[str] = None
    dst: str
    dst_port: Optional[str] = None
    raw_line: str

