"""
Data model definitions.

These structures stay aligned with the Rust-side `vigilyx-core` models.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Protocol(str, Enum):
    """Email protocol type."""
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    UNKNOWN = "UNKNOWN"


class SessionStatus(str, Enum):
    """Session status."""
    ACTIVE = "active"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"


class Direction(str, Enum):
    """Traffic direction."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class EmailSession(BaseModel):
    """Email session."""
    id: str
    protocol: Protocol
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: SessionStatus
    packet_count: int
    total_bytes: int
    mail_from: Optional[str] = None
    rcpt_to: list[str] = Field(default_factory=list)
    subject: Optional[str] = None


class EmailPacket(BaseModel):
    """Email packet."""
    id: str
    session_id: str
    protocol: Protocol
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    direction: Direction
    size: int
    timestamp: datetime
    command: Optional[str] = None
    raw_data: Optional[str] = None


class ThreatLevel(str, Enum):
    """Threat level."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisResult(BaseModel):
    """Analysis result."""
    session_id: str
    threat_level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    summary: str
    details: dict = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AIAnalyzeRequest(BaseModel):
    """AI analysis request."""
    session: EmailSession
    packets: list[EmailPacket] = Field(default_factory=list)
    options: dict = Field(default_factory=dict)


class AIAnalyzeResponse(BaseModel):
    """AI analysis response."""
    success: bool
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None
