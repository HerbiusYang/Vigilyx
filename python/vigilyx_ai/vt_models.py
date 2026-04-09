"""
VirusTotal scraping request/response models.

These stay aligned with the Rust IntelLayer VT scrape client.
"""

from typing import Optional
from pydantic import BaseModel, Field


class VtScrapeRequest(BaseModel):
    """VT scrape request."""
    indicator: str = Field(description="Domain, IP, URL, or file hash")
    indicator_type: str = Field(description="domain / ip / url / hash")


class VtScrapeResponse(BaseModel):
    """VT scrape response."""
    success: bool
    verdict: str = Field(
        default="unknown",
        description="malicious / suspicious / clean / unknown",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    malicious_count: int = Field(default=0, ge=0)
    total_engines: int = Field(default=0, ge=0)
    details: str = Field(default="")
    error: Optional[str] = None
