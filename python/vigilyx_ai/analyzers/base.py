"""
Base analyzer abstractions.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..models import AnalysisResult, EmailSession, EmailPacket


class BaseAnalyzer(ABC):
    """Base class for analyzers."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def analyze(
        self,
        session: EmailSession,
        packets: list[EmailPacket],
        options: Optional[dict] = None,
    ) -> AnalysisResult:
        """
        Run analysis.

        Args:
            session: Email session
            packets: Related packet list
            options: Analyzer options

        Returns:
            Analysis result
        """
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r})>"
