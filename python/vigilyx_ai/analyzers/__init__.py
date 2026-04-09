"""
Analyzer package.

Provides email-analysis capabilities such as:
- threat detection
- content classification
- anomaly identification
"""

from .base import BaseAnalyzer
from .threat import ThreatAnalyzer

__all__ = ["BaseAnalyzer", "ThreatAnalyzer"]
