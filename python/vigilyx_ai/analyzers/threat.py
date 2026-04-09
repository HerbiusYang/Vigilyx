"""
Threat analyzer.

Uses simple rules plus AI-oriented signals to estimate email risk.
"""

from datetime import datetime
from typing import Optional

from ..models import (
    AnalysisResult,
    EmailPacket,
    EmailSession,
    ThreatLevel,
)
from .base import BaseAnalyzer


class ThreatAnalyzer(BaseAnalyzer):
    """Threat analyzer."""

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        "password", "credential", "login", "verify", "urgent",
        "account", "suspended", "confirm", "click here", "act now",
        "密码", "验证", "账户", "紧急", "立即", "点击",
    ]

    # Suspicious sender patterns
    SUSPICIOUS_PATTERNS = [
        r"@.*\d{5,}\..*",  # Domains with long numeric sequences
        r"@.*-.*-.*\..*",  # Multiple hyphens
    ]

    def __init__(self):
        super().__init__("threat_analyzer")

    async def analyze(
        self,
        session: EmailSession,
        packets: list[EmailPacket],
        options: Optional[dict] = None,
    ) -> AnalysisResult:
        """Run threat analysis."""
        categories: list[str] = []
        threat_score = 0.0
        details: dict = {}
        recommendations: list[str] = []

        # 1. Check sender
        if session.mail_from:
            sender_score, sender_cats = self._analyze_sender(session.mail_from)
            threat_score += sender_score
            categories.extend(sender_cats)
            details["sender_analysis"] = {
                "address": session.mail_from,
                "risk_score": sender_score,
            }

        # 2. Check subject
        if session.subject:
            subject_score, subject_cats = self._analyze_subject(session.subject)
            threat_score += subject_score
            categories.extend(subject_cats)
            details["subject_analysis"] = {
                "subject": session.subject,
                "risk_score": subject_score,
            }

        # 3. Check recipient volume
        if len(session.rcpt_to) > 10:
            threat_score += 0.2
            categories.append("mass_mailing")
            details["recipient_count"] = len(session.rcpt_to)

        # 4. Check packet content (simple heuristics)
        content_score, content_cats = self._analyze_content(packets)
        threat_score += content_score
        categories.extend(content_cats)

        # Compute final threat level
        threat_level = self._score_to_level(threat_score)

        # Generate recommendations
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            recommendations.append("Quarantine this email and trigger manual review.")
            recommendations.append("Check whether the sender appears in known malicious lists.")
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.append("Mark the email as suspicious.")
            recommendations.append("Warn recipients to handle it carefully.")

        return AnalysisResult(
            session_id=session.id,
            threat_level=threat_level,
            confidence=min(1.0, 0.5 + threat_score * 0.3),
            categories=list(set(categories)),
            summary=self._generate_summary(threat_level, categories),
            details=details,
            recommendations=recommendations,
            analyzed_at=datetime.utcnow(),
        )

    def _analyze_sender(self, sender: str) -> tuple[float, list[str]]:
        """Analyze the sender."""
        score = 0.0
        categories: list[str] = []

        # Check for suspicious patterns
        import re
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, sender, re.IGNORECASE):
                score += 0.3
                categories.append("suspicious_sender")
                break

        return score, categories

    def _analyze_subject(self, subject: str) -> tuple[float, list[str]]:
        """Analyze the email subject."""
        score = 0.0
        categories: list[str] = []

        subject_lower = subject.lower()
        keyword_count = sum(
            1 for kw in self.SUSPICIOUS_KEYWORDS
            if kw.lower() in subject_lower
        )

        if keyword_count > 0:
            score += min(0.5, keyword_count * 0.1)
            categories.append("suspicious_subject")

        # Check for all-uppercase subjects
        if subject.isupper() and len(subject) > 5:
            score += 0.1
            categories.append("uppercase_subject")

        return score, categories

    def _analyze_content(self, packets: list[EmailPacket]) -> tuple[float, list[str]]:
        """Analyze packet content."""
        score = 0.0
        categories: list[str] = []

        for packet in packets:
            if packet.raw_data:
                content_lower = packet.raw_data.lower()
                keyword_count = sum(
                    1 for kw in self.SUSPICIOUS_KEYWORDS
                    if kw.lower() in content_lower
                )
                if keyword_count > 2:
                    score += 0.2
                    categories.append("suspicious_content")
                    break

        return score, categories

    def _score_to_level(self, score: float) -> ThreatLevel:
        """Convert the score into a threat level."""
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        elif score >= 0.2:
            return ThreatLevel.LOW
        return ThreatLevel.SAFE

    def _generate_summary(self, level: ThreatLevel, categories: list[str]) -> str:
        """Generate an analysis summary."""
        level_desc = {
            ThreatLevel.SAFE: "safe",
            ThreatLevel.LOW: "low risk",
            ThreatLevel.MEDIUM: "medium risk",
            ThreatLevel.HIGH: "high risk",
            ThreatLevel.CRITICAL: "critical threat",
        }

        if not categories:
            return f"Email assessed as {level_desc[level]}; no obvious threat indicators were found."

        cats_str = ", ".join(categories[:3])
        return f"Email assessed as {level_desc[level]}; observed indicators: {cats_str}."
