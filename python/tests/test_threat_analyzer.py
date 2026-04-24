"""Tests for ThreatAnalyzer rule-based functions."""

from __future__ import annotations

import pytest

from vigilyx_ai.analyzers.threat import ThreatAnalyzer
from vigilyx_ai.models import ThreatLevel


@pytest.fixture()
def analyzer():
    return ThreatAnalyzer()


# =====================================================================
# _score_to_level
# =====================================================================


class TestScoreToLevel:
    """~10 boundary-value cases for _score_to_level."""

    def test_zero(self, analyzer):
        assert analyzer._score_to_level(0.0) == ThreatLevel.SAFE

    def test_019(self, analyzer):
        assert analyzer._score_to_level(0.19) == ThreatLevel.SAFE

    def test_020(self, analyzer):
        assert analyzer._score_to_level(0.2) == ThreatLevel.LOW

    def test_039(self, analyzer):
        assert analyzer._score_to_level(0.39) == ThreatLevel.LOW

    def test_040(self, analyzer):
        assert analyzer._score_to_level(0.4) == ThreatLevel.MEDIUM

    def test_059(self, analyzer):
        assert analyzer._score_to_level(0.59) == ThreatLevel.MEDIUM

    def test_060(self, analyzer):
        assert analyzer._score_to_level(0.6) == ThreatLevel.HIGH

    def test_079(self, analyzer):
        assert analyzer._score_to_level(0.79) == ThreatLevel.HIGH

    def test_080(self, analyzer):
        assert analyzer._score_to_level(0.8) == ThreatLevel.CRITICAL

    def test_100(self, analyzer):
        assert analyzer._score_to_level(1.0) == ThreatLevel.CRITICAL


# =====================================================================
# _analyze_sender
# =====================================================================


class TestAnalyzeSender:
    """~5 cases for _analyze_sender."""

    def test_normal_address(self, analyzer):
        score, cats = analyzer._analyze_sender("alice@example.com")
        assert score == 0.0
        assert cats == []

    def test_long_numbers_in_domain(self, analyzer):
        # Pattern: @.*\d{5,}\..*
        score, cats = analyzer._analyze_sender("user@domain12345.test")
        assert score > 0
        assert "suspicious_sender" in cats

    def test_many_hyphens_in_domain(self, analyzer):
        # Pattern: @.*-.*-.*\..*
        score, cats = analyzer._analyze_sender("user@foo-bar-baz.test")
        assert score > 0
        assert "suspicious_sender" in cats

    def test_empty_string(self, analyzer):
        score, cats = analyzer._analyze_sender("")
        assert score == 0.0
        assert cats == []

    def test_only_one_hyphen_not_suspicious(self, analyzer):
        score, cats = analyzer._analyze_sender("user@my-domain.test")
        assert score == 0.0
        assert cats == []


# =====================================================================
# _analyze_subject
# =====================================================================


class TestAnalyzeSubject:
    """~6 cases for _analyze_subject."""

    def test_normal_subject(self, analyzer):
        score, cats = analyzer._analyze_subject("Meeting at 3pm today")
        assert score == 0.0
        assert cats == []

    def test_single_phishing_keyword(self, analyzer):
        score, cats = analyzer._analyze_subject("Please verify your password")
        # "password" and "verify" → 2 keywords → 0.2
        assert score > 0
        assert "suspicious_subject" in cats

    def test_all_caps_subject_adds_score(self, analyzer):
        score, cats = analyzer._analyze_subject("MEETING TOMORROW AFTERNOON")
        # No suspicious keywords, but all caps and len > 5 → +0.1
        assert score == pytest.approx(0.1)
        assert "uppercase_subject" in cats

    def test_chinese_keywords(self, analyzer):
        score, cats = analyzer._analyze_subject("紧急：请验证您的账户")
        # Three suspicious Chinese keywords contribute 0.3 in total.
        assert score >= 0.3
        assert "suspicious_subject" in cats

    def test_multiple_keywords_capped(self, analyzer):
        # 6+ keywords should cap at 0.5
        subject = "urgent password verify account login confirm"
        score, cats = analyzer._analyze_subject(subject)
        assert score == pytest.approx(0.5)
        assert "suspicious_subject" in cats

    def test_short_uppercase_not_flagged(self, analyzer):
        # len <= 5 → isupper check doesn't trigger
        score, cats = analyzer._analyze_subject("HELLO")
        assert "uppercase_subject" not in cats
