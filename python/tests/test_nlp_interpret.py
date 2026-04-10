"""Tests for ModelManager._interpret_5class and _interpret_2class.

These tests require the real torch to create synthetic probability tensors.
They are skipped if torch is not installed.
"""

from __future__ import annotations

import pytest

from tests.conftest import torch_available

pytestmark = pytest.mark.skipif(not torch_available, reason="torch not installed")


@pytest.fixture()
def manager():
    """Create a ModelManager instance without loading any models."""
    from vigilyx_ai.nlp_phishing import ModelManager
    mgr = ModelManager()
    mgr._finetuned_version = "test-v1"
    return mgr


@pytest.fixture()
def torch():
    import torch as _t
    return _t


# =====================================================================
# _interpret_5class
# =====================================================================


class TestInterpret5Class:
    """~10 cases for _interpret_5class."""

    def test_legitimate_dominant(self, manager, torch):
        probs = torch.tensor([0.9, 0.05, 0.02, 0.02, 0.01])
        result = manager._interpret_5class(probs, "test email", 42)
        assert result.threat_level == "safe"
        assert result.is_phishing is False
        assert result.confidence == pytest.approx(0.9, abs=0.01)
        assert result.inference_ms == 42

    def test_phishing_dominant(self, manager, torch):
        probs = torch.tensor([0.1, 0.8, 0.05, 0.03, 0.02])
        result = manager._interpret_5class(probs, "test email", 50)
        assert result.threat_level == "high"
        assert result.is_phishing is True
        assert result.confidence == pytest.approx(0.8, abs=0.01)

    def test_spoofing_dominant(self, manager, torch):
        probs = torch.tensor([0.05, 0.1, 0.8, 0.03, 0.02])
        result = manager._interpret_5class(probs, "test email", 30)
        assert result.threat_level == "critical"
        assert result.is_phishing is True

    def test_social_engineering_dominant(self, manager, torch):
        probs = torch.tensor([0.1, 0.05, 0.05, 0.7, 0.1])
        result = manager._interpret_5class(probs, "test email", 25)
        assert result.threat_level == "high"
        assert result.is_phishing is True

    def test_other_threat_dominant(self, manager, torch):
        probs = torch.tensor([0.1, 0.05, 0.05, 0.05, 0.75])
        result = manager._interpret_5class(probs, "test email", 20)
        assert result.threat_level == "medium"
        assert result.is_phishing is True

    def test_uniform_distribution(self, manager, torch):
        probs = torch.tensor([0.2, 0.2, 0.2, 0.2, 0.2])
        result = manager._interpret_5class(probs, "test email", 15)
        assert result.confidence == pytest.approx(0.2, abs=0.01)

    def test_confidence_equals_top_prob(self, manager, torch):
        probs = torch.tensor([0.15, 0.65, 0.10, 0.05, 0.05])
        result = manager._interpret_5class(probs, "test email", 10)
        assert result.confidence == pytest.approx(0.65, abs=0.01)

    def test_categories_above_threshold(self, manager, torch):
        probs = torch.tensor([0.15, 0.30, 0.10, 0.20, 0.25])
        result = manager._interpret_5class(probs, "test email", 10)
        assert "nlp_phishing" in result.categories
        assert "nlp_social_engineering" in result.categories
        assert "nlp_spoofing" not in result.categories

    def test_categories_empty_when_legitimate(self, manager, torch):
        probs = torch.tensor([0.95, 0.02, 0.01, 0.01, 0.01])
        result = manager._interpret_5class(probs, "test email", 5)
        assert result.categories == []

    def test_summary_contains_model_type(self, manager, torch):
        probs = torch.tensor([0.9, 0.05, 0.02, 0.02, 0.01])
        result = manager._interpret_5class(probs, "test email", 42)
        assert "Fine-tuned 5-class" in result.summary


# =====================================================================
# _interpret_2class
# =====================================================================


class TestInterpret2Class:
    """~12 cases for _interpret_2class."""

    def test_safe_dominant(self, manager, torch):
        probs = torch.tensor([0.9, 0.1])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "safe"
        assert result.is_phishing is False
        assert result.confidence == pytest.approx(0.9, abs=0.01)

    def test_critical_threshold(self, manager, torch):
        probs = torch.tensor([0.1, 0.9])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "critical"
        assert result.is_phishing is True
        assert result.confidence == pytest.approx(0.9, abs=0.01)

    def test_high_threshold(self, manager, torch):
        probs = torch.tensor([0.3, 0.7])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "high"
        assert result.is_phishing is True

    def test_medium_threshold(self, manager, torch):
        probs = torch.tensor([0.55, 0.45])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "medium"
        assert result.is_phishing is True

    def test_low_threshold(self, manager, torch):
        probs = torch.tensor([0.75, 0.25])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "low"
        assert result.is_phishing is False

    def test_boundary_at_085(self, manager, torch):
        probs = torch.tensor([0.15, 0.85])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "critical"

    def test_boundary_at_065(self, manager, torch):
        probs = torch.tensor([0.35, 0.65])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "high"

    def test_boundary_at_040(self, manager, torch):
        probs = torch.tensor([0.60, 0.40])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "medium"

    def test_boundary_at_020(self, manager, torch):
        probs = torch.tensor([0.80, 0.20])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "low"

    def test_below_020(self, manager, torch):
        probs = torch.tensor([0.85, 0.15])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.threat_level == "safe"

    def test_categories_nlp_phishing_when_above_03(self, manager, torch):
        probs = torch.tensor([0.6, 0.4])
        result = manager._interpret_2class(probs, "test email", 20)
        assert "nlp_phishing" in result.categories

    def test_categories_empty_when_below_03(self, manager, torch):
        probs = torch.tensor([0.85, 0.15])
        result = manager._interpret_2class(probs, "test email", 20)
        assert result.categories == []
