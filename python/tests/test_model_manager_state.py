"""Tests for ModelManager state management without loading models."""

from __future__ import annotations

import time

import pytest

from vigilyx_ai.nlp_phishing import ModelManager


class TestMarkUnavailable:
    """~5 cases for _mark_unavailable backoff logic."""

    def test_first_failure_30s(self):
        mgr = ModelManager()
        secs = mgr._mark_unavailable("fail1")
        assert secs == 30
        assert mgr._consecutive_failures == 1

    def test_second_failure_60s(self):
        mgr = ModelManager()
        mgr._mark_unavailable("fail1")
        secs = mgr._mark_unavailable("fail2")
        assert secs == 60
        assert mgr._consecutive_failures == 2

    def test_third_failure_120s(self):
        mgr = ModelManager()
        mgr._mark_unavailable("f1")
        mgr._mark_unavailable("f2")
        secs = mgr._mark_unavailable("f3")
        assert secs == 120
        assert mgr._consecutive_failures == 3

    def test_fourth_failure_240s(self):
        mgr = ModelManager()
        for i in range(3):
            mgr._mark_unavailable(f"f{i}")
        secs = mgr._mark_unavailable("f4")
        assert secs == 240

    def test_fifth_and_beyond_capped_at_300s(self):
        mgr = ModelManager()
        for i in range(4):
            mgr._mark_unavailable(f"f{i}")
        secs = mgr._mark_unavailable("f5")
        assert secs == 300
        # Beyond 5 stays at 300
        secs = mgr._mark_unavailable("f6")
        assert secs == 300

    def test_stores_error_message(self):
        mgr = ModelManager()
        mgr._mark_unavailable("download failed")
        assert mgr._last_error == "download failed"


class TestClearFailureState:
    """~3 cases for _clear_failure_state."""

    def test_resets_consecutive_failures(self):
        mgr = ModelManager()
        mgr._mark_unavailable("f1")
        mgr._mark_unavailable("f2")
        mgr._clear_failure_state()
        assert mgr._consecutive_failures == 0

    def test_clears_error_message(self):
        mgr = ModelManager()
        mgr._mark_unavailable("something broke")
        mgr._clear_failure_state()
        assert mgr._last_error is None

    def test_clears_cooldown_timestamp(self):
        mgr = ModelManager()
        mgr._mark_unavailable("f")
        assert mgr._unavailable_until_ts > 0
        mgr._clear_failure_state()
        assert mgr._unavailable_until_ts == 0.0


class TestCooldownRemainingSecs:
    """~3 cases for cooldown_remaining_secs."""

    def test_no_cooldown_returns_zero(self):
        mgr = ModelManager()
        assert mgr.cooldown_remaining_secs() == 0

    def test_active_cooldown_returns_positive(self):
        mgr = ModelManager()
        mgr._unavailable_until_ts = time.time() + 100
        remaining = mgr.cooldown_remaining_secs()
        assert remaining > 0
        assert remaining <= 100

    def test_expired_cooldown_returns_zero(self):
        mgr = ModelManager()
        mgr._unavailable_until_ts = time.time() - 10
        assert mgr.cooldown_remaining_secs() == 0


class TestReadinessReport:
    """~5 cases for readiness_report."""

    def test_fresh_init_uninitialized(self):
        mgr = ModelManager()
        report = mgr.readiness_report()
        assert report["ready"] is False
        assert report["mode"] == "uninitialized"
        assert report["active_model"] is None
        assert report["has_finetuned"] is False
        assert report["zero_shot_loaded"] is False

    def test_after_mark_unavailable_with_active_cooldown(self):
        mgr = ModelManager()
        mgr._warmup_state = "failed"
        mgr._mark_unavailable("all models failed")
        report = mgr.readiness_report()
        assert report["ready"] is False
        assert report["mode"] == "cooldown"
        assert report["retry_after_secs"] > 0
        assert report["last_error"] == "all models failed"

    def test_after_mark_unavailable_with_expired_cooldown(self):
        mgr = ModelManager()
        mgr._mark_unavailable("fail")
        mgr._unavailable_until_ts = time.time() - 10  # Expired
        mgr._warmup_state = "failed"
        report = mgr.readiness_report()
        assert report["ready"] is False
        assert report["mode"] == "failed"

    def test_finetuned_model_loaded(self):
        mgr = ModelManager()
        mgr._finetuned_model = object()  # Fake model
        mgr._finetuned_version = "v42"
        mgr._warmup_state = "ready"
        report = mgr.readiness_report()
        assert report["ready"] is True
        assert report["mode"] == "fine_tuned"
        assert report["active_model"] == "fine-tuned/v42"
        assert report["has_finetuned"] is True

    def test_warming_up_mode(self):
        mgr = ModelManager()
        mgr._warmup_state = "running"
        report = mgr.readiness_report()
        assert report["ready"] is False
        assert report["mode"] == "warming_up"
