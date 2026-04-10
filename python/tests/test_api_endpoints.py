"""Tests for FastAPI endpoints with mocked models."""

from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vigilyx_ai.nlp_phishing import ModelManager, ModelUnavailableError, NLPPhishingResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager(**overrides) -> ModelManager:
    """Create a ModelManager with optional attribute overrides."""
    mgr = ModelManager()
    for k, v in overrides.items():
        setattr(mgr, k, v)
    return mgr


def _patch_stack(*patches):
    """Context-manager factory: enter all patches at once."""
    import contextlib
    return contextlib.ExitStack()


# We need to patch _INTERNAL_TOKEN and _background_warmup for every test.
# Use a module-level approach via autouse fixture.


@pytest.fixture(autouse=True)
def _set_token():
    """Ensure the internal token env var is set before app module loads."""
    with patch("vigilyx_ai.api._INTERNAL_TOKEN", "test-secret-token"), \
         patch("vigilyx_ai.api._background_warmup", new=AsyncMock()):
        yield


def _client(manager: ModelManager | None = None):
    """Build a TestClient with optional ModelManager override."""
    patches = {}
    if manager is not None:
        return patch("vigilyx_ai.api.get_model_manager", return_value=manager)
    return patch("vigilyx_ai.api.get_model_manager", return_value=_make_manager())


AUTH_HEADERS = {"X-Internal-Token": "test-secret-token"}
WRONG_HEADERS = {"X-Internal-Token": "wrong-token"}


# =====================================================================
# Authentication middleware
# =====================================================================


class TestAuthMiddleware:
    """~5 cases for the X-Internal-Token middleware."""

    def test_no_token_rejected(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.post("/analyze/content", json={"session_id": "s1"})
        assert resp.status_code == 401

    def test_wrong_token_rejected(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.post(
                    "/analyze/content",
                    json={"session_id": "s1"},
                    headers=WRONG_HEADERS,
                )
        assert resp.status_code == 401

    def test_correct_token_allowed(self):
        mgr = _make_manager(_finetuned_model=object(), _finetuned_version="v1", _warmup_state="ready")
        nlp_result = NLPPhishingResult(
            is_phishing=False, threat_level="safe", confidence=0.95,
            categories=[], summary="safe", model_name="test",
        )
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.analyze_phishing_nlp", new=AsyncMock(return_value=nlp_result)):
            from vigilyx_ai.api import app
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.post(
                    "/analyze/content",
                    json={"session_id": "s1", "subject": "Hello", "body_text": "Hi there"},
                    headers=AUTH_HEADERS,
                )
        assert resp.status_code == 200

    def test_health_without_token_allowed(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_ready_without_token_allowed(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.get("/health/ready")
        # 200 or 503 depending on model state, but NOT 401/403
        assert resp.status_code in (200, 503)


# =====================================================================
# POST /analyze/content
# =====================================================================


class TestAnalyzeContent:
    """~3 cases for the /analyze/content endpoint."""

    def test_successful_analysis(self):
        mgr = _make_manager(_finetuned_model=object(), _finetuned_version="v1", _warmup_state="ready")
        nlp_result = NLPPhishingResult(
            is_phishing=True,
            threat_level="high",
            confidence=0.85,
            categories=["nlp_phishing"],
            summary="Phishing detected",
            details={"model_type": "test"},
            model_name="test-model",
            inference_ms=42,
        )
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.analyze_phishing_nlp", new=AsyncMock(return_value=nlp_result)):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/analyze/content",
                    json={
                        "session_id": "s1",
                        "subject": "Reset password",
                        "body_text": "Click here to verify",
                        "mail_from": "attacker@evil.com",
                    },
                    headers=AUTH_HEADERS,
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_level"] == "high"
        assert data["confidence"] == pytest.approx(0.85)
        assert "nlp_phishing" in data["categories"]

    def test_model_unavailable_503(self):
        mgr = _make_manager(_warmup_state="failed", _last_error="fail")
        mgr._unavailable_until_ts = time.time() + 60
        exc = ModelUnavailableError("Model unavailable", retry_after_secs=60, status=mgr.readiness_report())
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.analyze_phishing_nlp", new=AsyncMock(side_effect=exc)):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/analyze/content",
                    json={"session_id": "s1", "subject": "Test", "body_text": "Test"},
                    headers=AUTH_HEADERS,
                )
        assert resp.status_code == 503
        data = resp.json()
        assert data["error"] == "MODEL_UNAVAILABLE"

    def test_generic_exception_500(self):
        mgr = _make_manager(_finetuned_model=object(), _finetuned_version="v1", _warmup_state="ready")
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.analyze_phishing_nlp", new=AsyncMock(side_effect=RuntimeError("boom"))):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/analyze/content",
                    json={"session_id": "s1", "subject": "Test", "body_text": "Test"},
                    headers=AUTH_HEADERS,
                )
        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "ANALYSIS_FAILED"


# =====================================================================
# GET /health
# =====================================================================


class TestHealthEndpoint:

    def test_returns_200_with_status(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "vigilyx-ai"
        assert "model_status" in data


# =====================================================================
# GET /health/ready
# =====================================================================


class TestHealthReady:

    def test_model_ready_200(self):
        mgr = _make_manager(_finetuned_model=object(), _finetuned_version="v1", _warmup_state="ready")
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"

    def test_model_not_ready_503(self):
        mgr = _make_manager(_warmup_state="failed", _last_error="fail")
        mgr._unavailable_until_ts = time.time() + 120
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["error"] == "MODEL_UNAVAILABLE"
        assert data["retry_after_secs"] > 0


# =====================================================================
# POST /training/train
# =====================================================================


class TestTrainingEndpoint:

    def test_already_training_409(self):
        mgr = _make_manager()
        mock_trainer = MagicMock()
        mock_trainer.is_training = True  # Simulate already training
        # When train() is called while is_training, it returns error dict
        mock_trainer.train = AsyncMock(
            return_value={"ok": False, "error": "Training is already in progress. Try again later."}
        )

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.get_trainer", return_value=mock_trainer):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                samples = [
                    {"session_id": f"s{i}", "label": 0, "subject": "Hi", "body_text": "Hello"}
                    for i in range(35)
                ]
                resp = client.post(
                    "/training/train",
                    json={"samples": samples},
                    headers=AUTH_HEADERS,
                )
        # The endpoint returns 200 with ok=False (not a real 409 HTTP status)
        data = resp.json()
        assert data["ok"] is False
        assert "already in progress" in data["error"].lower()

    def test_too_few_samples(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                samples = [
                    {"session_id": f"s{i}", "label": 0, "subject": "Hi", "body_text": "Hello"}
                    for i in range(5)  # Below MIN_SAMPLES=30
                ]
                resp = client.post(
                    "/training/train",
                    json={"samples": samples},
                    headers=AUTH_HEADERS,
                )
        data = resp.json()
        assert data["ok"] is False
        assert "insufficient" in data.get("error", "").lower()

    def test_too_many_samples_413(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                samples = [
                    {"session_id": f"s{i}", "label": 0, "subject": "Hi", "body_text": "Hello"}
                    for i in range(10001)  # > 10000
                ]
                resp = client.post(
                    "/training/train",
                    json={"samples": samples},
                    headers=AUTH_HEADERS,
                )
        # HTTPException with 413
        assert resp.status_code == 413
