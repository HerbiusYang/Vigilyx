"""Tests for FastAPI endpoints with mocked models."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

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


# We need to patch _INTERNAL_TOKEN and _background_warmup for every test.
# Use a module-level approach via autouse fixture.


@pytest.fixture(autouse=True)
def _set_token():
    """Ensure the internal token env var is set before app module loads."""
    with patch("vigilyx_ai.api._INTERNAL_TOKEN", "test-secret-token"), \
         patch("vigilyx_ai.api._background_warmup", new=AsyncMock()):
        yield


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
                        "mail_from": "attacker@evil.invalid",
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


class TestRequestSizeLimit:
    """Request body byte cap should reject oversized JSON before endpoint parsing."""

    def test_oversized_request_body_413(self, monkeypatch):
        monkeypatch.setenv("AI_MAX_REQUEST_BYTES", "1024")
        mgr = _make_manager(_finetuned_model=object(), _finetuned_version="v1", _warmup_state="ready")
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app, raise_server_exceptions=False) as client:
                resp = client.post(
                    "/analyze/content",
                    json={"session_id": "s1", "body_text": "A" * 2048},
                    headers=AUTH_HEADERS,
                )

        assert resp.status_code == 413
        assert resp.json()["error"] == "REQUEST_TOO_LARGE"


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

    @pytest.mark.parametrize("samples_count", [0, 5, 35, 10001])
    def test_training_removed_410(self, samples_count):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                samples = [
                    {"session_id": f"s{i}", "label": 0, "subject": "Hi", "body_text": "Hello"}
                    for i in range(samples_count)
                ]
                resp = client.post(
                    "/training/train",
                    json={"samples": samples},
                    headers=AUTH_HEADERS,
                )
        assert resp.status_code == 410
        assert resp.json()["detail"] == "TRAINING_REMOVED"

    def test_training_requires_auth(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/training/train", json={"samples": []})
        assert resp.status_code == 401

    def test_training_progress_inactive(self):
        mgr = _make_manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.get("/training/progress", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert resp.json() == {"active": False}
