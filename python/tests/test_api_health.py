import time
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from vigilyx_ai.api import app
from vigilyx_ai.nlp_phishing import ModelManager, ModelUnavailableError


class AiApiHealthTests(unittest.TestCase):
    def _client_with_manager(self, manager: ModelManager):
        return patch("vigilyx_ai.api.get_model_manager", return_value=manager), patch(
            "vigilyx_ai.api._background_warmup", new=AsyncMock()
        )

    def test_health_ready_reports_not_ready_when_models_are_unavailable(self):
        manager = ModelManager()
        manager._warmup_state = "failed"
        manager._last_error = "download failed"
        manager._unavailable_until_ts = time.time() + 90

        manager_patch, warmup_patch = self._client_with_manager(manager)
        with manager_patch, warmup_patch, TestClient(app) as client:
            response = client.get("/health/ready")

        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertEqual(payload["error"], "MODEL_UNAVAILABLE")
        self.assertGreater(payload["retry_after_secs"], 0)
        self.assertFalse(payload["model_status"]["ready"])

    def test_health_ready_reports_ready_when_finetuned_model_is_loaded(self):
        manager = ModelManager()
        manager._finetuned_model = object()
        manager._finetuned_version = "fixture-model"
        manager._model_version = "fixture-model"
        manager._warmup_state = "ready"

        manager_patch, warmup_patch = self._client_with_manager(manager)
        with manager_patch, warmup_patch, TestClient(app) as client:
            response = client.get("/health/ready")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ready")
        self.assertTrue(payload["model_status"]["ready"])
        self.assertEqual(payload["model_status"]["mode"], "fine_tuned")

    def test_analyze_content_returns_503_when_model_is_unavailable(self):
        manager = ModelManager()
        manager._warmup_state = "failed"
        manager._last_error = "download failed"
        manager._unavailable_until_ts = time.time() + 60
        unavailable = ModelUnavailableError(
            "NLP model unavailable",
            retry_after_secs=60,
            status=manager.readiness_report(),
        )

        manager_patch, warmup_patch = self._client_with_manager(manager)
        with manager_patch, warmup_patch, patch(
            "vigilyx_ai.api._INTERNAL_TOKEN", "test-token"
        ), patch(
            "vigilyx_ai.api.analyze_phishing_nlp", side_effect=unavailable
        ), TestClient(app) as client:
            response = client.post(
                "/analyze/content",
                headers={"X-Internal-Token": "test-token"},
                json={
                    "session_id": "session-1",
                    "subject": "Reset password",
                    "body_text": "Please verify your account",
                    "mail_from": "security@example.com",
                    "rcpt_to": ["user@example.com"],
                },
            )

        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertEqual(payload["error"], "MODEL_UNAVAILABLE")
        self.assertEqual(payload["retry_after_secs"], 60)
        self.assertFalse(payload["model_status"]["ready"])


class LastErrorSanitizationTests(unittest.TestCase):
    """SEC-22: unauthenticated health output must not leak filesystem details."""

    def test_sanitize_last_error_redacts_paths_and_truncates(self):
        from vigilyx_ai.nlp_phishing import _sanitize_last_error

        self.assertIsNone(_sanitize_last_error(None))
        self.assertIsNone(_sanitize_last_error(""))
        self.assertEqual(
            _sanitize_last_error("OSError: /app/data/nlp_models/base/config.json missing"),
            "OSError: <path> missing",
        )
        self.assertEqual(
            _sanitize_last_error(r"IOError: C:\models\base\config.json missing"),
            "IOError: <path> missing",
        )
        # Plain messages without paths pass through unchanged.
        self.assertEqual(
            _sanitize_last_error("All zero-shot NLP models failed to load"),
            "All zero-shot NLP models failed to load",
        )
        self.assertEqual(len(_sanitize_last_error("E" * 200)), 120)

    def test_health_redacts_paths_in_last_error(self):
        manager = ModelManager()
        manager._warmup_state = "failed"
        manager._last_error = (
            "OSError: /app/data/nlp_models/base/config.json not found; "
            "hf download failed " + "x" * 200
        )

        with patch("vigilyx_ai.api.get_model_manager", return_value=manager), patch(
            "vigilyx_ai.api._background_warmup", new=AsyncMock()
        ), TestClient(app) as client:
            response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        last_error = response.json()["model_status"]["last_error"]
        self.assertIsNotNone(last_error)
        self.assertNotIn("/app", last_error)
        self.assertLessEqual(len(last_error), 120)
        self.assertIn("OSError", last_error)


if __name__ == "__main__":
    unittest.main()
