"""Tests for pending-model approval and optimistic concurrency checks."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from vigilyx_ai.nlp_phishing import ModelManager


@pytest.fixture(autouse=True)
def _set_token():
    """Same auth/warmup patching strategy as test_api_endpoints.py."""
    with patch("vigilyx_ai.api._INTERNAL_TOKEN", "test-secret-token"), \
         patch("vigilyx_ai.api._background_warmup", new=AsyncMock()):
        yield


AUTH_HEADERS = {"X-Internal-Token": "test-secret-token"}


@pytest.fixture
def models_root(tmp_path, monkeypatch):
    """Redirect the pending-file and models root into a tmp directory."""
    root = tmp_path / "nlp_models"
    root.mkdir()
    monkeypatch.setattr(
        "vigilyx_ai.api.LATEST_MODEL_DIR", str(root / "latest")
    )
    monkeypatch.setattr(
        "vigilyx_ai.api.PENDING_MODEL_FILE", str(root / "pending.json")
    )
    return root


def _manager() -> ModelManager:
    mgr = ModelManager()
    mgr._finetuned_model = object()
    mgr._finetuned_version = "old-model-v1"
    mgr._model_version = "old-model-v1"
    mgr._warmup_state = "ready"
    mgr.hot_swap = AsyncMock()
    return mgr


class TestModelStatus:

    def test_training_status_exposes_pending_model(self, models_root):
        model_dir = models_root / "run-x"
        model_dir.mkdir()
        (models_root / "pending.json").write_text(
            json.dumps({"model_dir": str(model_dir), "version": "v9"})
        )
        mgr = _manager()

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.get("/training/status", headers=AUTH_HEADERS)

        assert resp.status_code == 200
        data = resp.json()
        assert data["pending_model"]["model_dir"] == str(model_dir)
        assert data["training_enabled"] is False
        assert data["is_training"] is False
        assert data["last_trained"] is None
        assert data["base_model"] is None
        assert data["model_version"] == "old-model-v1"


class TestModelApproveEndpoint:

    def test_approve_swaps_and_clears_pending(self, models_root):
        model_dir = models_root / "run-approve"
        model_dir.mkdir()
        (models_root / "pending.json").write_text(
            json.dumps({"model_dir": str(model_dir), "version": "v2"})
        )
        mgr = _manager()

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/model/approve", headers=AUTH_HEADERS)

        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        mgr.hot_swap.assert_awaited_once()
        assert not (models_root / "pending.json").exists()

    def test_approve_without_pending_404(self, models_root):
        mgr = _manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/model/approve", headers=AUTH_HEADERS)

        assert resp.status_code == 404
        mgr.hot_swap.assert_not_awaited()

    def test_approve_missing_model_dir_410_and_clears(self, models_root):
        # Pending record points at a deleted directory: refuse and clean up.
        (models_root / "pending.json").write_text(
            json.dumps({"model_dir": str(models_root / "gone"), "version": "v3"})
        )
        mgr = _manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/model/approve", headers=AUTH_HEADERS)

        assert resp.status_code == 410
        mgr.hot_swap.assert_not_awaited()
        assert not (models_root / "pending.json").exists()

    def test_approve_rejects_path_outside_models_root(self, models_root, tmp_path):
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (models_root / "pending.json").write_text(
            json.dumps({"model_dir": str(outside), "version": "evil"})
        )
        mgr = _manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/model/approve", headers=AUTH_HEADERS)

        assert resp.status_code == 410
        mgr.hot_swap.assert_not_awaited()

    def test_approve_requires_auth(self, models_root):
        mgr = _manager()
        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/model/approve")
        assert resp.status_code == 401


class TestPendingVersionCheck:
    """Approval rejects a staged model that changed after operator review."""

    def test_approve_expected_mismatch_409(self, models_root):
        # 修复前: approve 无任何版本概念，审核的是模型 A、上线的是模型 B。
        model_dir = models_root / "run-mismatch"
        model_dir.mkdir()
        (models_root / "pending.json").write_text(
            json.dumps({
                "model_dir": str(model_dir),
                "version": "v2",
                "staged_at": 1000.0,
            })
        )
        mgr = _manager()

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/model/approve",
                    json={"expected_staged_at": 9999.0},
                    headers=AUTH_HEADERS,
                )

        assert resp.status_code == 409
        mgr.hot_swap.assert_not_awaited()
        assert (models_root / "pending.json").exists()  # staged record kept

    def test_approve_expected_match_succeeds_and_echoes(self, models_root):
        model_dir = models_root / "run-match"
        model_dir.mkdir()
        (models_root / "pending.json").write_text(
            json.dumps({
                "model_dir": str(model_dir),
                "version": "v2",
                "staged_at": 1000.0,
                "samples_count": 35,
                "samples_hash": "ab" * 32,
            })
        )
        mgr = _manager()

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/model/approve",
                    json={"expected_model_dir": str(model_dir), "expected_staged_at": 1000.0},
                    headers=AUTH_HEADERS,
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        mgr.hot_swap.assert_awaited_once()
        # The approved record is echoed back for operator-side comparison.
        assert data["approved_model"]["samples_hash"] == "ab" * 32
        assert data["approved_model"]["staged_at"] == 1000.0

    def test_approve_race_between_read_and_swap_409(self, models_root):
        # A concurrent update stages a different model AFTER the
        # approve endpoint's first read but BEFORE the swap: the approval
        # must be rejected instead of hot-swapping the unreviewed model.
        model_dir = models_root / "run-race"
        model_dir.mkdir()
        original = {
            "model_dir": str(model_dir),
            "version": "v2",
            "staged_at": 1000.0,
        }
        changed = {
            "model_dir": str(model_dir),
            "version": "v3-poisoned",
            "staged_at": 2000.0,
        }
        (models_root / "pending.json").write_text(json.dumps(original))
        mgr = _manager()

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch(
                 "vigilyx_ai.api._read_pending_model",
                 side_effect=[dict(original), dict(changed)],
             ):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post("/model/approve", headers=AUTH_HEADERS)

        assert resp.status_code == 409
        mgr.hot_swap.assert_not_awaited()
