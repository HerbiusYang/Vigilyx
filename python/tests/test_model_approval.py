"""PoC tests for the trained-model approval gate (C4).

Before the fix, a successful training run hot-swapped the new model into
inference automatically, so a consistent-poisoning attack that passed the CV
quality gate went live without any human approval. Now the model is staged
as pending and only swapped after an explicit POST /model/approve.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

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
    mgr._warmup_state = "ready"
    mgr.hot_swap = AsyncMock()
    return mgr


def _trainer(model_dir: str) -> MagicMock:
    trainer = MagicMock()
    trainer.is_training = False
    trainer.last_trained = "2026-08-13T00:00:00"
    trainer.train = AsyncMock(
        return_value={"ok": True, "model_dir": model_dir, "version": "v2"}
    )
    return trainer


def _samples(n: int = 35) -> list[dict]:
    return [
        {"session_id": f"s{i}", "label": 0, "subject": "Hi", "body_text": "Hello"}
        for i in range(n)
    ]


class TestTrainingStagesPending:

    def test_training_does_not_hot_swap_automatically(self, models_root):
        # 修复前: 训练成功 → manager.hot_swap() 立即上线（投毒模型直接生效）。
        model_dir = models_root / "run-20260813"
        model_dir.mkdir()
        mgr = _manager()
        trainer = _trainer(str(model_dir))

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.get_trainer", return_value=trainer):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/training/train",
                    json={"samples": _samples()},
                    headers=AUTH_HEADERS,
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["model_pending_approval"] is True
        assert "model_swapped" not in data
        # The old model keeps serving inference — no swap happened.
        mgr.hot_swap.assert_not_awaited()
        assert mgr._finetuned_version == "old-model-v1"
        # The staged model is recorded on disk.
        pending = json.loads((models_root / "pending.json").read_text())
        assert pending["model_dir"] == str(model_dir)
        assert pending["version"] == "v2"

    def test_training_status_exposes_pending_model(self, models_root):
        model_dir = models_root / "run-x"
        model_dir.mkdir()
        (models_root / "pending.json").write_text(
            json.dumps({"model_dir": str(model_dir), "version": "v9"})
        )
        mgr = _manager()

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.get_trainer", return_value=MagicMock(is_training=False, last_trained=None)), \
             patch("vigilyx_ai.api.get_base_model_info", return_value={}):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.get("/training/status", headers=AUTH_HEADERS)

        assert resp.status_code == 200
        assert resp.json()["pending_model"]["model_dir"] == str(model_dir)


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


class TestPendingFingerprintAndVersionCheck:
    """PoC (R4 发现D): the staged record must identify WHAT was trained
    (samples hash + timestamp), and approve must reject when the staged
    record changed between review and swap (409 instead of silently
    hot-swapping an unreviewed model).
    """

    def test_training_records_samples_hash_and_count(self, models_root):
        model_dir = models_root / "run-hash"
        model_dir.mkdir()
        mgr = _manager()
        trainer = _trainer(str(model_dir))

        with patch("vigilyx_ai.api.get_model_manager", return_value=mgr), \
             patch("vigilyx_ai.api.get_trainer", return_value=trainer):
            from vigilyx_ai.api import app
            with TestClient(app) as client:
                resp = client.post(
                    "/training/train",
                    json={"samples": _samples()},
                    headers=AUTH_HEADERS,
                )

        assert resp.status_code == 200
        pending = json.loads((models_root / "pending.json").read_text())
        assert pending["samples_count"] == 35
        assert isinstance(pending["samples_hash"], str)
        assert len(pending["samples_hash"]) == 64  # sha256 hex
        assert pending["staged_at"] > 0

    def test_samples_fingerprint_changes_with_content(self):
        from vigilyx_ai.api import TrainingSampleInput, _samples_fingerprint

        def _fp(samples):
            return _samples_fingerprint([TrainingSampleInput(**s) for s in samples])

        base = _samples()
        flipped = [dict(s) for s in base]
        flipped[0]["label"] = 4  # one label flipped (poisoning delta)
        assert _fp(base) != _fp(flipped)
        assert _fp(base) == _fp(_samples())  # deterministic

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
        # A concurrent training run stages a different model AFTER the
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