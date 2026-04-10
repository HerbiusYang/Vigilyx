"""Shared fixtures and factories for Vigilyx AI tests.

This module also installs a mock ``torch`` shim so that
``vigilyx_ai.nlp_phishing`` can be imported on development machines
where PyTorch is not installed (macOS laptops, CI runners without GPU
dependencies, etc.).  The shim is **only** used when ``torch`` is not
already available.
"""

from __future__ import annotations

import os
import sys
import types
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Ensure AI internal token is set for API tests before any app import.
# ---------------------------------------------------------------------------
os.environ.setdefault("AI_INTERNAL_TOKEN", "test-secret-token")

# ---------------------------------------------------------------------------
# Mock torch if not installed so nlp_phishing can be imported.
# ---------------------------------------------------------------------------
_real_torch = True
try:
    import torch as _torch  # noqa: F401
except ImportError:
    _real_torch = False

    # Minimal shim so that ``import torch`` and the top-level calls in
    # nlp_phishing.py succeed.
    _torch_mod = types.ModuleType("torch")

    # torch.cuda
    _cuda_mod = types.ModuleType("torch.cuda")
    _cuda_mod.is_available = lambda: False  # type: ignore[attr-defined]
    _torch_mod.cuda = _cuda_mod  # type: ignore[attr-defined]

    # torch.backends / torch.backends.mps
    _backends_mod = types.ModuleType("torch.backends")
    _mps_mod = types.ModuleType("torch.backends.mps")
    _mps_mod.is_available = lambda: False  # type: ignore[attr-defined]
    _backends_mod.mps = _mps_mod  # type: ignore[attr-defined]
    _torch_mod.backends = _backends_mod  # type: ignore[attr-defined]

    # torch.set_num_threads / torch.set_num_interop_threads
    _torch_mod.set_num_threads = lambda n: None  # type: ignore[attr-defined]
    _torch_mod.set_num_interop_threads = lambda n: None  # type: ignore[attr-defined]

    # torch.inference_mode (used as context manager)
    class _FakeInferenceMode:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
    _torch_mod.inference_mode = _FakeInferenceMode  # type: ignore[attr-defined]

    # torch.nn.functional (needed by trainer but not in pure unit tests)
    _nn_mod = types.ModuleType("torch.nn")
    _nn_func = types.ModuleType("torch.nn.functional")
    _nn_mod.functional = _nn_func  # type: ignore[attr-defined]
    _torch_mod.nn = _nn_mod  # type: ignore[attr-defined]

    # torch.Tensor type annotation stub (used in method signatures)
    class _FakeTensor:
        pass
    _torch_mod.Tensor = _FakeTensor  # type: ignore[attr-defined]

    # torch.tensor / torch.softmax stubs (only needed by interpret tests)
    # We skip those tests if torch is not available, but having the name
    # avoids import-time AttributeError in other places.
    _torch_mod.tensor = lambda *a, **kw: None  # type: ignore[attr-defined]
    _torch_mod.softmax = lambda *a, **kw: None  # type: ignore[attr-defined]
    _torch_mod.float32 = "float32"  # type: ignore[attr-defined]

    # torch.utils / torch.utils.data
    _utils_mod = types.ModuleType("torch.utils")
    _data_mod = types.ModuleType("torch.utils.data")

    class _FakeDataset:
        pass

    _data_mod.Dataset = _FakeDataset  # type: ignore[attr-defined]
    _utils_mod.data = _data_mod  # type: ignore[attr-defined]
    _torch_mod.utils = _utils_mod  # type: ignore[attr-defined]

    sys.modules["torch"] = _torch_mod
    sys.modules["torch.cuda"] = _cuda_mod
    sys.modules["torch.backends"] = _backends_mod
    sys.modules["torch.backends.mps"] = _mps_mod
    sys.modules["torch.nn"] = _nn_mod
    sys.modules["torch.nn.functional"] = _nn_func
    sys.modules["torch.utils"] = _utils_mod
    sys.modules["torch.utils.data"] = _data_mod


# Expose for tests that want to conditionally skip.
torch_available = _real_torch


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_email(
    *,
    session_id: str = "",
    subject: str | None = "Test subject",
    body_text: str | None = "Hello, this is a test email.",
    body_html: str | None = None,
    mail_from: str | None = "sender@example.com",
    rcpt_to: list[str] | None = None,
) -> dict[str, Any]:
    """Build a dict matching ``ContentAnalysisRequest`` fields."""
    return {
        "session_id": session_id or str(uuid.uuid4()),
        "subject": subject,
        "body_text": body_text,
        "body_html": body_html,
        "mail_from": mail_from,
        "rcpt_to": rcpt_to or ["recipient@example.com"],
    }


def make_session(
    *,
    id: str = "",
    protocol: str = "SMTP",
    client_ip: str = "192.168.1.100",
    client_port: int = 54321,
    server_ip: str = "10.0.0.1",
    server_port: int = 25,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    status: str = "completed",
    packet_count: int = 10,
    total_bytes: int = 2048,
    mail_from: str | None = "sender@example.com",
    rcpt_to: list[str] | None = None,
    subject: str | None = "Test Subject",
) -> dict[str, Any]:
    """Build a dict suitable for constructing ``EmailSession``."""
    return {
        "id": id or str(uuid.uuid4()),
        "protocol": protocol,
        "client_ip": client_ip,
        "client_port": client_port,
        "server_ip": server_ip,
        "server_port": server_port,
        "started_at": (started_at or datetime.now(timezone.utc)).isoformat(),
        "ended_at": ended_at.isoformat() if ended_at else None,
        "status": status,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "mail_from": mail_from,
        "rcpt_to": rcpt_to or ["user@example.com"],
        "subject": subject,
    }


def make_packet(
    *,
    id: str = "",
    session_id: str = "",
    protocol: str = "SMTP",
    src_ip: str = "192.168.1.100",
    src_port: int = 54321,
    dst_ip: str = "10.0.0.1",
    dst_port: int = 25,
    direction: str = "inbound",
    size: int = 256,
    timestamp: datetime | None = None,
    command: str | None = None,
    raw_data: str | None = None,
) -> dict[str, Any]:
    """Build a dict suitable for constructing ``EmailPacket``."""
    return {
        "id": id or str(uuid.uuid4()),
        "session_id": session_id or str(uuid.uuid4()),
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "direction": direction,
        "size": size,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "command": command,
        "raw_data": raw_data,
    }


def make_vt_api_response(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 60,
    undetected: int = 10,
    nested: bool = True,
) -> dict[str, Any]:
    """Build a mock VT internal-API JSON response.

    If *nested* is True, use ``data.data.attributes``; otherwise ``data.attributes``.
    """
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }
    attrs = {
        "last_analysis_stats": stats,
        "last_analysis_results": {
            f"engine_{i}": {"category": "undetected", "result": None}
            for i in range(harmless + undetected)
        },
    }
    # Add malicious engines
    for i in range(malicious):
        attrs["last_analysis_results"][f"mal_engine_{i}"] = {
            "category": "malicious",
            "result": "malware",
        }
    for i in range(suspicious):
        attrs["last_analysis_results"][f"sus_engine_{i}"] = {
            "category": "suspicious",
            "result": "suspicious",
        }

    if nested:
        return {"url": "https://vt-api/test", "data": {"data": {"attributes": attrs}}}
    else:
        return {"url": "https://vt-api/test", "data": {"attributes": attrs}}


def make_training_sample(
    *,
    session_id: str = "",
    label: int = 0,
    subject: str | None = "Training sample subject",
    body_text: str | None = "This is a training sample body text.",
    body_html: str | None = None,
    mail_from: str | None = "trainer@example.com",
    rcpt_to: list[str] | None = None,
) -> dict[str, Any]:
    """Build a dict matching ``TrainingSampleInput`` fields."""
    return {
        "session_id": session_id or str(uuid.uuid4()),
        "label": label,
        "subject": subject,
        "body_text": body_text,
        "body_html": body_html,
        "mail_from": mail_from,
        "rcpt_to": rcpt_to or [],
    }
