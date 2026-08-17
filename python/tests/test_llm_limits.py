"""PoC tests for LLM timeout and concurrency limits (C2).

Before the fix, the LLM hard timeout (20s) exceeded the Rust engine's NLP
timeout (8s), so a stalled LLM call made the engine drop the whole AI
response (fail-open), and LLM calls ran without any concurrency bound.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

import vigilyx_ai.api as api_module
from vigilyx_ai.llm.client import LLMConfig, LLMResponse
from vigilyx_ai.nlp_phishing import NLPPhishingResult
from vigilyx_ai.scraper import validate_vt_indicator


@pytest.fixture(autouse=True)
def _enable_mock_llm_egress(monkeypatch):
    """Mocked provider tests opt in; production defaults to no egress."""
    monkeypatch.setenv("LLM_EXTERNAL_EGRESS_ENABLED", "true")
    api_module._llm_rate_log.clear()
    api_module._llm_global_rate_log.clear()
    yield
    api_module._llm_rate_log.clear()
    api_module._llm_global_rate_log.clear()


class TestLlmTimeoutConfig:
    """LLM client default timeout must be 5s and env-configurable."""

    def test_default_timeout_is_5s(self, monkeypatch):
        monkeypatch.delenv("LLM_TIMEOUT_SECS", raising=False)
        assert LLMConfig().timeout == 5.0

    def test_timeout_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_TIMEOUT_SECS", "3")
        assert LLMConfig().timeout == 3.0

    def test_timeout_invalid_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("LLM_TIMEOUT_SECS", "not-a-number")
        assert LLMConfig().timeout == 5.0

    def test_hard_timeout_below_engine_nlp_timeout(self):
        # The Rust engine drops the whole AI response after its 8s NLP
        # timeout; the LLM cap must always fire before that.
        assert api_module.LLM_HARD_TIMEOUT_SECS <= 8.0


class _TrackingClient:
    """LLMClient stand-in that records peak concurrent chat calls."""

    inflight = 0
    max_inflight = 0

    def __init__(self, config):
        self.config = config

    async def chat(self, prompt, system=None):
        type(self).inflight += 1
        type(self).max_inflight = max(type(self).max_inflight, type(self).inflight)
        try:
            await asyncio.sleep(0.05)
            return LLMResponse(
                content='{"threat_level": "high", "confidence": 0.8, "summary": "x"}',
                model="claude-test-model",
            )
        finally:
            type(self).inflight -= 1

    async def close(self):
        pass


class TestLlmConcurrencyLimit:
    """Concurrent uncertain emails must be serialized through the semaphore."""

    def _uncertain_result(self) -> NLPPhishingResult:
        return NLPPhishingResult(
            is_phishing=False,
            threat_level="medium",
            confidence=0.5,
            summary="uncertain",
            details={"malicious_probability": 0.5},
            model_name="test",
        )

    def test_concurrent_calls_bounded(self):
        async def run():
            api_module._llm_rate_log.clear()
            cfg = api_module.LlmRequestConfig(provider="claude", api_key="sk-test")
            requests = [
                api_module.ContentAnalysisRequest(
                    session_id=f"s{i}",
                    mail_from=f"sender{i}@example.com",  # distinct: no rate limit
                    subject="Verify your account",
                    body_text="Please confirm your password.",
                    llm=cfg,
                )
                for i in range(5)
            ]
            results = await asyncio.gather(
                *(api_module._llm_second_opinion(req, self._uncertain_result()) for req in requests)
            )
            return results

        with patch.object(api_module, "LLMClient", _TrackingClient):
            _TrackingClient.inflight = 0
            _TrackingClient.max_inflight = 0
            results = asyncio.run(run())

        assert all(r is not None and r["verdict"] == "high" for r in results)
        assert 1 <= _TrackingClient.max_inflight <= api_module._LLM_MAX_CONCURRENCY
        assert api_module._LLM_MAX_CONCURRENCY == 2

    def test_semaphore_limit_param_respected(self, monkeypatch):
        # A higher configured limit must widen the semaphore.
        monkeypatch.setattr(api_module, "_LLM_MAX_CONCURRENCY", 4)

        async def run():
            api_module._llm_rate_log.clear()
            cfg = api_module.LlmRequestConfig(provider="claude", api_key="sk-test")
            requests = [
                api_module.ContentAnalysisRequest(
                    session_id=f"s{i}",
                    mail_from=f"bulk{i}@example.com",
                    subject="s",
                    body_text="b",
                    llm=cfg,
                )
                for i in range(6)
            ]
            await asyncio.gather(
                *(api_module._llm_second_opinion(req, self._uncertain_result()) for req in requests)
            )

        with patch.object(api_module, "LLMClient", _TrackingClient):
            _TrackingClient.inflight = 0
            _TrackingClient.max_inflight = 0
            asyncio.run(run())

        assert _TrackingClient.max_inflight > 2
        assert _TrackingClient.max_inflight <= 4


class TestLlmGlobalRateLimit:
    """PoC (R4 发现B): the per-sender limit alone is bypassed by rotating
    sender addresses; the global per-minute cap bounds total LLM spend."""

    def test_global_cap_blocks_sender_rotation(self, monkeypatch):
        # 修复前: 每个伪造 sender 都有独立 2/min 额度，轮换发件人 = 无限 LLM 调用。
        monkeypatch.setattr(api_module, "LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", 3)

        allowed = [
            api_module._llm_rate_allow(f"attacker{i}@evil.test") for i in range(6)
        ]

        assert allowed == [True, True, True, False, False, False]

    def test_default_global_limit_is_20(self, monkeypatch):
        monkeypatch.delenv("LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", raising=False)
        assert api_module._llm_global_rate_limit_per_minute() == 20

    def test_global_limit_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", "7")
        assert api_module._llm_global_rate_limit_per_minute() == 7
        monkeypatch.setenv("LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", "junk")
        assert api_module._llm_global_rate_limit_per_minute() == 20

    def test_stale_sender_keys_are_swept(self, monkeypatch):
        # 修复前: 每个轮换的 sender 在 _llm_rate_log 里留下永久键（内存缓增）。
        monkeypatch.setattr(api_module, "_LLM_RATE_LOG_MAX_KEYS", 5)
        old = time.monotonic() - api_module._LLM_RATE_WINDOW_SECS - 1.0
        for i in range(10):
            api_module._llm_rate_log[f"stale{i}@evil.test"] = [old]

        assert api_module._llm_rate_allow("fresh@example.com") is True

        keys = list(api_module._llm_rate_log)
        assert keys == ["fresh@example.com"]

    def test_empty_key_dropped_on_revisit(self):
        key = "gone@example.com"
        old = time.monotonic() - api_module._LLM_RATE_WINDOW_SECS - 1.0
        api_module._llm_rate_log[key] = [old]

        assert api_module._llm_rate_allow(key) is True
        # The stale entry was pruned and only the fresh call remains.
        assert len(api_module._llm_rate_log[key]) == 1
        assert api_module._llm_rate_log[key][0] > old


class TestLlmRateLogHardCap:
    """PoC (A8): sender rotation with FRESH keys made the stale-key sweep a
    no-op, so `_llm_rate_log` grew without bound (memory DoS). Now the map
    is hard-capped: once full, brand-new sender keys are refused (the LLM
    re-check is skipped, fail-open to the local NLP verdict)."""

    def test_fresh_key_rotation_capped(self, monkeypatch):
        # 修复前: 8 个轮换发件人 = 8 个常驻 key，持续轮换 = 无界增长。
        # 修复后: 第 6 个新 key 起直接拒绝，map 大小不超过上限。
        monkeypatch.setattr(api_module, "LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", 1000)
        monkeypatch.setattr(api_module, "_LLM_RATE_LOG_MAX_KEYS", 5)

        allowed = [
            api_module._llm_rate_allow(f"rot{i}@evil.test") for i in range(8)
        ]

        assert allowed == [True] * 5 + [False] * 3
        assert len(api_module._llm_rate_log) <= 5

    def test_known_sender_still_allowed_at_cap(self, monkeypatch):
        # A sender already in the map keeps its (per-sender limited)
        # allowance even when the map is full of rotated keys — the cap
        # only refuses NEW keys.
        monkeypatch.setattr(api_module, "LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", 1000)
        monkeypatch.setattr(api_module, "_LLM_RATE_LOG_MAX_KEYS", 3)

        assert api_module._llm_rate_allow("known@example.com") is True
        assert api_module._llm_rate_allow("filler1@evil.test") is True
        assert api_module._llm_rate_allow("filler2@evil.test") is True
        # Map is now full of fresh keys.
        assert api_module._llm_rate_allow("new@evil.test") is False
        # Known sender's second call is within the per-sender limit.
        assert api_module._llm_rate_allow("known@example.com") is True

    def test_stale_sweep_frees_slots_for_new_keys(self, monkeypatch):
        # Refusal is the last resort: expired keys are reclaimed first, so
        # a full-but-stale map still accepts new senders.
        monkeypatch.setattr(api_module, "LLM_GLOBAL_RATE_LIMIT_PER_MINUTE", 1000)
        monkeypatch.setattr(api_module, "_LLM_RATE_LOG_MAX_KEYS", 3)
        old = time.monotonic() - api_module._LLM_RATE_WINDOW_SECS - 1.0
        for i in range(3):
            api_module._llm_rate_log[f"stale{i}@evil.test"] = [old]

        assert api_module._llm_rate_allow("fresh@example.com") is True
        assert "fresh@example.com" in api_module._llm_rate_log


class TestThirdPartyIndicatorPrivacy:
    """Internal indicators must never reach VirusTotal scraping."""

    @pytest.mark.parametrize(
        ("indicator", "indicator_type"),
        [
            ("10.0.0.5", "ip"),
            ("mail.corp", "domain"),
            ("http://127.0.0.1/admin", "url"),
            ("https://portal.bank.internal/login", "url"),
        ],
    )
    def test_non_public_indicator_is_rejected(self, indicator, indicator_type):
        with pytest.raises(ValueError, match="non-public|non-public host"):
            validate_vt_indicator(indicator, indicator_type)

    def test_configured_internal_domain_is_rejected(self, monkeypatch):
        monkeypatch.setenv("VIGILYX_INTERNAL_DOMAINS", "bank.example")
        with pytest.raises(ValueError, match="non-public"):
            validate_vt_indicator("mx.bank.example", "domain")


class TestSemaphoreQueueCountsAgainstTimeout:
    """PoC (R4 发现B): before the fix, asyncio.wait_for wrapped only the chat
    call, so time spent QUEUING behind the semaphore was outside the
    hard-timeout budget — a saturated semaphore let the LLM stage overrun the
    engine's 8s NLP budget. Now queueing counts against the budget."""

    def test_queued_call_times_out_instead_of_overrunning(self, monkeypatch):
        monkeypatch.setattr(api_module, "LLM_HARD_TIMEOUT_SECS", 0.3)
        monkeypatch.setattr(api_module, "_LLM_MAX_CONCURRENCY", 1)
        api_module._llm_semaphores.clear()

        class _SlowClient:
            """Each chat call takes 0.2s; with concurrency=1 the second call
            queues 0.2s + runs 0.2s = 0.4s > 0.3s budget."""

            def __init__(self, config):
                pass

            async def chat(self, prompt, system=None):
                await asyncio.sleep(0.2)
                return LLMResponse(
                    content='{"threat_level": "high", "confidence": 0.8, "summary": "x"}',
                    model="claude-test-model",
                )

            async def close(self):
                pass

        def _uncertain() -> NLPPhishingResult:
            return NLPPhishingResult(
                is_phishing=False,
                threat_level="medium",
                confidence=0.5,
                summary="uncertain",
                details={"malicious_probability": 0.5},
                model_name="test",
            )

        async def run():
            cfg = api_module.LlmRequestConfig(provider="claude", api_key="sk-test")
            requests = [
                api_module.ContentAnalysisRequest(
                    session_id=f"s{i}",
                    mail_from=f"q{i}@example.com",
                    subject="s",
                    body_text="b",
                    llm=cfg,
                )
                for i in range(2)
            ]
            return await asyncio.gather(
                *(api_module._llm_second_opinion(req, _uncertain()) for req in requests)
            )

        try:
            with patch.object(api_module, "LLMClient", _SlowClient):
                results = asyncio.run(run())
        finally:
            api_module._llm_semaphores.clear()

        # Exactly one call fits the budget; the queued one must time out
        # (fail-open to local NLP) instead of completing after 0.4s.
        outcomes = sorted(r is None for r in results)
        assert outcomes == [False, True]
