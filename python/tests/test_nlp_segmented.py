"""PoC tests for segmented long-email NLP inference (A1).

Before the fix, ``preprocess_email`` stitched head+middle+tail samples into a
single <=3000-char model input. The blind bands were a deterministic function
of body length (a ~12000-char body had a gap covering offsets 3000-4500 and
7500-9000), and the model's 512-token truncation meant the stitched tail
never reached the model anyway. A pure social-engineering BEC payload placed
at offset 4000 was invisible to the NLP stage. After the fix the cleaned
text is split into consecutive windows, each window is inferred
independently, and the max malicious (min legitimate) probability wins.
"""

from __future__ import annotations

import asyncio

import pytest

import vigilyx_ai.nlp_phishing as nlp_module
from vigilyx_ai.nlp_phishing import (
    ModelUnavailableError,
    NLPPhishingResult,
    _split_into_segments,
    _tokenizer_input_coverage,
    analyze_phishing_nlp,
)

# Real-world style BEC social-engineering payload (pure text, no IoC).
PAYLOAD = (
    "张总临时有事，请立即将合同款50万元转至新账户6228480012345678901，"
    "财务章后补，务必今天下班前完成，不要声张。"
)

BENIGN_FILLER = "这是一条正常的业务往来邮件内容，请查收附件中的对账单。"


def _filler(chars: int) -> str:
    """Deterministic benign filler of exactly `chars` characters."""
    reps = (chars // len(BENIGN_FILLER)) + 1
    return (BENIGN_FILLER * reps)[:chars]


class _PayloadAwareManager:
    """ModelManager stand-in: 'malicious' iff the BEC payload is visible in
    the model input. Records every input it was shown."""

    def __init__(self):
        self.seen_inputs: list[str] = []

    async def predict(self, text: str, lang: str) -> NLPPhishingResult:
        self.seen_inputs.append(text)
        if PAYLOAD in text:
            return NLPPhishingResult(
                is_phishing=True,
                threat_level="high",
                confidence=0.9,
                categories=["nlp_bec"],
                summary="BEC intent detected",
                details={"malicious_probability": 0.92},
                model_name="fake",
                inference_ms=5,
            )
        return NLPPhishingResult(
            is_phishing=False,
            threat_level="safe",
            confidence=0.95,
            summary="benign",
            details={"malicious_probability": 0.02},
            model_name="fake",
            inference_ms=5,
        )


class _FailingManager:
    """Every inference fails (model in cooldown)."""

    async def predict(self, text: str, lang: str) -> NLPPhishingResult:
        raise ModelUnavailableError("cooldown", retry_after_secs=30)


class _FirstSegmentFlakyManager(_PayloadAwareManager):
    """The first window's inference times out; the rest succeed."""

    async def predict(self, text: str, lang: str) -> NLPPhishingResult:
        if not self.seen_inputs:
            self.seen_inputs.append(text)
            raise asyncio.TimeoutError()
        return await super().predict(text, lang)


class _TokenizerTruncatingManager(_PayloadAwareManager):
    async def predict(self, text: str, lang: str) -> NLPPhishingResult:
        result = await super().predict(text, lang)
        result.details["model_input_truncated"] = True
        return result


class _FakeTokenizer:
    def encode(self, text: str, add_special_tokens: bool = False) -> list[int]:
        del add_special_tokens
        return list(range(len(text)))

    def num_special_tokens_to_add(self, pair: bool = False) -> int:
        return 3 if pair else 2


def _install_manager(monkeypatch, manager) -> None:
    monkeypatch.setattr(nlp_module, "get_model_manager", lambda: manager)


class TestSplitIntoSegments:
    def test_full_coverage_no_gaps(self):
        text = "x" * 10000
        segments = _split_into_segments(text, 3000, 8)
        assert "".join(segments) == text
        assert [len(s) for s in segments] == [3000, 3000, 3000, 1000]

    def test_segment_count_capped(self):
        segments = _split_into_segments("y" * 50000, 3000, 8)
        assert len(segments) == 8

    def test_empty_text(self):
        assert _split_into_segments("", 3000, 8) == []

    def test_tokenizer_coverage_counts_single_and_pair_inputs(self):
        tokenizer = _FakeTokenizer()
        assert _tokenizer_input_coverage(tokenizer, "x" * 510) == (False, 512, 512)
        assert _tokenizer_input_coverage(tokenizer, "x" * 511) == (True, 513, 512)
        assert _tokenizer_input_coverage(tokenizer, "x" * 500, ("y" * 10,)) == (
            True,
            513,
            512,
        )

    def test_unknown_tokenizer_is_conservatively_limited(self):
        assert _tokenizer_input_coverage(None, "text") == (True, None, 512)


class TestSegmentedInference:
    def test_payload_in_old_blind_band_is_detected(self, monkeypatch):
        # 修复前: ~12000 字正文采样 [0,3000)∪[L/2±1500)∪[L-3000,L)，
        # 偏移 4000 的载荷恰好落在盲带内，单次推理只能看到正常内容 → safe。
        # 修复后: 连续分段覆盖偏移 4000，含 BEC 话术的分段判 malicious，
        # 合并取 max → 检出。
        manager = _PayloadAwareManager()
        _install_manager(monkeypatch, manager)

        body = _filler(4000) + PAYLOAD + _filler(8000)
        result = asyncio.run(
            analyze_phishing_nlp(
                subject="对账提醒",
                body_text=body,
                mail_from="finance@example.com",
            )
        )

        # Precondition: the payload really is inside the old blind band.
        assert PAYLOAD not in body[:3000]
        assert len(body) > 9000

        assert any(PAYLOAD in s for s in manager.seen_inputs)
        assert result.is_phishing is True
        assert result.details["malicious_probability"] == 0.92
        assert result.details["segments_analyzed"] >= 4
        assert result.threat_level == "high"

    def test_rt010_payload_beyond_old_prefix_cap_is_detected_and_limited(self, monkeypatch):
        manager = _PayloadAwareManager()
        _install_manager(monkeypatch, manager)

        body = _filler(25_000) + PAYLOAD + _filler(4_000)
        result = asyncio.run(
            analyze_phishing_nlp(
                subject="Q3 digest",
                body_text=body,
                mail_from="reports@ops.example",
            )
        )

        assert any(PAYLOAD in segment for segment in manager.seen_inputs)
        assert result.is_phishing is True
        assert result.details["coverage_limited"] is True
        assert result.details["input_chars_before_nlp_cap"] > 24_000

    def test_every_window_within_segment_budget(self, monkeypatch):
        manager = _PayloadAwareManager()
        _install_manager(monkeypatch, manager)

        body = _filler(12000)
        asyncio.run(analyze_phishing_nlp(subject=None, body_text=body, mail_from=None))

        assert len(manager.seen_inputs) >= 4
        for segment in manager.seen_inputs:
            assert len(segment) <= nlp_module.NLP_SEGMENT_CHARS

    def test_segment_count_capped_for_huge_body(self, monkeypatch):
        # Inference cost must stay bounded regardless of body size.
        manager = _PayloadAwareManager()
        _install_manager(monkeypatch, manager)

        body = _filler(100000)
        asyncio.run(analyze_phishing_nlp(subject=None, body_text=body, mail_from=None))

        assert len(manager.seen_inputs) == nlp_module.NLP_MAX_SEGMENTS

    def test_max_malicious_min_legitimate_wins(self, monkeypatch):
        # The merged verdict keeps the MOST malicious window's result, i.e.
        # max malicious probability / min legitimate probability.
        manager = _PayloadAwareManager()
        _install_manager(monkeypatch, manager)

        body = _filler(3000) + PAYLOAD + _filler(3000)
        result = asyncio.run(analyze_phishing_nlp(subject="s", body_text=body, mail_from=None))

        probs = result.details["segment_malicious_probabilities"]
        assert max(probs) == 0.92
        assert min(probs) == 0.02
        assert result.details["malicious_probability"] == max(probs)

    def test_short_email_single_inference(self, monkeypatch):
        manager = _PayloadAwareManager()
        _install_manager(monkeypatch, manager)

        result = asyncio.run(
            analyze_phishing_nlp(subject="Hi", body_text="short body", mail_from="a@b.com")
        )

        assert len(manager.seen_inputs) == 1
        assert "segments_analyzed" not in result.details

    def test_model_token_truncation_marks_coverage_limited(self, monkeypatch):
        _install_manager(monkeypatch, _TokenizerTruncatingManager())

        result = asyncio.run(
            analyze_phishing_nlp(subject="Hi", body_text="short body", mail_from="a@b.com")
        )

        assert result.details["coverage_limited"] is True
        assert "model_token_limit" in result.details["coverage_reasons"]

    def test_all_windows_fail_raises_for_503_mapping(self, monkeypatch):
        # When every window fails, the first error must surface so api.py
        # keeps its 503 MODEL_UNAVAILABLE mapping instead of fabricating a
        # "safe" result from nothing.
        _install_manager(monkeypatch, _FailingManager())

        with pytest.raises(ModelUnavailableError):
            asyncio.run(analyze_phishing_nlp(subject="s", body_text=_filler(12000), mail_from=None))

    def test_partial_window_failure_still_detects(self, monkeypatch):
        # One timed-out window must not blind the whole email.
        manager = _FirstSegmentFlakyManager()
        _install_manager(monkeypatch, manager)

        body = _filler(4000) + PAYLOAD + _filler(4000)
        result = asyncio.run(analyze_phishing_nlp(subject="s", body_text=body, mail_from=None))

        assert result.is_phishing is True
        assert result.details["segments_succeeded"] == result.details["segments_analyzed"] - 1
        assert result.details["coverage_limited"] is True
        assert "segment_inference_failure" in result.details["coverage_reasons"]
