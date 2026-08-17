"""
NLP phishing-detection module.

Uses HuggingFace Transformer models for multilingual phishing-intent analysis.
The `ModelManager` follows a two-tier strategy:
  1. A fine-tuned classifier trained from analyst feedback, preferred when available
  2. A zero-shot multilingual NLI fallback when no trained model is present

Chinese, English, and other languages are supported through multilingual base models.
"""

import asyncio
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import structlog
import torch

logger = structlog.get_logger()

# Constants
LATEST_MODEL_DIR = "data/nlp_models/latest"

# SEC-23: immutable Hugging Face revisions for every zero-shot fallback.
# Update model id and commit together after reviewing upstream changes.
ZEROSHOT_MODEL_REVISIONS = {
    "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7": (
        "b5113eb38ab63efdd7f280f8c144ea8b13f978ce"
    ),
    "joeddav/xlm-roberta-large-xnli": (
        "b227ee8435ceadfa86dc1368a34254e2838bf242"
    ),
    "facebook/bart-large-mnli": "d7645e127eaf1aefc7862fd59a17a5aa8558b8ce",
}

# SEC-22: cap concurrent inference calls to protect CPU/memory under load.
_MAX_INFERENCE_CONCURRENCY = max(1, int(os.environ.get("AI_MAX_CONCURRENCY", "4")))
_INFERENCE_TIMEOUT_SECS = max(
    1.0,
    float(os.environ.get("AI_INFERENCE_TIMEOUT_SECS", "30")),
)

# Segmented inference for long emails: the cleaned text is split into
# consecutive windows of NLP_SEGMENT_CHARS characters and each window is
# inferred independently; the verdict keeps the highest malicious (lowest
# legitimate) probability across windows. The segment cap bounds per-email
# inference cost.
NLP_SEGMENT_CHARS = max(500, int(os.environ.get("AI_NLP_SEGMENT_CHARS", "3000")))
NLP_MAX_SEGMENTS = max(1, int(os.environ.get("AI_NLP_MAX_SEGMENTS", "8")))

# CPU inference tuning
# Recommended thread count is roughly 60-80% of physical cores to leave headroom.
_cpu_count = os.cpu_count() or 4
_default_threads = max(4, int(_cpu_count * 0.7))
_NUM_THREADS = int(os.environ.get("VIGILYX_NUM_THREADS", str(_default_threads)))
_NUM_INTEROP = max(2, _NUM_THREADS // 2)
torch.set_num_threads(_NUM_THREADS)
torch.set_num_interop_threads(_NUM_INTEROP)

# Auto-detect the best available device.
def _detect_device() -> tuple[int, str]:
    """Return `(pipeline_device, torch_device_str)`."""
    if torch.cuda.is_available():
        logger.info("CUDA GPU detected, using GPU for inference")
        return 0, "cuda:0"
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        logger.info("Apple MPS detected, using MPS for inference")
        return -1, "mps"  # pipeline doesn't support mps device int
    logger.info(
        "No GPU detected, using CPU for inference",
        num_threads=_NUM_THREADS,
        num_interop_threads=_NUM_INTEROP,
        cpu_count=_cpu_count,
    )
    return -1, "cpu"

_PIPELINE_DEVICE, _TORCH_DEVICE = _detect_device()


class PhishingCategory(str, Enum):
    """Phishing-analysis category."""
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    SCAM = "scam"
    SPAM = "spam"
    BEC = "bec"


@dataclass
class NLPPhishingResult:
    """NLP phishing-analysis result."""
    is_phishing: bool
    threat_level: str           # safe / low / medium / high / critical
    confidence: float           # 0.0 - 1.0
    categories: list[str] = field(default_factory=list)
    summary: str = ""
    details: dict = field(default_factory=dict)
    model_name: str = ""
    inference_ms: int = 0


class ModelUnavailableError(RuntimeError):
    """Raised when no usable NLP model is currently available."""

    def __init__(
        self,
        message: str,
        *,
        retry_after_secs: int = 0,
        status: Optional[dict[str, object]] = None,
    ):
        super().__init__(message)
        self.retry_after_secs = retry_after_secs
        self.status = status or {}


# Zero-shot candidate labels
CANDIDATE_LABELS_EN = [
    "phishing email trying to steal credentials or personal information",
    "scam email with fraudulent offer or social engineering",
    "business email compromise requesting urgent money transfer",
    "spam or unsolicited marketing email",
    "legitimate business or personal email",
]

CANDIDATE_LABELS_ZH = [
    "钓鱼邮件，试图窃取密码或个人信息",
    "诈骗邮件，包含虚假优惠或社交工程攻击",
    "商务邮件欺诈，要求紧急汇款或转账",
    "垃圾邮件或未经请求的营销广告",
    "正常的工作邮件或个人通信",
]

LABEL_THREAT_MAP = {
    0: ("phishing", "high"),
    1: ("scam", "high"),
    2: ("bec", "critical"),
    3: ("spam", "low"),
    4: ("legitimate", "safe"),
}

# Fine-tuned five-class labels aligned with Rust `LABEL_NAMES`.
FINETUNED_LABEL_NAMES = [
    "legitimate",           # 0
    "phishing",             # 1
    "spoofing",             # 2
    "social_engineering",   # 3
    "other_threat",         # 4
]

FINETUNED_LABEL_DISPLAY = {
    "legitimate": "legitimate email",
    "phishing": "phishing email",
    "spoofing": "spoofed email",
    "social_engineering": "social engineering",
    "other_threat": "other threat",
}

FINETUNED_LABEL_THREAT = {
    "legitimate": "safe",
    "phishing": "high",
    "spoofing": "critical",
    "social_engineering": "high",
    "other_threat": "medium",
}

FINETUNED_LABEL_CATEGORY = {
    "legitimate": None,
    "phishing": "nlp_phishing",
    "spoofing": "nlp_spoofing",
    "social_engineering": "nlp_social_engineering",
    "other_threat": "nlp_other_threat",
}


def _detect_language(text: str) -> str:
    """Simple language heuristic for Chinese vs. English."""
    cjk_count = sum(1 for ch in text if '\u4e00' <= ch <= '\u9fff'
                    or '\u3400' <= ch <= '\u4dbf')
    total = sum(1 for ch in text if not ch.isspace())
    if total == 0:
        return "unknown"
    cjk_ratio = cjk_count / total
    if cjk_ratio > 0.3:
        return "zh"
    return "en"


def _clean_html(text: str) -> str:
    """Clean HTML by stripping blocks, comments, tags, and HTML entities."""
    from html import unescape
    # Remove script/style blocks together with their contents.
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML comments.
    text = re.sub(r'<!--.*?-->', ' ', text, flags=re.DOTALL)
    # Remove all remaining tags.
    text = re.sub(r'<[^>]+>', ' ', text)
    # Decode HTML entities.
    text = unescape(text)
    # Collapse whitespace.
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def preprocess_email(
    subject: Optional[str],
    body: Optional[str],
    mail_from: Optional[str],
    max_chars: int = 3000,
    max_segments: int = 1,
) -> str:
    """
    Preprocess email content for NLP analysis.

    Combines sender, subject, and body with a character-level cap of
    `max_chars * max_segments`. `max_chars` is intentionally character-based
    to limit memory use on long emails, while tokenizer-level truncation
    still enforces the exact 512-token model window per segment.

    Above the aggregate inference budget, raw-body windows are distributed
    across the full input before HTML cleaning. The result remains partial and
    the caller records ``coverage_limited``; distribution prevents the entire
    suffix from becoming one predictable blind region. Within the bound,
    `analyze_phishing_nlp` runs independent per-window inference and keeps the
    most malicious successful result. Sender/subject headers remain intact.
    """
    header_parts = []
    if mail_from:
        header_parts.append(f"From: {mail_from}")
    if subject:
        header_parts.append(f"Subject: {subject}")

    segment_count = max(1, max_segments)
    cap = max_chars * segment_count
    header_text = "\n".join(header_parts)
    body_budget = max(0, cap - len(header_text) - (1 if header_text and body else 0))
    body_text = ""
    if body and body_budget > 0:
        if (
            len(body) > body_budget
            and segment_count > 1
            and body_budget > len("\n[... omitted ...]\n") + 2
        ):
            marker = "\n[... omitted ...]\n"
            window_count = min(
                segment_count,
                max(2, body_budget // (len(marker) + 1)),
            )
            separator_budget = len(marker) * (window_count - 1)
            sampled_budget = body_budget - separator_budget
            base, remainder = divmod(sampled_budget, window_count)
            windows = []
            for index in range(window_count):
                window_len = base + (1 if index < remainder else 0)
                if index == window_count - 1:
                    start = len(body) - window_len
                else:
                    start = round(index * (len(body) - window_len) / (window_count - 1))
                windows.append(_clean_html(body[start : start + window_len]))
            body_text = marker.join(windows)
        else:
            # The default single-window trainer path intentionally retains its
            # prefix behavior; security analysis always passes max_segments=8.
            body_text = _clean_html(body[:body_budget])

    parts = header_parts + ([body_text] if body_text else [])
    text = "\n".join(parts)

    if len(text) > cap:
        text = text[:cap]
    return text


def _split_into_segments(text: str, segment_chars: int, max_segments: int) -> list[str]:
    """Split cleaned text into consecutive non-overlapping windows.

    Consecutive windows have no blind bands by construction; `max_segments`
    bounds the per-email inference cost. `preprocess_email` already caps the
    text at `segment_chars * max_segments`, so the slice here is a safety
    net rather than the primary bound.
    """
    if not text:
        return []
    segments = [
        text[i : i + segment_chars]
        for i in range(0, len(text), segment_chars)
    ]
    return segments[: max(1, max_segments)]


def _malicious_probability(result: NLPPhishingResult) -> float:
    """Best-effort malicious probability across model types.

    Zero-shot and five-class fine-tuned results carry
    `malicious_probability`; the legacy two-class model carries
    `phishing_probability`. Fall back to deriving it from the verdict
    confidence so segment comparison never crashes on an unknown shape.
    """
    details = result.details or {}
    for key in ("malicious_probability", "phishing_probability"):
        value = details.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return result.confidence if result.is_phishing else 1.0 - result.confidence


def _tokenizer_input_coverage(
    tokenizer,
    text: str,
    hypotheses: tuple[str, ...] = (),
    max_tokens: int = 512,
) -> tuple[bool, int | None, int]:
    """Report whether model tokenization will truncate an inference input.

    Character windows are only a transport bound; multilingual tokenizers can
    turn one character into one or more tokens. Count the actual tokens before
    invoking an inference path that truncates to 512. Zero-shot classification
    uses premise/hypothesis pairs, so reserve the longest rendered label too.

    If coverage cannot be measured, return a conservative limited result. The
    model may still run, but inline disposition must not call that inspection
    complete.
    """
    if tokenizer is None:
        return True, None, max_tokens
    try:
        text_tokens = tokenizer.encode(text, add_special_tokens=False)
        hypothesis_tokens = 0
        pair = bool(hypotheses)
        if hypotheses:
            hypothesis_tokens = max(
                len(tokenizer.encode(hypothesis, add_special_tokens=False))
                for hypothesis in hypotheses
            )
        special_tokens = tokenizer.num_special_tokens_to_add(pair=pair)
        token_count = len(text_tokens) + hypothesis_tokens + special_tokens
        return token_count > max_tokens, token_count, max_tokens
    except Exception as exc:
        logger.warning("Unable to measure tokenizer input coverage", error=str(exc))
        return True, None, max_tokens


def _sanitize_last_error(message: Optional[str]) -> Optional[str]:
    """
    Redact filesystem paths and truncate `last_error` for health-endpoint output.

    `/health` and `/health/ready` are unauthenticated, so raw loader errors
    (which may embed absolute paths or HuggingFace internals) must not leak.
    The leading error text is preserved so operators can still tell which
    step failed.
    """
    if not message:
        return None
    # Collapse absolute-path fragments (POSIX and Windows) into a placeholder.
    sanitized = re.sub(r"(?:[A-Za-z]:)?(?:[/\\][^/\\\s'\"]+){2,}", "<path>", message)
    return sanitized[:120]


class ModelManager:
    """
    Manage zero-shot and fine-tuned NLP models with hot-swap support.

    Inference priority:
      1. Fine-tuned classifier when available
      2. Zero-shot fallback otherwise

    On startup, the manager checks whether `data/nlp_models/latest/` contains a
    trained model.
    """

    def __init__(self):
        self._swap_lock = asyncio.Lock()    # Protect model hot swaps.
        self._init_lock = asyncio.Lock()    # Protect first-load initialization.
        # SEC-22: bound concurrent inference (asyncio primitives bind to the
        # running loop lazily on first await, like the locks above).
        self._inference_semaphore = asyncio.Semaphore(_MAX_INFERENCE_CONCURRENCY)
        # Use a dedicated bounded executor. Timed-out native/PyTorch calls cannot
        # be force-killed safely, but they also cannot create unbounded workers.
        self._inference_executor = ThreadPoolExecutor(
            max_workers=_MAX_INFERENCE_CONCURRENCY,
            thread_name_prefix="vigilyx-nlp",
        )
        # Zero-shot model
        self._zeroshot_pipeline = None
        self._zeroshot_model_name: Optional[str] = None
        self._zeroshot_load_time: Optional[float] = None
        # Fine-tuned model
        self._finetuned_model = None
        self._finetuned_tokenizer = None
        self._finetuned_version: str = ""
        # Status
        self._model_version: str = "base"
        self._warmup_state: str = "idle"
        self._last_error: Optional[str] = None
        self._unavailable_until_ts: float = 0.0
        self._consecutive_failures: int = 0

    def _clear_failure_state(self):
        self._last_error = None
        self._unavailable_until_ts = 0.0
        self._consecutive_failures = 0

    def _mark_unavailable(self, message: str) -> int:
        self._last_error = message
        self._consecutive_failures += 1
        shift = min(self._consecutive_failures - 1, 4)
        backoff_secs = min(30 * (2 ** shift), 300)
        self._unavailable_until_ts = time.time() + backoff_secs
        return backoff_secs

    def cooldown_remaining_secs(self) -> int:
        return max(0, int(self._unavailable_until_ts - time.time()))

    def readiness_report(self) -> dict[str, object]:
        retry_after_secs = self.cooldown_remaining_secs()
        if self._finetuned_model is not None:
            ready = True
            mode = "fine_tuned"
            active_model = f"fine-tuned/{self._finetuned_version}"
        elif self._zeroshot_pipeline is not None:
            ready = True
            mode = "zero_shot"
            active_model = self._zeroshot_model_name or "zero-shot"
        elif self._warmup_state == "running":
            ready = False
            mode = "warming_up"
            active_model = None
        elif retry_after_secs > 0:
            ready = False
            mode = "cooldown"
            active_model = None
        elif self._warmup_state == "failed" or self._last_error:
            ready = False
            mode = "failed"
            active_model = None
        else:
            ready = False
            mode = "uninitialized"
            active_model = None

        return {
            "ready": ready,
            "mode": mode,
            "active_model": active_model,
            "model_version": self._model_version,
            "has_finetuned": self._finetuned_model is not None,
            "zero_shot_loaded": self._zeroshot_pipeline is not None,
            "zero_shot_model": self._zeroshot_model_name,
            "warmup_state": self._warmup_state,
            "retry_after_secs": retry_after_secs,
            "last_error": _sanitize_last_error(self._last_error),
        }

    def _load_zeroshot(self):
        """Lazily load the zero-shot model."""
        if self._zeroshot_pipeline is not None:
            return self._zeroshot_pipeline

        retry_after_secs = self.cooldown_remaining_secs()
        if retry_after_secs > 0:
            raise ModelUnavailableError(
                f"Zero-shot NLP model load is in cooldown; retry after about {retry_after_secs}s",
                retry_after_secs=retry_after_secs,
                status=self.readiness_report(),
            )

        logger.info("Loading zero-shot NLP model...")
        start = time.time()

        from transformers import pipeline

        model_priority = list(ZEROSHOT_MODEL_REVISIONS)

        for model_id in model_priority:
            try:
                revision = ZEROSHOT_MODEL_REVISIONS[model_id]
                logger.info("Trying pinned model", model=model_id, revision=revision)
                self._zeroshot_pipeline = pipeline(
                    "zero-shot-classification",
                    model=model_id,
                    revision=revision,
                    device=_PIPELINE_DEVICE,
                )
                self._zeroshot_model_name = model_id
                self._zeroshot_load_time = time.time() - start
                self._clear_failure_state()
                logger.info(
                    "Zero-shot model loaded",
                    model=model_id,
                    load_time_s=f"{self._zeroshot_load_time:.1f}",
                    device=_TORCH_DEVICE,
                )
                return self._zeroshot_pipeline
            except Exception as e:
                logger.warning(f"Failed to load {model_id}: {e}")
                continue

        backoff_secs = self._mark_unavailable("All zero-shot NLP models failed to load")
        raise ModelUnavailableError(
            f"All zero-shot NLP models failed to load; retry after about {backoff_secs}s",
            retry_after_secs=backoff_secs,
            status=self.readiness_report(),
        )

    def warmup(self):
        """Warm up the model so the first real request avoids JIT/setup cost."""
        logger.info("Warming up NLP model with dummy inference...")
        start = time.time()
        self._warmup_state = "running"
        try:
            dummy_text = "This is a test email for model warmup."
            if self._finetuned_model is not None:
                self._predict_finetuned(dummy_text)
            else:
                self._load_zeroshot()
                self._predict_zeroshot(dummy_text, "en")
            warmup_ms = int((time.time() - start) * 1000)
            self._warmup_state = "ready"
            logger.info("Model warmup complete", warmup_ms=warmup_ms)
        except ModelUnavailableError as e:
            self._warmup_state = "failed"
            logger.warning(
                "Model warmup deferred because no NLP model is currently available",
                retry_after_secs=e.retry_after_secs,
                error=str(e),
            )
        except Exception as e:
            self._warmup_state = "failed"
            logger.warning(f"Model warmup failed (non-fatal): {e}")

    def try_load_finetuned(self):
        """Try loading the existing fine-tuned model during startup."""
        if not os.path.isdir(LATEST_MODEL_DIR):
            logger.info("No fine-tuned model found, using zero-shot only")
            return

        try:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            model_dir = os.path.realpath(LATEST_MODEL_DIR)
            logger.info(f"Loading fine-tuned model from {model_dir}")

            self._finetuned_tokenizer = AutoTokenizer.from_pretrained(model_dir)
            self._finetuned_model = AutoModelForSequenceClassification.from_pretrained(model_dir)
            self._finetuned_model.eval()
            # Move weights to the selected inference device.
            if _TORCH_DEVICE != "cpu":
                self._finetuned_model = self._finetuned_model.to(_TORCH_DEVICE)
            self._finetuned_version = os.path.basename(model_dir)
            self._model_version = self._finetuned_version
            self._clear_failure_state()

            logger.info(
                "Fine-tuned model loaded",
                version=self._finetuned_version,
                device=_TORCH_DEVICE,
            )
        except Exception as e:
            logger.warning(f"Failed to load fine-tuned model: {e}, using zero-shot only")
            self._finetuned_model = None
            self._finetuned_tokenizer = None

    async def hot_swap(self, model_dir: str):
        """Hot-swap the fine-tuned model after a successful training run."""
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )

        def _load():
            """Load model artifacts synchronously (disk I/O plus deserialization)."""
            tok = AutoTokenizer.from_pretrained(model_dir)
            mdl = AutoModelForSequenceClassification.from_pretrained(model_dir)
            mdl.eval()
            if _TORCH_DEVICE != "cpu":
                mdl = mdl.to(_TORCH_DEVICE)
            return tok, mdl

        async with self._swap_lock:
            logger.info(f"Hot-swapping fine-tuned model: {model_dir}")
            # Load in a worker thread so the event loop stays responsive.
            loop = asyncio.get_event_loop()
            tokenizer, model = await loop.run_in_executor(None, _load)

            # Swap references only after the new model is fully ready.
            self._finetuned_tokenizer = tokenizer
            self._finetuned_model = model
            self._finetuned_version = os.path.basename(model_dir)
            self._model_version = self._finetuned_version
            self._clear_failure_state()
            self._warmup_state = "ready"

            logger.info(
                "Fine-tuned model hot-swapped",
                version=self._finetuned_version,
                device=_TORCH_DEVICE,
            )

    def _predict_finetuned(self, text: str) -> NLPPhishingResult:
        """
        Run inference with the fine-tuned model.

        Supports both the current five-class model (`num_labels=5`) and the
        legacy two-class variant (`num_labels=2`).
        """
        start = time.time()
        model_input_truncated, model_input_tokens, model_input_token_limit = (
            _tokenizer_input_coverage(self._finetuned_tokenizer, text)
        )

        inputs = self._finetuned_tokenizer(
            text, truncation=True, padding=True, max_length=512, return_tensors="pt",
        )
        if _TORCH_DEVICE != "cpu":
            inputs = {k: v.to(_TORCH_DEVICE) for k, v in inputs.items()}
        with torch.inference_mode():
            outputs = self._finetuned_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[0]

        num_labels = probs.shape[0]
        inference_ms = int((time.time() - start) * 1000)

        if num_labels >= 5:
            prediction = self._interpret_5class(probs, text, inference_ms)
        else:
            prediction = self._interpret_2class(probs, text, inference_ms)
        prediction.details.update(
            {
                "model_input_truncated": model_input_truncated,
                "model_input_tokens": model_input_tokens,
                "model_input_token_limit": model_input_token_limit,
            }
        )
        return prediction

    def _interpret_5class(self, probs: torch.Tensor, text: str, inference_ms: int) -> NLPPhishingResult:
        """Interpret five-class model output."""
        prob_values = {name: probs[i].item() for i, name in enumerate(FINETUNED_LABEL_NAMES)}
        top_idx = probs.argmax().item()
        top_name = FINETUNED_LABEL_NAMES[top_idx]
        top_prob = probs[top_idx].item()

        # Malicious probability = 1 - P(legitimate)
        malicious_prob = 1.0 - prob_values["legitimate"]

        # Threat level follows the highest-probability class.
        threat_level = FINETUNED_LABEL_THREAT[top_name]
        is_phishing = threat_level in ("high", "critical", "medium")

        categories = []
        for name, cat in FINETUNED_LABEL_CATEGORY.items():
            if cat and prob_values.get(name, 0) > 0.15:
                categories.append(cat)

        lang = _detect_language(text)
        top_display = FINETUNED_LABEL_DISPLAY.get(top_name, top_name)
        summary = f"[Fine-tuned 5-class] Classified as {top_display} (confidence {top_prob:.1%})"

        return NLPPhishingResult(
            is_phishing=is_phishing,
            threat_level=threat_level,
            confidence=round(top_prob, 3),
            categories=categories,
            summary=summary,
            details={
                "probabilities": {k: round(v, 4) for k, v in prob_values.items()},
                "malicious_probability": round(malicious_prob, 4),
                "top_label": top_name,
                "top_score": round(top_prob, 4),
                "model_type": "fine-tuned-5class",
                "model_version": self._finetuned_version,
                "language_detected": lang,
                "text_length": len(text),
            },
            model_name=f"fine-tuned/{self._finetuned_version}",
            inference_ms=inference_ms,
        )

    def _interpret_2class(self, probs: torch.Tensor, text: str, inference_ms: int) -> NLPPhishingResult:
        """Interpret legacy two-class output for backward compatibility."""
        legit_prob = probs[0].item()
        phishing_prob = probs[1].item()
        # Torch commonly exposes configured decimal thresholds as nearby
        # float32 values (for example 0.65 -> 0.649999976). Normalize only for
        # policy comparisons so exact threshold values are classified as
        # documented without materially widening the bands.
        policy_prob = round(phishing_prob, 6)

        if policy_prob >= 0.85:
            threat_level = "critical"
        elif policy_prob >= 0.65:
            threat_level = "high"
        elif policy_prob >= 0.40:
            threat_level = "medium"
        elif policy_prob >= 0.20:
            threat_level = "low"
        else:
            threat_level = "safe"

        is_phishing = threat_level in ("high", "critical", "medium")

        categories = []
        if policy_prob > 0.3:
            categories.append("nlp_phishing")

        lang = _detect_language(text)
        if is_phishing:
            summary = f"[Fine-tuned] Phishing intent detected (probability {phishing_prob:.1%})"
        else:
            summary = f"[Fine-tuned] Classified as legitimate (phishing probability {phishing_prob:.1%})"

        return NLPPhishingResult(
            is_phishing=is_phishing,
            threat_level=threat_level,
            confidence=round(phishing_prob if is_phishing else legit_prob, 3),
            categories=categories,
            summary=summary,
            details={
                "phishing_probability": round(phishing_prob, 4),
                "legitimate_probability": round(legit_prob, 4),
                "model_type": "fine-tuned",
                "model_version": self._finetuned_version,
                "language_detected": lang,
                "text_length": len(text),
            },
            model_name=f"fine-tuned/{self._finetuned_version}",
            inference_ms=inference_ms,
        )

    def _predict_zeroshot(self, text: str, lang: str) -> NLPPhishingResult:
        """Run inference through the zero-shot model."""
        start = time.time()

        classifier = self._load_zeroshot()

        if lang == "zh":
            labels = CANDIDATE_LABELS_ZH
        else:
            labels = CANDIDATE_LABELS_EN

        hypothesis_template = "This email is: {}" if lang != "zh" else "这封邮件是: {}"
        hypotheses = tuple(hypothesis_template.format(label) for label in labels)
        model_input_truncated, model_input_tokens, model_input_token_limit = (
            _tokenizer_input_coverage(
                getattr(classifier, "tokenizer", None),
                text,
                hypotheses,
            )
        )

        result = classifier(
            text,
            candidate_labels=labels,
            multi_label=False,
            hypothesis_template=hypothesis_template,
        )

        inference_ms = int((time.time() - start) * 1000)

        top_label_idx = labels.index(result["labels"][0])
        top_score = result["scores"][0]
        category, _ = LABEL_THREAT_MAP.get(top_label_idx, ("unknown", "safe"))

        all_probs = {}
        for label, score in zip(result["labels"], result["scores"]):
            idx = labels.index(label)
            cat, _ = LABEL_THREAT_MAP.get(idx, ("unknown", "safe"))
            all_probs[cat] = round(score, 4)

        malicious_prob = all_probs.get("phishing", 0) + all_probs.get("scam", 0) + all_probs.get("bec", 0)

        if malicious_prob >= 0.85:
            final_threat = "critical"
        elif malicious_prob >= 0.65:
            final_threat = "high"
        elif malicious_prob >= 0.40:
            final_threat = "medium"
        elif malicious_prob >= 0.20:
            final_threat = "low"
        else:
            final_threat = "safe"

        is_phishing = final_threat in ("high", "critical", "medium")

        malicious_categories = []
        if all_probs.get("phishing", 0) > 0.15:
            malicious_categories.append("nlp_phishing")
        if all_probs.get("scam", 0) > 0.15:
            malicious_categories.append("nlp_scam")
        if all_probs.get("bec", 0) > 0.15:
            malicious_categories.append("nlp_bec")
        if all_probs.get("spam", 0) > 0.30:
            malicious_categories.append("nlp_spam")

        if is_phishing:
            summary = (
                f"NLP model detected phishing/scam intent (malicious probability {malicious_prob:.1%}): "
                f"top match [{category}] confidence {top_score:.1%}"
            )
        else:
            summary = f"NLP model classified as legitimate (malicious probability {malicious_prob:.1%})"

        return NLPPhishingResult(
            is_phishing=is_phishing,
            threat_level=final_threat,
            confidence=round(malicious_prob if is_phishing else (1.0 - malicious_prob), 3),
            categories=malicious_categories,
            summary=summary,
            details={
                "probabilities": all_probs,
                "malicious_probability": round(malicious_prob, 4),
                "top_label": category,
                "top_score": round(top_score, 4),
                "language_detected": lang,
                "text_length": len(text),
                "model_type": "zero-shot",
                "model": self._zeroshot_model_name,
                "model_input_truncated": model_input_truncated,
                "model_input_tokens": model_input_tokens,
                "model_input_token_limit": model_input_token_limit,
            },
            model_name=self._zeroshot_model_name or "unknown",
            inference_ms=inference_ms,
        )

    async def predict(self, text: str, lang: str) -> NLPPhishingResult:
        """
        Run inference, preferring fine-tuned models and falling back to zero-shot.

        Inference is read-only, so it does not take the swap lock. The init lock
        only protects first-time lazy loading. PyTorch work runs in a thread pool
        so the event loop stays responsive. Concurrent inference is bounded by
        `_inference_semaphore` to protect CPU/memory under load (SEC-22).
        """
        async with self._inference_semaphore:
            loop = asyncio.get_event_loop()

            if self._finetuned_model is not None:
                try:
                    return await asyncio.wait_for(
                        loop.run_in_executor(
                            self._inference_executor,
                            self._predict_finetuned,
                            text,
                        ),
                        timeout=_INFERENCE_TIMEOUT_SECS,
                    )
                except asyncio.TimeoutError:
                    logger.error(
                        "Fine-tuned model inference timed out",
                        timeout_s=_INFERENCE_TIMEOUT_SECS,
                    )
                    raise
                except Exception as e:
                    logger.warning(f"Fine-tuned model inference failed, falling back: {e}")

            # Lock only around first zero-shot initialization.
            if self._zeroshot_pipeline is None:
                async with self._init_lock:
                    if self._zeroshot_pipeline is None:
                        await loop.run_in_executor(None, self._load_zeroshot)

            return await asyncio.wait_for(
                loop.run_in_executor(
                    self._inference_executor,
                    self._predict_zeroshot,
                    text,
                    lang,
                ),
                timeout=_INFERENCE_TIMEOUT_SECS,
            )

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def has_finetuned(self) -> bool:
        return self._finetuned_model is not None


# Global singleton
_model_manager: Optional[ModelManager] = None


def get_model_manager(warmup: bool = True) -> ModelManager:
    """Return the global `ModelManager`, loading and warming it on first use."""
    global _model_manager
    if _model_manager is None:
        _model_manager = ModelManager()
        _model_manager.try_load_finetuned()
        if warmup:
            _model_manager.warmup()
    return _model_manager


async def analyze_phishing_nlp(
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
    mail_from: Optional[str] = None,
    rcpt_to: Optional[list[str]] = None,
) -> NLPPhishingResult:
    """
    Analyze whether an email looks phishy via the NLP pipeline.

    Keeps the existing external signature and delegates internally to
    `ModelManager`. Long emails are scored per consecutive window within a
    bounded budget (see `_split_into_segments`) and the most malicious window's
    result is kept. If the input exceeds that budget, the returned details
    explicitly mark the NLP view as coverage-limited; whole-message rule
    detectors remain responsible for content outside the NLP budget.
    """
    body = body_text or body_html or ""
    if not body and not subject:
        return NLPPhishingResult(
            is_phishing=False,
            threat_level="safe",
            confidence=0.0,
            summary="No email content available; skipped NLP analysis.",
            model_name="none",
        )

    text = preprocess_email(
        subject,
        body,
        mail_from,
        max_chars=NLP_SEGMENT_CHARS,
        max_segments=NLP_MAX_SEGMENTS,
    )
    lang = _detect_language(text)

    coverage_limit_chars = NLP_SEGMENT_CHARS * NLP_MAX_SEGMENTS
    input_chars_before_nlp_cap = sum(len(value or "") for value in (subject, body, mail_from))
    input_coverage_limited = input_chars_before_nlp_cap > coverage_limit_chars

    def annotate_coverage_limit(
        result: NLPPhishingResult,
        additional_reasons: tuple[str, ...] = (),
    ) -> NLPPhishingResult:
        reasons = list(additional_reasons)
        if input_coverage_limited:
            reasons.append("character_budget")
        reasons = sorted(set(reasons))
        if not reasons:
            return result
        result.details["coverage_limited"] = True
        result.details["coverage_reasons"] = reasons
        result.details["coverage_limit_chars"] = coverage_limit_chars
        result.details["input_chars_before_nlp_cap"] = input_chars_before_nlp_cap
        result.details["coverage_note"] = (
            "NLP model attention was incomplete or uncertain; "
            "whole-message rule detectors remain authoritative for omitted content"
        )
        result.summary += (
            f" [NLP coverage limited ({', '.join(reasons)}); "
            "whole-message rules remain authoritative]"
        )
        return result

    manager = get_model_manager()

    segments = _split_into_segments(text, NLP_SEGMENT_CHARS, NLP_MAX_SEGMENTS)
    if len(segments) <= 1:
        result = await manager.predict(text, lang)
        reasons = (
            ("model_token_limit",)
            if result.details.get("model_input_truncated") is True
            else ()
        )
        return annotate_coverage_limit(result, reasons)

    # Long email: run independent inference on every window. Concatenating
    # windows into one model input would push everything past the first
    # ~512 tokens into the tokenizer's truncation void and recreate
    # deterministic blind bands.
    raw_results = await asyncio.gather(
        *(manager.predict(segment, lang) for segment in segments),
        return_exceptions=True,
    )
    results = [r for r in raw_results if isinstance(r, NLPPhishingResult)]
    if not results:
        # Every window failed (model unavailable or inference timeout);
        # surface the first error so the caller keeps its 503/504 mapping.
        raise raw_results[0]

    best = max(results, key=_malicious_probability)
    best.details["segments_analyzed"] = len(segments)
    best.details["segments_succeeded"] = len(results)
    best.details["best_segment_index"] = results.index(best)
    best.details["segment_malicious_probabilities"] = [
        round(_malicious_probability(r), 4) for r in results
    ]
    best.details["total_inference_ms"] = sum(r.inference_ms for r in results)
    best.summary += (
        f" [long email: {len(segments)} segments scored, max malicious probability kept]"
    )
    coverage_reasons = []
    if len(results) < len(segments):
        coverage_reasons.append("segment_inference_failure")
    if any(result.details.get("model_input_truncated") is True for result in results):
        coverage_reasons.append("model_token_limit")
    return annotate_coverage_limit(best, tuple(coverage_reasons))
