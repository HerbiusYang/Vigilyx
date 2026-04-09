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
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import structlog
import torch

logger = structlog.get_logger()

# Constants
LATEST_MODEL_DIR = "data/nlp_models/latest"

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
) -> str:
    """
    Preprocess email content for NLP analysis.

    Combines sender, subject, and body with a coarse character-level cap.
    `max_chars` is intentionally character-based to limit memory use on long
    emails, while tokenizer-level truncation still enforces the exact 512-token
    model window.
    """
    parts = []

    if mail_from:
        parts.append(f"From: {mail_from}")
    if subject:
        parts.append(f"Subject: {subject}")
    if body:
        # Trim before HTML cleaning to avoid excessive work on very large inputs.
        raw = body[:max_chars * 3] if len(body) > max_chars * 3 else body
        clean = _clean_html(raw)
        if clean:
            parts.append(clean)

    text = "\n".join(parts)

    if len(text) > max_chars:
        text = text[:max_chars]

    return text


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

    def _load_zeroshot(self):
        """Lazily load the zero-shot model."""
        if self._zeroshot_pipeline is not None:
            return self._zeroshot_pipeline

        logger.info("Loading zero-shot NLP model...")
        start = time.time()

        from transformers import pipeline

        model_priority = [
            "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7",
            "joeddav/xlm-roberta-large-xnli",
            "facebook/bart-large-mnli",
        ]

        for model_id in model_priority:
            try:
                logger.info(f"Trying model: {model_id}")
                self._zeroshot_pipeline = pipeline(
                    "zero-shot-classification",
                    model=model_id,
                    device=_PIPELINE_DEVICE,
                )
                self._zeroshot_model_name = model_id
                self._zeroshot_load_time = time.time() - start
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

        raise RuntimeError("All zero-shot NLP models failed to load")

    def warmup(self):
        """Warm up the model so the first real request avoids JIT/setup cost."""
        logger.info("Warming up NLP model with dummy inference...")
        start = time.time()
        try:
            self._load_zeroshot()
            dummy_text = "This is a test email for model warmup."
            self._predict_zeroshot(dummy_text, "en")
            warmup_ms = int((time.time() - start) * 1000)
            logger.info("Model warmup complete", warmup_ms=warmup_ms)
        except Exception as e:
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
            return self._interpret_5class(probs, text, inference_ms)
        else:
            return self._interpret_2class(probs, text, inference_ms)

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

        if phishing_prob >= 0.85:
            threat_level = "critical"
        elif phishing_prob >= 0.65:
            threat_level = "high"
        elif phishing_prob >= 0.40:
            threat_level = "medium"
        elif phishing_prob >= 0.20:
            threat_level = "low"
        else:
            threat_level = "safe"

        is_phishing = threat_level in ("high", "critical", "medium")

        categories = []
        if phishing_prob > 0.3:
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

        result = classifier(
            text,
            candidate_labels=labels,
            multi_label=False,
            hypothesis_template="This email is: {}" if lang != "zh" else "这封邮件是: {}",
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
            },
            model_name=self._zeroshot_model_name or "unknown",
            inference_ms=inference_ms,
        )

    async def predict(self, text: str, lang: str) -> NLPPhishingResult:
        """
        Run inference, preferring fine-tuned models and falling back to zero-shot.

        Inference is read-only, so it does not take the swap lock. The init lock
        only protects first-time lazy loading. PyTorch work runs in a thread pool
        so the event loop stays responsive.
        """
        loop = asyncio.get_event_loop()

        if self._finetuned_model is not None:
            try:
                return await loop.run_in_executor(
                    None, self._predict_finetuned, text,
                )
            except Exception as e:
                logger.warning(f"Fine-tuned model inference failed, falling back: {e}")

        # Lock only around first zero-shot initialization.
        if self._zeroshot_pipeline is None:
            async with self._init_lock:
                if self._zeroshot_pipeline is None:
                    await loop.run_in_executor(None, self._load_zeroshot)

        return await loop.run_in_executor(
            None, self._predict_zeroshot, text, lang,
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
    `ModelManager`.
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

    text = preprocess_email(subject, body, mail_from)
    lang = _detect_language(text)

    manager = get_model_manager()

    try:
        return await manager.predict(text, lang)
    except Exception as e:
        logger.error(f"NLP analysis failed: {e}")
        return NLPPhishingResult(
            is_phishing=False,
            threat_level="safe",
            confidence=0.0,
            summary=f"NLP analysis failed: {e}",
            model_name="error",
        )
