"""
Vigilyx AI service FastAPI entrypoint.

Endpoints:
  POST /api/vt-scrape              - Scrape VirusTotal detection data with Playwright
  POST /analyze/content            - NLP phishing analysis (HuggingFace Transformer)
  POST /training/train             - Trigger five-class fine-tuning from batch samples
  POST /model/approve              - Approve a staged (pending) trained model for hot-swap
  GET  /training/status            - Query training and model status
  GET  /training/progress          - Query live training progress
  GET  /health                     - Liveness check
  GET  /health/ready               - Model-readiness check
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .scraper import get_scraper, validate_vt_indicator
from .nlp_phishing import (
    LATEST_MODEL_DIR,
    ModelUnavailableError,
    NLPPhishingResult,
    analyze_phishing_nlp,
    get_model_manager,
)
from .trainer import get_trainer, get_base_model_info, get_training_progress, MIN_SAMPLES
from .vt_models import VtScrapeRequest, VtScrapeResponse
from .llm.client import (
    LLMClient,
    LLMConfig,
    LLMProvider,
    contains_high_risk_sensitive_data,
    redact_sensitive_text,
)
from .llm.prompts import SYSTEM_PROMPT, format_analyze_prompt

# Structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logging.basicConfig(level=logging.INFO, format="%(message)s")

logger = structlog.get_logger()

DEFAULT_MAX_REQUEST_BYTES = 10 * 1024 * 1024


class RequestBodyTooLarge(Exception):
    """Raised when an incoming ASGI request body exceeds the configured cap."""


def max_request_bytes() -> int:
    raw = os.environ.get("AI_MAX_REQUEST_BYTES")
    if not raw:
        return DEFAULT_MAX_REQUEST_BYTES
    try:
        parsed = int(raw)
    except ValueError:
        logger.warning("Invalid AI_MAX_REQUEST_BYTES; using default", value=raw)
        return DEFAULT_MAX_REQUEST_BYTES
    return max(1024, parsed)


class RequestBodyLimitMiddleware:
    """Enforce a byte-level request cap before Pydantic buffers JSON bodies."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        max_bytes = max_request_bytes()
        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }
        content_length = headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    await request_too_large_response(max_bytes)(scope, receive, send)
                    return
            except ValueError:
                pass

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_bytes:
                    raise RequestBodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await request_too_large_response(max_bytes)(scope, receive, send)


def request_too_large_response(max_bytes: int) -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={"error": "REQUEST_TOO_LARGE", "max_bytes": max_bytes},
    )


async def _background_warmup():
    """Warm up models in the background without blocking the health check."""
    import asyncio
    await asyncio.sleep(0.1)  # Let uvicorn finish startup first.
    loop = asyncio.get_event_loop()
    mgr = get_model_manager(warmup=False)  # Only load fine-tuned weights here.
    # Run warmup in a thread pool because it is synchronous and blocking.
    await loop.run_in_executor(None, mgr.warmup)
    logger.info("Background warmup complete")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle hook for startup preload and shutdown cleanup."""
    import asyncio
    logger.info("Intel service starting")
    # Load only the fine-tuned model on startup; zero-shot stays lazy.
    mgr = get_model_manager(warmup=False)
    logger.info("NLP model manager ready", version=mgr._model_version)
    # Warmup runs in the background so health checks stay responsive.
    warmup_task = asyncio.create_task(_background_warmup())
    yield
    warmup_task.cancel()
    # Close the shared browser instance.
    scraper = get_scraper()
    await scraper.close()
    logger.info("Intel service stopped, browser closed")


app = FastAPI(
    title="Vigilyx AI Service",
    description="NLP phishing detection, VirusTotal scraping, and threat-intel helper APIs.",
    version="0.3.0",
    lifespan=lifespan,
)
app.add_middleware(RequestBodyLimitMiddleware)

# SEC-H07: Internal-service authentication middleware (CWE-306)
# Verifies X-Internal-Token with constant-time comparison to resist timing attacks.
_INTERNAL_TOKEN = os.environ.get("AI_INTERNAL_TOKEN", "")

@app.middleware("http")
async def verify_internal_token(request: Request, call_next):
    # Health and docs endpoints stay unauthenticated.
    if request.url.path in ("/health", "/health/ready", "/docs", "/openapi.json"):
        return await call_next(request)

    if not _INTERNAL_TOKEN:
        logger.warning("AI_INTERNAL_TOKEN is not configured; rejecting all requests")
        return JSONResponse(status_code=403, content={"error": "Internal auth token is not configured"})

    provided = request.headers.get("X-Internal-Token", "")
    if not hmac.compare_digest(provided, _INTERNAL_TOKEN):
        return JSONResponse(status_code=401, content={"error": "Authentication failed"})

    return await call_next(request)


# NLP analysis request/response models aligned with the Rust remote client.

class LlmRequestConfig(BaseModel):
    """Optional LLM second-opinion config forwarded by the Rust engine.

    Mirrors the `llm` field of Rust ContentAnalysisRequest; populated only when
    the operator configured a remote LLM provider + API key in the UI.
    """
    provider: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.3
    max_tokens: int = 4096


class ContentAnalysisRequest(BaseModel):
    """Email-content analysis request aligned with Rust ContentAnalysisRequest."""
    session_id: str = ""
    subject: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    mail_from: Optional[str] = None
    rcpt_to: list[str] = Field(default_factory=list)
    llm: Optional[LlmRequestConfig] = None


class AiAnalysisResponse(BaseModel):
    """AI analysis response aligned with Rust AiAnalysisResponse."""
    threat_level: str           # safe / low / medium / high / critical
    confidence: float           # 0.0 - 1.0
    categories: list[str] = Field(default_factory=list)
    summary: str = ""
    details: Optional[dict] = None


# ---------------------------------------------------------------------------
# LLM second opinion (advisory re-check for uncertain local NLP results)
# ---------------------------------------------------------------------------

# The local NLP verdict counts as "uncertain" only inside this probability band.
LLM_UNCERTAINTY_LOW = 0.3
LLM_UNCERTAINTY_HIGH = 0.7


def _llm_external_egress_enabled() -> bool:
    """Require an explicit deployment opt-in before email data can leave-site."""
    return os.environ.get("LLM_EXTERNAL_EGRESS_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _llm_hard_timeout_secs() -> float:
    """Hard cap for a single LLM call, from env LLM_TIMEOUT_SECS (default 5).

    Must stay below the Rust engine's NLP timeout (8s): a stalled LLM call
    must never cause the engine to drop the whole AI response — including the
    local NLP result — which would fail open.
    """
    raw = os.environ.get("LLM_TIMEOUT_SECS")
    if not raw:
        return 5.0
    try:
        return max(1.0, float(raw))
    except ValueError:
        logger.warning("Invalid LLM_TIMEOUT_SECS; using default", value=raw)
        return 5.0


LLM_HARD_TIMEOUT_SECS = _llm_hard_timeout_secs()


def _llm_max_concurrency() -> int:
    """Bound on simultaneous paid LLM calls, from env LLM_MAX_CONCURRENCY."""
    raw = os.environ.get("LLM_MAX_CONCURRENCY")
    if not raw:
        return 2
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("Invalid LLM_MAX_CONCURRENCY; using default", value=raw)
        return 2


_LLM_MAX_CONCURRENCY = _llm_max_concurrency()

# One semaphore per event loop (created lazily): a batch of uncertain emails
# must not turn into a batch of simultaneous provider requests. Keyed by the
# loop object itself (not id) so a destroyed loop's id can never alias a
# stale semaphore bound to a dead loop.
_llm_semaphores: "dict[asyncio.AbstractEventLoop, asyncio.Semaphore]" = {}


def _llm_semaphore() -> asyncio.Semaphore:
    """Return the LLM concurrency semaphore for the current event loop."""
    loop = asyncio.get_running_loop()
    sem = _llm_semaphores.get(loop)
    if sem is None:
        sem = asyncio.Semaphore(_LLM_MAX_CONCURRENCY)
        _llm_semaphores[loop] = sem
    return sem


# Same-sender rate limit: at most this many paid LLM calls per sender per
# minute. Beyond the limit the LLM re-check is skipped and the local NLP
# result stands (fail-open to the local verdict, never to "no analysis").
LLM_RATE_LIMIT_PER_MINUTE = 2
_LLM_RATE_WINDOW_SECS = 60.0
_llm_rate_log: "dict[str, list[float]]" = {}


def _llm_global_rate_limit_per_minute() -> int:
    """Global per-minute cap on paid LLM calls, from env
    LLM_GLOBAL_RATE_LIMIT_PER_MINUTE (default 20).

    The per-sender limit alone is trivially bypassed by rotating sender
    addresses; the global cap bounds total LLM spend regardless of how many
    distinct senders the attacker cycles through.
    """
    raw = os.environ.get("LLM_GLOBAL_RATE_LIMIT_PER_MINUTE")
    if not raw:
        return 20
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("Invalid LLM_GLOBAL_RATE_LIMIT_PER_MINUTE; using default", value=raw)
        return 20


LLM_GLOBAL_RATE_LIMIT_PER_MINUTE = _llm_global_rate_limit_per_minute()
_llm_global_rate_log: "list[float]" = []

# Hard bound on the per-sender map size: once full, stale keys are swept
# and brand-new sender keys are refused (the LLM re-check is skipped and
# the local NLP verdict stands). Without the refusal, sender rotation with
# fresh keys makes the sweep a no-op and the map grows without bound.
_LLM_RATE_LOG_MAX_KEYS = 1024


def _llm_rate_allow(sender: Optional[str]) -> bool:
    """Record an LLM call for `sender`; False when over the per-sender or
    global per-minute limit."""
    now = time.monotonic()
    cutoff = now - _LLM_RATE_WINDOW_SECS

    # Global cap first: sender rotation must not multiply paid LLM calls.
    while _llm_global_rate_log and _llm_global_rate_log[0] <= cutoff:
        _llm_global_rate_log.pop(0)
    if len(_llm_global_rate_log) >= LLM_GLOBAL_RATE_LIMIT_PER_MINUTE:
        return False

    key = (sender or "").strip().lower() or "<unknown>"
    calls = _llm_rate_log.get(key, [])
    while calls and calls[0] <= cutoff:
        calls.pop(0)
    if not calls:
        # Drop empty keys so they do not linger for the process lifetime.
        _llm_rate_log.pop(key, None)
    if len(calls) >= LLM_RATE_LIMIT_PER_MINUTE:
        return False
    if key not in _llm_rate_log and len(_llm_rate_log) >= _LLM_RATE_LOG_MAX_KEYS:
        # Sender rotation creates one key per forged sender and keeps every
        # key fresh, so try reclaiming expired keys first; if the map is
        # still full, refuse the NEW key instead of growing without bound.
        stale = [k for k, v in _llm_rate_log.items() if not v or v[-1] <= cutoff]
        for k in stale:
            _llm_rate_log.pop(k, None)
        if len(_llm_rate_log) >= _LLM_RATE_LOG_MAX_KEYS:
            logger.warning(
                "LLM rate-limit key cap reached; refusing new sender key",
                keys=len(_llm_rate_log),
            )
            return False
    calls.append(now)
    _llm_rate_log[key] = calls
    _llm_global_rate_log.append(now)
    return True


# Whitelist of verdicts the LLM is allowed to return. Anything else (for
# example a forged "green" verdict injected through the email body) is
# dropped and flagged instead of being rendered as a badge in the analyst UI.
_LLM_VALID_VERDICTS = frozenset({"safe", "low", "medium", "high", "critical"})

_LLM_JSON_BLOCK: "re.Pattern[str]" = re.compile(r"\{.*\}", re.DOTALL)


def _local_result_uncertain(result: NLPPhishingResult) -> bool:
    prob = (result.details or {}).get("malicious_probability")
    if isinstance(prob, bool) or not isinstance(prob, (int, float)):
        return False
    return LLM_UNCERTAINTY_LOW <= prob <= LLM_UNCERTAINTY_HIGH


def _parse_llm_verdict(content: str) -> tuple[str, Optional[float], str]:
    """Extract (verdict, confidence, reasoning) from the LLM's JSON reply.

    Tolerates markdown fences / surrounding prose; falls back to an "unknown"
    verdict with the raw reply as reasoning.
    """
    reasoning = content.strip()[:500]
    match = _LLM_JSON_BLOCK.search(content)
    payload = None
    if match:
        try:
            payload = json.loads(match.group(0))
        except (ValueError, TypeError):
            payload = None
    if not isinstance(payload, dict):
        return "unknown", None, reasoning

    verdict = payload.get("threat_level")
    confidence = payload.get("confidence")
    summary = payload.get("summary") or payload.get("details")
    return (
        verdict if isinstance(verdict, str) and verdict else "unknown",
        float(confidence)
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool)
        else None,
        str(summary)[:500] if summary else reasoning,
    )


async def _llm_chat_with_semaphore(client: LLMClient, prompt: str):
    """Acquire the concurrency semaphore, then run the LLM chat call.

    Kept as a single coroutine so `asyncio.wait_for` can wrap BOTH the
    semaphore wait and the chat call: queueing behind other LLM calls must
    count against the hard-timeout budget, not extend it.
    """
    async with _llm_semaphore():
        return await client.chat(prompt, system=SYSTEM_PROMPT)


async def _llm_second_opinion(
    request: ContentAnalysisRequest,
    result: NLPPhishingResult,
) -> Optional[dict]:
    """Run an advisory LLM re-check when the local NLP result is uncertain.

    Fail-open by design: any failure (timeout, network, bad key, malformed
    reply) logs a warning and returns None, so the local NLP verdict stands.
    The LLM result never changes `malicious_probability`; it is only attached
    to the response details as an extra signal.
    """
    cfg = request.llm
    if cfg is None or not cfg.api_key or cfg.provider not in ("claude", "openai"):
        return None
    if not _llm_external_egress_enabled():
        logger.warning(
            "LLM second opinion skipped: external egress is disabled by deployment policy",
            session_id=request.session_id,
        )
        return None
    if not _local_result_uncertain(result):
        return None

    raw_subject = request.subject or ""
    raw_body = request.body_text or request.body_html or ""
    if contains_high_risk_sensitive_data(raw_subject, raw_body):
        logger.warning(
            "LLM second opinion skipped: high-risk DLP match in email content",
            session_id=request.session_id,
        )
        return None

    # Only DLP-redacted values enter the prompt. Sender/recipient addresses
    # are useful for local analysis but are not needed by the external model.
    safe_mail_from = redact_sensitive_text(request.mail_from)
    safe_rcpt_to = [redact_sensitive_text(address) for address in request.rcpt_to]
    safe_subject = redact_sensitive_text(raw_subject)
    safe_body = redact_sensitive_text(raw_body)
    if not _llm_rate_allow(request.mail_from):
        logger.warning(
            "LLM second opinion skipped: sender rate limit reached",
            session_id=request.session_id,
            mail_from=request.mail_from,
        )
        return None

    # prompts.py sanitizes inputs (injection markers, <email_data> boundary,
    # truncation) — the email content never becomes instructions.
    prompt = format_analyze_prompt(
        mail_from=safe_mail_from,
        rcpt_to=safe_rcpt_to,
        subject=safe_subject,
        protocol="smtp",
        content_preview=safe_body,
    )
    try:
        client = LLMClient(
            LLMConfig(
                provider=LLMProvider(cfg.provider),
                api_key=cfg.api_key,
                model=cfg.model or LLMConfig().model,
                max_tokens=cfg.max_tokens,
                temperature=cfg.temperature,
                # HTTP timeout slightly above the wait_for cap so the asyncio
                # timeout fires first and the response is discarded cleanly.
                timeout=LLM_HARD_TIMEOUT_SECS + 1.0,
            )
        )
        try:
            # wait_for wraps the semaphore acquisition too: time spent
            # queueing behind other LLM calls is part of the hard-timeout
            # budget, so a saturated semaphore degrades to "skip LLM"
            # instead of delaying the whole engine response.
            response = await asyncio.wait_for(
                _llm_chat_with_semaphore(client, prompt),
                timeout=LLM_HARD_TIMEOUT_SECS,
            )
        finally:
            await client.close()
    except Exception as exc:
        logger.warning(
            "LLM second opinion failed, keeping local NLP result",
            session_id=request.session_id,
            provider=cfg.provider,
            error=str(exc),
        )
        return None

    verdict, confidence, reasoning = _parse_llm_verdict(response.content)
    injection_suspected = False
    if verdict != "unknown":
        normalized = verdict.strip().lower()
        if normalized in _LLM_VALID_VERDICTS:
            verdict = normalized
        else:
            # Forged/invalid verdict (e.g. an injected "threat_level": "green"
            # from the email body): drop it and flag instead of rendering
            # attacker-controlled text as a badge in the UI.
            injection_suspected = True
            logger.warning(
                "LLM verdict outside whitelist; dropping",
                session_id=request.session_id,
                verdict=verdict[:50],
            )
            verdict = None
    logger.info(
        "LLM second opinion completed",
        session_id=request.session_id,
        provider=cfg.provider,
        model=response.model,
        verdict=verdict,
        confidence=confidence,
        injection_suspected=injection_suspected,
    )
    return {
        "provider": cfg.provider,
        "model": response.model,
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "injection_suspected": injection_suspected,
    }


@app.get("/health")
async def health():
    """Liveness check that also exposes current model-readiness details."""
    manager = get_model_manager(warmup=False)
    model_status = manager.readiness_report()
    return {
        "status": "ok",
        "service": "vigilyx-ai",
        "ready": model_status["ready"],
        "model_status": model_status,
    }


@app.get("/health/ready")
async def health_ready():
    """Readiness check used by the Rust engine before sending NLP work."""
    manager = get_model_manager(warmup=False)
    model_status = manager.readiness_report()
    if model_status["ready"]:
        return {"status": "ready", "service": "vigilyx-ai", "model_status": model_status}

    return JSONResponse(
        status_code=503,
        content={
            "status": "not_ready",
            "service": "vigilyx-ai",
            "error": "MODEL_UNAVAILABLE",
            "retry_after_secs": model_status["retry_after_secs"],
            "model_status": model_status,
        },
    )


@app.post("/analyze/content", response_model=AiAnalysisResponse)
async def analyze_content(request: ContentAnalysisRequest) -> AiAnalysisResponse:
    """
    Run NLP-based phishing analysis on email content.

    Uses multilingual HuggingFace Transformer models to classify content as
    phishing, scam, BEC, spam, or legitimate mail. Works with both Chinese
    and English content.

    Initial model load usually takes 10-30 seconds; steady-state inference is
    typically 50-200ms per message (long emails are scored in up to
    NLP_MAX_SEGMENTS windows, so worst-case cost scales with segment count).
    """
    logger.info(
        "NLP phishing analysis request",
        session_id=request.session_id,
        has_subject=request.subject is not None,
        has_body=request.body_text is not None or request.body_html is not None,
        mail_from=request.mail_from,
    )

    try:
        result = await analyze_phishing_nlp(
            subject=request.subject,
            body_text=request.body_text,
            body_html=request.body_html,
            mail_from=request.mail_from,
            rcpt_to=request.rcpt_to,
        )
    except ModelUnavailableError as exc:
        manager = get_model_manager(warmup=False)
        model_status = exc.status or manager.readiness_report()
        logger.warning(
            "NLP phishing analysis unavailable",
            session_id=request.session_id,
            retry_after_secs=exc.retry_after_secs,
            error=str(exc),
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "MODEL_UNAVAILABLE",
                "message": "NLP model is temporarily unavailable",
                "retry_after_secs": exc.retry_after_secs,
                "model_status": model_status,
            },
        )
    except asyncio.TimeoutError:
        logger.error(
            "NLP phishing analysis timed out",
            session_id=request.session_id,
        )
        return JSONResponse(
            status_code=504,
            content={
                "error": "ANALYSIS_TIMEOUT",
                "message": "NLP analysis exceeded its time limit",
            },
        )
    except Exception as exc:
        logger.exception(
            "NLP phishing analysis failed unexpectedly",
            session_id=request.session_id,
            error=str(exc),
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "ANALYSIS_FAILED",
                # SECURITY: Do not expose str(exc) — it may leak internal paths,
                # model names, or stack details.  The full error is already logged above.
                "message": "Internal analysis error",
            },
        )

    logger.info(
        "NLP phishing analysis result",
        session_id=request.session_id,
        threat_level=result.threat_level,
        is_phishing=result.is_phishing,
        confidence=result.confidence,
        inference_ms=result.inference_ms,
    )

    # Advisory LLM second opinion for uncertain local results; fail-open.
    llm_analysis = await _llm_second_opinion(request, result)
    details = result.details
    if llm_analysis is not None:
        details = {**(result.details or {}), "llm_analysis": llm_analysis}

    return AiAnalysisResponse(
        threat_level=result.threat_level,
        confidence=result.confidence,
        categories=result.categories,
        summary=result.summary,
        details=details,
    )


@app.post("/api/vt-scrape", response_model=VtScrapeResponse)
async def vt_scrape(request: VtScrapeRequest) -> VtScrapeResponse:
    """
    Scrape VirusTotal detection data via Playwright.

    Supported `indicator_type` values:
    - domain: domain name such as `example.com`
    - ip: IP address
    - url: full URL; the API computes the SHA-256 VT lookup hash automatically
    - hash: file hash (MD5, SHA-1, or SHA-256)
    """
    try:
        indicator = validate_vt_indicator(request.indicator, request.indicator_type)
    except ValueError:
        return VtScrapeResponse(
            success=False,
            error="INVALID_INDICATOR",
        )

    logger.info(
        "VT scrape request",
        indicator=indicator,
        indicator_type=request.indicator_type,
    )

    scraper = get_scraper()
    result = await scraper.scrape(indicator, request.indicator_type)

    logger.info(
        "VT scrape result",
        indicator=indicator,
        verdict=result.verdict,
        malicious=result.malicious_count,
        total=result.total_engines,
        success=result.success,
    )

    return result


# Training-management endpoints.

class TrainingSampleInput(BaseModel):
    """Single training sample sent in batch form from Rust."""
    session_id: str = ""
    label: int                    # 0-4 for the five-class training task
    subject: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    mail_from: Optional[str] = None
    rcpt_to: list[str] = Field(default_factory=list)


class TrainingRequest(BaseModel):
    """Batch training request used by Rust `trigger_nlp_training`."""
    samples: list[TrainingSampleInput]


# ---------------------------------------------------------------------------
# Trained-model approval gate
# ---------------------------------------------------------------------------

# A freshly trained model is staged as "pending" and is only hot-swapped into
# inference after an explicit operator approval (POST /model/approve). This
# prevents a consistent-poisoning attack that passes the CV quality gate from
# going live automatically.
PENDING_MODEL_FILE = os.path.join(os.path.dirname(LATEST_MODEL_DIR), "pending.json")


def _read_pending_model() -> Optional[dict]:
    """Return the staged-model record, or None when nothing is pending."""
    try:
        with open(PENDING_MODEL_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("model_dir"):
        return None
    return data


def _write_pending_model(info: dict) -> None:
    """Atomically record a staged model awaiting approval."""
    os.makedirs(os.path.dirname(PENDING_MODEL_FILE), exist_ok=True)
    tmp_path = PENDING_MODEL_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(info, fh)
    os.replace(tmp_path, PENDING_MODEL_FILE)


def _clear_pending_model() -> None:
    try:
        os.remove(PENDING_MODEL_FILE)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("Failed to clear pending model file", error=str(exc))


def _samples_fingerprint(samples: list["TrainingSampleInput"]) -> str:
    """Stable hash over the training batch (session_id + label pairs).

    Recorded with the staged model in pending.json so the operator can
    verify WHICH training set produced the model before approving it, and
    so a swapped-in training run can be detected via the version check.
    """
    digest = hashlib.sha256()
    for sample in samples:
        digest.update(sample.session_id.encode("utf-8", "replace"))
        digest.update(b"\x00")
        digest.update(str(sample.label).encode("ascii"))
        digest.update(b"\x00")
    return digest.hexdigest()


class ModelApproveRequest(BaseModel):
    """Optional optimistic-concurrency check for POST /model/approve.

    When provided, the staged record must match these values exactly;
    otherwise the approval is rejected with 409 instead of swapping a model
    the operator did not review.
    """
    expected_model_dir: Optional[str] = None
    expected_staged_at: Optional[float] = None


@app.post("/training/train")
async def train(request: TrainingRequest):
    """
    Accept batch samples and trigger five-class fine-tuning.

    Rust reads the full training set from the database and posts it here in
    one batch. Python handles `preprocess_email()`, model training, and the
    result payload. Training runs in a subprocess so the API stays responsive.
    A successful run does NOT hot-swap the model automatically: the new model
    is staged as pending and only goes live after an explicit operator
    approval via POST /model/approve.
    """
    # SEC-M10: Cap request size to reduce OOM risk from oversized payloads.
    if len(request.samples) > 10000:
        raise HTTPException(status_code=413, detail="TOO_MANY_SAMPLES")

    logger.info(
        "Training request received",
        total_samples=len(request.samples),
    )

    if len(request.samples) < MIN_SAMPLES:
        return {"ok": False, "error": f"Insufficient samples: {len(request.samples)}/{MIN_SAMPLES}"}

    trainer = get_trainer()
    result = await trainer.train(request.samples)

    if result.get("ok"):
        model_dir = result.get("model_dir", "")
        if model_dir:
            # Approval gate: a poisoned-but-consistent training set could pass
            # the CV quality gate, so the model is staged instead of swapped.
            _write_pending_model({
                "model_dir": model_dir,
                "version": result.get("version", ""),
                "staged_at": time.time(),
                "samples_count": len(request.samples),
                "samples_hash": _samples_fingerprint(request.samples),
            })
            result["model_pending_approval"] = True
            logger.info(
                "Trained model staged; awaiting approval before hot-swap",
                model_dir=model_dir,
            )

    return result


@app.post("/model/approve")
async def approve_model(payload: Optional[ModelApproveRequest] = None):
    """Hot-swap the staged (pending) trained model into inference.

    Protected by the same X-Internal-Token middleware as every other
    non-health endpoint. Until approval, inference keeps using the old model.

    Optimistic concurrency: the caller may pass expected_model_dir /
    expected_staged_at (echoed by /training/status) and the staged record is
    re-read right before the swap. Any mismatch means a newer training run
    was staged in between and the approval is rejected with 409 rather than
    silently swapping a model the operator did not review.
    """
    pending = _read_pending_model()
    if pending is None:
        raise HTTPException(status_code=404, detail="NO_PENDING_MODEL")

    if payload is not None:
        if (
            payload.expected_model_dir is not None
            and payload.expected_model_dir != pending.get("model_dir")
        ) or (
            payload.expected_staged_at is not None
            and payload.expected_staged_at != pending.get("staged_at")
        ):
            logger.warning(
                "Model approval rejected: staged record does not match expectation",
                pending_model_dir=pending.get("model_dir"),
            )
            raise HTTPException(status_code=409, detail="PENDING_MODEL_CHANGED")

    model_dir = pending.get("model_dir", "")
    # Path safety: only approve directories inside the models root.
    models_root = os.path.realpath(os.path.dirname(LATEST_MODEL_DIR))
    real_dir = os.path.realpath(model_dir)
    if not real_dir.startswith(models_root + os.sep) or not os.path.isdir(real_dir):
        logger.warning("Pending model path invalid or missing", model_dir=model_dir)
        _clear_pending_model()
        raise HTTPException(status_code=410, detail="PENDING_MODEL_MISSING")

    # Race guard: re-read the staged record immediately before swapping. If a
    # concurrent training run staged a different model after our first read,
    # refuse instead of approving an unreviewed model.
    fresh = _read_pending_model()
    if (
        fresh is None
        or fresh.get("model_dir") != pending.get("model_dir")
        or fresh.get("staged_at") != pending.get("staged_at")
    ):
        logger.warning(
            "Pending model changed between read and approval; rejecting",
            original_model_dir=pending.get("model_dir"),
        )
        raise HTTPException(status_code=409, detail="PENDING_MODEL_CHANGED")

    manager = get_model_manager(warmup=False)
    await manager.hot_swap(real_dir)
    _clear_pending_model()
    logger.info("Pending model approved and hot-swapped", model_dir=real_dir)
    return {"ok": True, "model_dir": real_dir, "model_swapped": True, "approved_model": pending}


@app.get("/training/status")
async def training_status():
    """Query model and training status."""
    manager = get_model_manager(warmup=False)
    trainer = get_trainer()
    base_info = get_base_model_info()

    return {
        "model_version": manager.model_version,
        "has_finetuned": manager.has_finetuned,
        "model_status": manager.readiness_report(),
        "is_training": trainer.is_training,
        "last_trained": trainer.last_trained,
        "base_model": base_info,
        "pending_model": _read_pending_model(),
    }


@app.get("/training/progress")
async def training_progress():
    """Query live training progress."""
    trainer = get_trainer()
    if not trainer.is_training:
        return {"active": False}

    progress = get_training_progress()
    if progress is None:
        return {"active": True, "phase": "initializing"}

    progress["active"] = True
    return progress
