"""
Vigilyx AI service FastAPI entrypoint.

Endpoints:
  POST /api/vt-scrape              - Scrape VirusTotal detection data with Playwright
  POST /analyze/content            - NLP phishing analysis (HuggingFace Transformer)
  POST /training/train             - Trigger five-class fine-tuning from batch samples
  GET  /training/status            - Query training and model status
  GET  /training/progress          - Query live training progress
  POST /training/update-base-model - Refresh the local base-model snapshot
  GET  /health                     - Liveness check
  GET  /health/ready               - Model-readiness check
"""

import hmac
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .scraper import get_scraper
from .nlp_phishing import ModelUnavailableError, analyze_phishing_nlp, get_model_manager
from .trainer import get_trainer, get_base_model_info, get_training_progress, BASE_MODEL_HF, NUM_LABELS, LABEL_NAMES, BASE_MODEL_DIR, MIN_SAMPLES
from .vt_models import VtScrapeRequest, VtScrapeResponse

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

class ContentAnalysisRequest(BaseModel):
    """Email-content analysis request aligned with Rust ContentAnalysisRequest."""
    session_id: str = ""
    subject: Optional[str] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    mail_from: Optional[str] = None
    rcpt_to: list[str] = Field(default_factory=list)


class AiAnalysisResponse(BaseModel):
    """AI analysis response aligned with Rust AiAnalysisResponse."""
    threat_level: str           # safe / low / medium / high / critical
    confidence: float           # 0.0 - 1.0
    categories: list[str] = Field(default_factory=list)
    summary: str = ""
    details: Optional[dict] = None


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
    typically 50-200ms per message.
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

    return AiAnalysisResponse(
        threat_level=result.threat_level,
        confidence=result.confidence,
        categories=result.categories,
        summary=result.summary,
        details=result.details,
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
    logger.info(
        "VT scrape request",
        indicator=request.indicator,
        indicator_type=request.indicator_type,
    )

    if request.indicator_type not in ("domain", "ip", "url", "hash"):
        return VtScrapeResponse(
            success=False,
            error=f"Unsupported indicator_type: {request.indicator_type}",
        )

    scraper = get_scraper()
    result = await scraper.scrape(request.indicator, request.indicator_type)

    logger.info(
        "VT scrape result",
        indicator=request.indicator,
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


@app.post("/training/train")
async def train(request: TrainingRequest):
    """
    Accept batch samples and trigger five-class fine-tuning.

    Rust reads the full training set from the database and posts it here in
    one batch. Python handles `preprocess_email()`, model training, and the
    result payload. Training runs in a subprocess so the API stays responsive,
    and a successful run hot-swaps the inference model automatically.
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
            manager = get_model_manager(warmup=False)
            await manager.hot_swap(model_dir)
            result["model_swapped"] = True
            logger.info("Model hot-swapped after training", model_dir=model_dir)

    return result


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


@app.post("/training/update-base-model")
async def update_base_model():
    """
    Re-download the base model and refresh the local snapshot.

    Intended for explicit administrator-driven base-model upgrades. A new
    fine-tuning run is still required before the updated base model is used
    for inference.
    """
    import shutil
    import asyncio

    trainer = get_trainer()
    if trainer.is_training:
        return {"ok": False, "error": "Training is in progress; update the base model later."}

    old_info = get_base_model_info()

    logger.info("Updating base model snapshot", model=BASE_MODEL_HF)

    def _download():
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        import json as _json
        from datetime import datetime as _dt, timezone as _tz

        # Remove the old snapshot.
        if os.path.exists(BASE_MODEL_DIR):
            shutil.rmtree(BASE_MODEL_DIR)
        os.makedirs(BASE_MODEL_DIR, exist_ok=True)

        # Force a fresh download from HuggingFace instead of reusing the snapshot.
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_HF)
        model = AutoModelForSequenceClassification.from_pretrained(
            BASE_MODEL_HF, num_labels=NUM_LABELS,
        )
        # Keep semantic label mappings aligned with `_ensure_base_model`.
        model.config.id2label = {i: name for i, name in enumerate(LABEL_NAMES)}
        model.config.label2id = {name: i for i, name in enumerate(LABEL_NAMES)}

        tokenizer.save_pretrained(BASE_MODEL_DIR)
        model.save_pretrained(BASE_MODEL_DIR)

        from .trainer import _get_hf_revision
        revision = _get_hf_revision(BASE_MODEL_HF)

        meta = {
            "source_model": BASE_MODEL_HF,
            "revision": revision,
            "num_labels": NUM_LABELS,
            "label_names": list(LABEL_NAMES),
            "downloaded_at": _dt.now(_tz.utc).isoformat(),
        }
        meta_path = os.path.join(BASE_MODEL_DIR, "base_meta.json")
        with open(meta_path, "w") as f:
            _json.dump(meta, f, indent=2, ensure_ascii=False)

        return meta

    try:
        loop = asyncio.get_event_loop()
        new_info = await loop.run_in_executor(None, _download)
        logger.info(
            "Base model updated",
            old_revision=old_info.get("revision") if old_info else None,
            new_revision=new_info.get("revision"),
        )
        return {
            "ok": True,
            "old": old_info,
            "new": new_info,
            "message": "Base model snapshot updated. Trigger training again to use the new model.",
        }
    except Exception as e:
        logger.error(f"Failed to update base model: {e}")
        return {"ok": False, "error": "MODEL_UPDATE_FAILED"}
