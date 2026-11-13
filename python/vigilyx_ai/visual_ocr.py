"""Bounded OCR adapter for image bytes already contained in an email.

This module deliberately does not fetch URLs or render arbitrary HTML.  The
caller must resolve a ``data:`` or ``cid:`` image inside the MIME message and
send only the bounded bytes here.  OCR output is advisory text with explicit
coverage status; it is not a threat verdict.
"""

from __future__ import annotations

import base64
import binascii
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

MAX_IMAGE_BYTES = 2 * 1024 * 1024
OCR_TIMEOUT_SECS = 4.0
OCR_LANGUAGES = "chi_sim+eng"
ALLOWED_IMAGE_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/gif",
        "image/bmp",
        "image/webp",
        "image/tiff",
    }
)


@dataclass(frozen=True)
class VisualOcrResult:
    """One bounded image OCR result, safe to serialize in the API layer."""

    source_id: str
    status: str
    text: str = ""
    confidence: float = 0.0
    reason: str | None = None


def decode_image_base64(payload: str, media_type: str) -> bytes | None:
    """Decode one validated image payload without accepting arbitrary files."""

    normalized_type = media_type.strip().lower().split(";", 1)[0]
    if normalized_type not in ALLOWED_IMAGE_TYPES:
        return None
    if not payload or len(payload) > ((MAX_IMAGE_BYTES * 4) // 3 + 8):
        return None
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not decoded or len(decoded) > MAX_IMAGE_BYTES:
        return None
    return decoded


def _ocr_timeout() -> float:
    raw = os.environ.get("VISUAL_OCR_TIMEOUT_SECS")
    if not raw:
        return OCR_TIMEOUT_SECS
    try:
        return min(max(float(raw), 0.5), 10.0)
    except ValueError:
        return OCR_TIMEOUT_SECS


def _parse_tsv(tsv: str) -> tuple[str, float]:
    """Extract non-empty words and their mean confidence from tesseract TSV."""

    lines = tsv.splitlines()
    if not lines:
        return "", 0.0
    header = lines[0].split("\t")
    try:
        text_index = header.index("text")
        confidence_index = header.index("conf")
    except ValueError:
        return "", 0.0

    words: list[str] = []
    confidences: list[float] = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) <= max(text_index, confidence_index):
            continue
        word = fields[text_index].strip()
        if not word:
            continue
        try:
            confidence = float(fields[confidence_index])
        except ValueError:
            continue
        if confidence >= 0:
            confidences.append(min(max(confidence / 100.0, 0.0), 1.0))
        words.append(word)

    return " ".join(words), (sum(confidences) / len(confidences) if confidences else 0.0)


def run_image_ocr(
    source_id: str,
    image_bytes: bytes,
    media_type: str,
) -> VisualOcrResult:
    """Run tesseract on one bounded image in a temporary file.

    No shell is used, the input is not persisted after the call, and a hung
    decoder/OCR process becomes an explicit coverage result.
    """

    if len(image_bytes) == 0 or len(image_bytes) > MAX_IMAGE_BYTES:
        return VisualOcrResult(source_id, "rejected", reason="image_size_limit")
    normalized_type = media_type.strip().lower().split(";", 1)[0]
    if normalized_type not in ALLOWED_IMAGE_TYPES:
        return VisualOcrResult(source_id, "rejected", reason="unsupported_image_type")

    executable = shutil.which("tesseract")
    if executable is None:
        return VisualOcrResult(source_id, "unavailable", reason="ocr_engine_not_installed")

    suffix = "." + normalized_type.rsplit("/", 1)[-1].replace("jpeg", "jpg")
    try:
        with tempfile.NamedTemporaryFile(prefix="vigilyx-ocr-", suffix=suffix) as image_file:
            image_file.write(image_bytes)
            image_file.flush()
            completed = subprocess.run(
                [executable, image_file.name, "stdout", "--psm", "6", "-l", OCR_LANGUAGES, "tsv"],
                capture_output=True,
                check=False,
                timeout=_ocr_timeout(),
                text=True,
                encoding="utf-8",
                errors="replace",
                env={**os.environ, "OMP_THREAD_LIMIT": "1"},
            )
    except subprocess.TimeoutExpired:
        return VisualOcrResult(source_id, "timeout", reason="ocr_timeout")
    except OSError:
        return VisualOcrResult(source_id, "error", reason="ocr_process_error")

    if completed.returncode != 0:
        return VisualOcrResult(source_id, "error", reason="ocr_process_failed")
    text, confidence = _parse_tsv(completed.stdout)
    if not text:
        return VisualOcrResult(source_id, "empty", confidence=confidence)
    return VisualOcrResult(source_id, "ok", text=text, confidence=confidence)

