"""Hard-coded safety boundary for the Vigilyx email-security model.

These rules are intentionally code-level constants. They are not configurable
through environment variables or API requests:

1. The model must not be trained on or expose real identifying values.
2. The model may only be used for email-security classification.
3. Every non-email use is rejected at the AI API boundary.
"""

import re
from typing import Optional, Sequence


EMAIL_MODEL_SCOPE = "email_security_only"
MODEL_OUTPUT_LABELS = frozenset(
    {"legitimate", "phishing", "spoofing", "social_engineering", "other_threat"}
)
EMAIL_SCOPE_ERROR = "EMAIL_MODEL_SCOPE_ONLY"

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE
)
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_CARD_RE = re.compile(r"(?<!\w)(?:\d[ -]*?){13,19}(?!\w)")
_PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d ().-]{7,}\d(?!\w)")
_LONG_ID_RE = re.compile(r"(?<!\w)\d{8,}(?!\w)")


def sanitize_email_text(text: str) -> str:
    """Remove direct identifiers before text reaches a model."""
    if not text:
        return ""
    sanitized = _URL_RE.sub("<URL>", text)
    sanitized = _EMAIL_RE.sub("<EMAIL>", sanitized)
    sanitized = _IP_RE.sub("<IP>", sanitized)
    sanitized = _CARD_RE.sub("<CARD>", sanitized)
    sanitized = _PHONE_RE.sub("<PHONE>", sanitized)
    sanitized = _LONG_ID_RE.sub("<ID>", sanitized)
    return sanitized


def ensure_email_only_input(
    *,
    subject: Optional[str],
    body_text: Optional[str],
    body_html: Optional[str],
    mail_from: Optional[str],
    rcpt_to: Sequence[str],
) -> None:
    """Reject payloads without an explicit email context.

    The API endpoint is intentionally not a general-purpose text classifier.
    A sender, recipient, or subject is required in addition to content.
    """
    has_content = any(value and value.strip() for value in (subject, body_text, body_html))
    has_email_context = bool(
        (mail_from and mail_from.strip())
        or any(address and address.strip() for address in rcpt_to)
        or (subject and subject.strip())
    )
    if not has_content or not has_email_context:
        raise ValueError(EMAIL_SCOPE_ERROR)


def ensure_email_training_sample(sample: dict) -> None:
    """Reject a training record that is not identifiable as an email record."""
    schema_version = sample.get("schema_version") or ""
    has_email_fields = any(
        sample.get(key)
        for key in ("subject", "body_text", "body_html", "mail_from", "rcpt_to")
    )
    text = sample.get("text") or ""
    has_email_headers = "From:" in text or "Subject:" in text
    if not schema_version.startswith("vigilyx.email_training.") and not (
        has_email_fields or has_email_headers
    ):
        raise ValueError(EMAIL_SCOPE_ERROR)
