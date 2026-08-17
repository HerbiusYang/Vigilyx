"""
LLM client helpers.

Provides a unified interface for calling supported LLM providers.
"""

import os
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

import httpx


class LLMProvider(str, Enum):
    """Supported LLM provider."""
    CLAUDE = "claude"
    OPENAI = "openai"


# The client deliberately has no operator-supplied base URL. Keep this exact
# host allowlist as a second guard against accidental future endpoint changes.
LLM_PROVIDER_ENDPOINTS = {
    LLMProvider.CLAUDE: "https://api.anthropic.com/v1/messages",
    LLMProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
}
LLM_ALLOWED_EGRESS_HOSTS = frozenset({"api.anthropic.com", "api.openai.com"})

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PRIVATE_IP_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f])"
)
_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|bearer|password|passwd|secret|authorization)"
    r"\s*[:=]\s*[^\s,;]+"
)
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")
_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:localhost|[a-z0-9-]+\.(?:local|internal|intranet|lan|corp|home|test|example|invalid))\b"
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def is_non_public_host(host: str | None) -> bool:
    """Return True for private/reserved hosts that must not leave the site."""
    if not host:
        return False
    normalized = host.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None:
        private = (
            address.is_private
            if isinstance(address, ipaddress.IPv4Address)
            else address in ipaddress.ip_network("fc00::/7")
        )
        return (
            private
            or address.is_loopback
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
        )
    return normalized == "localhost" or any(
        normalized == suffix or normalized.endswith("." + suffix)
        for suffix in (
            "local",
            "internal",
            "intranet",
            "lan",
            "corp",
            "home",
            "test",
            "example",
            "invalid",
        )
    )


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group(0).rstrip(".,;:)]}")
    parsed = urlsplit(raw)
    if is_non_public_host(parsed.hostname):
        return "[REDACTED_INTERNAL_URL]"
    if not parsed.scheme or not parsed.netloc:
        return "[REDACTED_URL]"
    # Preserve public host/path for phishing analysis, but never forward
    # credentials, query tokens, or fragments.
    return f"{parsed.scheme}://{parsed.hostname}{parsed.path or ''}"


def redact_sensitive_text(text: str | None) -> str:
    """Redact common PII/secrets before text can enter an external prompt."""
    if not text:
        return text or ""
    redacted = _URL_RE.sub(_redact_url, text)
    redacted = _SECRET_RE.sub("[REDACTED_SECRET]", redacted)
    redacted = _IBAN_RE.sub("[REDACTED_IBAN]", redacted)
    redacted = _CARD_RE.sub("[REDACTED_PAYMENT_ID]", redacted)
    redacted = _PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    redacted = _PRIVATE_IP_RE.sub("[REDACTED_IP]", redacted)
    redacted = _INTERNAL_HOST_RE.sub("[REDACTED_INTERNAL_HOST]", redacted)
    return _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)


def contains_high_risk_sensitive_data(*values: str | None) -> bool:
    """Detect data that should block external egress rather than be sampled."""
    for value in values:
        if not value:
            continue
        if (
            _SECRET_RE.search(value)
            or _IBAN_RE.search(value)
            or _CARD_RE.search(value)
            or _PHONE_RE.search(value)
            or _PRIVATE_IP_RE.search(value)
            or _INTERNAL_HOST_RE.search(value)
        ):
            return True
        for match in _URL_RE.finditer(value):
            if is_non_public_host(urlsplit(match.group(0)).hostname):
                return True
    return False


def _default_timeout_secs() -> float:
    """Default LLM HTTP timeout from env LLM_TIMEOUT_SECS (default 5s)."""
    raw = os.environ.get("LLM_TIMEOUT_SECS")
    if not raw:
        return 5.0
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 5.0


@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: LLMProvider = LLMProvider.CLAUDE
    api_key: Optional[str] = None
    model: str = "claude-3-5-sonnet-20241022"
    max_tokens: int = 4096
    temperature: float = 0.3
    # Default 5s (env LLM_TIMEOUT_SECS): must stay below the Rust engine's
    # NLP timeout (8s) so a stalled LLM cannot make the engine drop the whole
    # AI response and fail open.
    timeout: float = field(default_factory=lambda: _default_timeout_secs())

    def __post_init__(self):
        if self.api_key is None:
            if self.provider == LLMProvider.CLAUDE:
                self.api_key = os.getenv("ANTHROPIC_API_KEY")
            elif self.provider == LLMProvider.OPENAI:
                self.api_key = os.getenv("OPENAI_API_KEY")

    def __repr__(self):
        """Mask api_key in repr to prevent accidental leakage in logs/tracebacks."""
        return f"LLMConfig(provider={self.provider!r}, model={self.model!r}, api_key='***')"


@dataclass
class LLMResponse:
    """LLM response payload."""
    content: str
    model: str
    usage: dict = field(default_factory=dict)


class LLMClient:
    """LLM client."""

    CLAUDE_API_URL = LLM_PROVIDER_ENDPOINTS[LLMProvider.CLAUDE]
    OPENAI_API_URL = LLM_PROVIDER_ENDPOINTS[LLMProvider.OPENAI]

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self._client = httpx.AsyncClient(timeout=self.config.timeout)

    async def close(self):
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def chat(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send a chat request.

        Args:
            prompt: User prompt
            system: Optional system prompt

        Returns:
            Parsed LLM response
        """
        if self.config.provider == LLMProvider.CLAUDE:
            return await self._chat_claude(prompt, system)
        elif self.config.provider == LLMProvider.OPENAI:
            return await self._chat_openai(prompt, system)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    async def _chat_claude(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """Call the Claude API."""
        self._assert_allowed_endpoint(self.CLAUDE_API_URL)
        headers = {
            "x-api-key": self.config.api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        data = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system:
            data["system"] = system

        response = await self._client.post(
            self.CLAUDE_API_URL,
            headers=headers,
            json=data,
        )
        response.raise_for_status()
        result = response.json()

        return LLMResponse(
            content=result["content"][0]["text"],
            model=result["model"],
            usage=result.get("usage", {}),
        )

    async def _chat_openai(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """Call the OpenAI API."""
        self._assert_allowed_endpoint(self.OPENAI_API_URL)
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": messages,
        }

        response = await self._client.post(
            self.OPENAI_API_URL,
            headers=headers,
            json=data,
        )
        response.raise_for_status()
        result = response.json()

        return LLMResponse(
            content=result["choices"][0]["message"]["content"],
            model=result["model"],
            usage=result.get("usage", {}),
        )

    @staticmethod
    def _assert_allowed_endpoint(endpoint: str) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or parsed.hostname not in LLM_ALLOWED_EGRESS_HOSTS:
            raise RuntimeError("LLM endpoint is outside the approved HTTPS egress allowlist")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
