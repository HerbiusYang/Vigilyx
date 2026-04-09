"""
LLM client helpers.

Provides a unified interface for calling supported LLM providers.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx


class LLMProvider(str, Enum):
    """Supported LLM provider."""
    CLAUDE = "claude"
    OPENAI = "openai"


@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: LLMProvider = LLMProvider.CLAUDE
    api_key: Optional[str] = None
    model: str = "claude-3-5-sonnet-20241022"
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout: float = 60.0

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

    CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
    OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

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

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
