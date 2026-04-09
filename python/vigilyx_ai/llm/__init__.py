"""
Large-language-model integration helpers.

Supported providers:
- Claude (Anthropic)
- OpenAI GPT
- Other compatible APIs
"""

from .client import LLMClient, LLMConfig

__all__ = ["LLMClient", "LLMConfig"]
