"""Tests for LLM prompt formatting functions."""

from __future__ import annotations

import pytest

from vigilyx_ai.llm.prompts import format_analyze_prompt


class TestFormatAnalyzePrompt:
    """~5 cases for format_analyze_prompt."""

    def test_normal_inputs(self):
        result = format_analyze_prompt(
            mail_from="alice@example.com",
            rcpt_to=["bob@example.com", "carol@example.com"],
            subject="Monthly Report",
            protocol="SMTP",
            content_preview="Please find the attached report.",
        )
        assert "alice@example.com" in result
        assert "bob@example.com, carol@example.com" in result
        assert "Monthly Report" in result
        assert "SMTP" in result
        assert "Please find the attached report." in result

    def test_none_values(self):
        result = format_analyze_prompt(
            mail_from=None,
            rcpt_to=[],
            subject=None,
            protocol="IMAP",
            content_preview="",
        )
        assert "Unknown" in result  # mail_from=None → "Unknown"
        assert "No subject" in result  # subject=None → "No subject"
        assert "No content" in result  # content_preview="" → "No content"

    def test_long_content_truncated(self):
        long_content = "X" * 5000
        result = format_analyze_prompt(
            mail_from="sender@example.test",
            rcpt_to=["recipient@example.test"],
            subject="Test",
            protocol="SMTP",
            content_preview=long_content,
        )
        # Content should be truncated at 2000 chars
        assert "X" * 2000 in result
        assert "X" * 2001 not in result

    def test_recipient_list_formatted(self):
        result = format_analyze_prompt(
            mail_from="author@example.test",
            rcpt_to=["first@example.com", "second@example.net", "third@example.org"],
            subject="Hi",
            protocol="SMTP",
            content_preview="test",
        )
        assert "first@example.com, second@example.net, third@example.org" in result

    def test_empty_recipient_list(self):
        result = format_analyze_prompt(
            mail_from="author@example.test",
            rcpt_to=[],
            subject="Hi",
            protocol="SMTP",
            content_preview="test",
        )
        assert "Unknown" in result
