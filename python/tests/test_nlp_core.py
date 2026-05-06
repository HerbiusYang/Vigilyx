"""Tests for NLP pure functions: _detect_language, _clean_html, preprocess_email."""

from __future__ import annotations

import pytest

from vigilyx_ai.nlp_phishing import _clean_html, _detect_language, preprocess_email


# =====================================================================
# _detect_language
# =====================================================================


class TestDetectLanguage:
    """~10 cases for _detect_language."""

    def test_pure_chinese(self):
        assert _detect_language("这是一封中文邮件") == "zh"

    def test_pure_english(self):
        assert _detect_language("This is a plain English email") == "en"

    def test_mixed_high_cjk_ratio(self):
        # >30% CJK -> "zh"
        text = "你好世界hello"  # 4 CJK chars / 9 total non-space chars ~= 44%
        assert _detect_language(text) == "zh"

    def test_mixed_low_cjk_ratio(self):
        # <30% CJK -> "en"
        text = "hello world 你"  # 1 CJK char / 11 non-space chars ~= 9%
        assert _detect_language(text) == "en"

    def test_empty_string(self):
        assert _detect_language("") == "unknown"

    def test_whitespace_only(self):
        # All whitespace -> total non-space chars = 0 -> "unknown"
        assert _detect_language("   \t\n  ") == "unknown"

    def test_japanese_kanji_counted_as_cjk(self):
        # Kanji (U+4E00–U+9FFF) is CJK and should trigger "zh"
        text = "東京都渋谷区"
        assert _detect_language(text) == "zh"

    def test_numbers_only(self):
        # Digits are non-space but not CJK -> ratio 0 -> "en"
        assert _detect_language("123456789") == "en"

    def test_threshold_boundary_exactly_30_percent(self):
        # 3 CJK out of 10 non-space chars = exactly 30%; detection requires strictly greater.
        text = "abcdefg你好吗"  # 3 CJK / 10 non-space = 0.30 -> not > 0.3 -> "en"
        assert _detect_language(text) == "en"

    def test_threshold_just_above_30_percent(self):
        # 4 CJK out of 10 non-space chars = 40% -> "zh"
        text = "abcdef你好吗呢"  # 4 CJK / 10 non-space = 0.40 -> "zh"
        assert _detect_language(text) == "zh"


# =====================================================================
# _clean_html
# =====================================================================


class TestCleanHtml:
    """~8 cases for _clean_html."""

    def test_script_tags_removed(self):
        html = "Hello <script>alert('xss')</script> World"
        result = _clean_html(html)
        assert "alert" not in result
        assert "Hello" in result
        assert "World" in result

    def test_style_tags_removed(self):
        html = "Hello <style>body{color:red}</style> World"
        result = _clean_html(html)
        assert "color" not in result
        assert "Hello" in result

    def test_html_comments_removed(self):
        html = "Hello <!-- this is a comment --> World"
        result = _clean_html(html)
        assert "comment" not in result
        assert "Hello" in result
        assert "World" in result

    def test_tags_stripped_text_preserved(self):
        html = "<p>Hello</p><br/><div>World</div>"
        result = _clean_html(html)
        assert "Hello" in result
        assert "World" in result
        assert "<p>" not in result
        assert "<div>" not in result

    def test_html_entities_decoded(self):
        html = "&amp; &#x41; &lt; &gt;"
        result = _clean_html(html)
        assert "&" in result
        assert "A" in result
        assert "<" in result
        assert ">" in result

    def test_whitespace_collapsed(self):
        html = "Hello    \n\n   World"
        result = _clean_html(html)
        assert result == "Hello World"

    def test_nested_tags(self):
        html = "<div><p><b>Bold <i>Italic</i></b></p></div>"
        result = _clean_html(html)
        assert "Bold" in result
        assert "Italic" in result
        assert "<" not in result

    def test_plain_text_unchanged(self):
        text = "Just plain text"
        assert _clean_html(text) == "Just plain text"


# =====================================================================
# preprocess_email
# =====================================================================


class TestPreprocessEmail:
    """~8 cases for preprocess_email."""

    def test_normal_email(self):
        result = preprocess_email("Test Subject", "Body text", "user@example.com")
        assert "From: user@example.com" in result
        assert "Subject: Test Subject" in result
        assert "Body text" in result

    def test_none_subject(self):
        result = preprocess_email(None, "Body text", "user@example.com")
        assert "Subject:" not in result
        assert "Body text" in result

    def test_none_body(self):
        result = preprocess_email("Subject", None, "user@example.com")
        assert "Subject: Subject" in result
        # No body section appended
        lines = result.strip().split("\n")
        # Should just be From and Subject
        assert len(lines) == 2

    def test_none_mail_from(self):
        result = preprocess_email("Subject", "Body", None)
        assert "From:" not in result
        assert "Subject: Subject" in result
        assert "Body" in result

    def test_body_truncated_at_max_chars(self):
        long_body = "A" * 10000
        result = preprocess_email("Subj", long_body, "user@example.test", max_chars=500)
        assert len(result) <= 500

    def test_html_body_cleaned(self):
        html_body = "<p>Hello <b>World</b></p><script>evil()</script>"
        result = preprocess_email("Subj", html_body, None)
        assert "Hello" in result
        assert "World" in result
        assert "evil" not in result
        assert "<p>" not in result

    def test_all_none(self):
        result = preprocess_email(None, None, None)
        # No parts → empty string
        assert result == ""

    def test_all_empty_strings(self):
        result = preprocess_email("", "", "")
        # Empty strings are falsy, so none of the parts are added
        assert result == ""

    def test_body_pretrimmed_before_html_clean(self):
        # body[:max_chars*3] happens before _clean_html
        large_body = "<b>" + "X" * 20000 + "</b>"
        result = preprocess_email(None, large_body, None, max_chars=3000)
        assert len(result) <= 3000
