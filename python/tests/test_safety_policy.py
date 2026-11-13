import pytest

from vigilyx_ai.safety_policy import (
    EMAIL_SCOPE_ERROR,
    ensure_email_only_input,
    ensure_email_training_sample,
    sanitize_email_text,
)


def test_sanitize_email_text_removes_direct_identifiers():
    text = "From: alice@example.com URL https://example.com/a IP 10.0.0.1 phone +86 138 0013 8000"
    sanitized = sanitize_email_text(text)
    assert "alice@example.com" not in sanitized
    assert "https://example.com" not in sanitized
    assert "10.0.0.1" not in sanitized
    assert "138 0013 8000" not in sanitized
    assert "<EMAIL>" in sanitized
    assert "<URL>" in sanitized


def test_email_only_input_requires_email_context():
    with pytest.raises(ValueError, match=EMAIL_SCOPE_ERROR):
        ensure_email_only_input(
            subject=None, body_text="general text", body_html=None, mail_from=None, rcpt_to=[]
        )

    ensure_email_only_input(
        subject="Invoice", body_text="Please review", body_html=None,
        mail_from="sender@example.com", rcpt_to=["user@example.net"]
    )


def test_training_sample_requires_email_provenance():
    with pytest.raises(ValueError, match=EMAIL_SCOPE_ERROR):
        ensure_email_training_sample({"text": "arbitrary text", "label": 0})
    ensure_email_training_sample({
        "schema_version": "vigilyx.email_training.v1",
        "text": "arbitrary sanitized feature",
        "label": 0,
    })
