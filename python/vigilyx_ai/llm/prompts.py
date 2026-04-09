"""
Prompt templates for LLM-driven email analysis.
"""

SYSTEM_PROMPT = """You are an expert email-security analyst. Analyze email content and identify potential security threats.

Cover these dimensions:
1. Phishing indicators (fake links, impersonation, urgency)
2. Malware delivery (suspicious attachments or download links)
3. Social-engineering patterns (credential harvesting, emotional manipulation)
4. Spam traits (promotion, misleading advertising)
5. Business email compromise (BEC, fraudulent payment requests)

Return the result as JSON."""

ANALYZE_EMAIL_TEMPLATE = """Analyze the following email session:

Sender: {mail_from}
Recipients: {rcpt_to}
Subject: {subject}
Protocol: {protocol}

Email content preview:
{content_preview}

Provide:
1. threat_level: safe / low / medium / high / critical
2. confidence: 0.0-1.0
3. categories: list of threat categories
4. summary: concise summary
5. details: detailed analysis
6. recommendations: list of recommended actions

Return the result as JSON."""

CLASSIFY_CONTENT_TEMPLATE = """Classify the following email content:

{content}

Possible classes:
- normal: legitimate business email
- marketing: promotional content
- spam: unsolicited spam
- phishing: phishing attempt
- malware: malware delivery
- bec: business email compromise
- scam: scam or fraud

Return the most likely class and a confidence score."""


def format_analyze_prompt(
    mail_from: str | None,
    rcpt_to: list[str],
    subject: str | None,
    protocol: str,
    content_preview: str,
) -> str:
    """Format the email-analysis prompt."""
    return ANALYZE_EMAIL_TEMPLATE.format(
        mail_from=mail_from or "Unknown",
        rcpt_to=", ".join(rcpt_to) if rcpt_to else "Unknown",
        subject=subject or "No subject",
        protocol=protocol,
        content_preview=content_preview[:2000] if content_preview else "No content",
    )
