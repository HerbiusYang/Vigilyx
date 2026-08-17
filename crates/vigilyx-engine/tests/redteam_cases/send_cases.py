#!/usr/bin/env python3
"""Send red-team .eml cases to a VIGILYX MTA endpoint and report dispositions.

Usage: python3 send_cases.py <host> <port> [case_dir]

For each case: EHLO, MAIL FROM, RCPT TO (corp.internal recipient), DATA,
then print the final SMTP reply. 250 = accepted or quarantined-with-250,
550 = rejected, 451 = tempfail.
"""
import glob
import os
import smtplib
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25
CASE_DIR = sys.argv[3] if len(sys.argv) > 3 else os.path.dirname(os.path.abspath(__file__))

MAIL_FROM = "sender@partner-external.com"
RCPT_TO = "employee@corp.internal"


def send_one(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()
    # Normalize mixed line endings to CRLF for the wire (bare LF is rejected
    # by the MTA's anti-smuggling CRLF enforcement).
    raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    try:
        with smtplib.SMTP(HOST, PORT, timeout=30) as smtp:
            smtp.ehlo("redteam-client.test")
            smtp.sendmail(MAIL_FROM, [RCPT_TO], raw)
        return "250 OK (delivered or quarantined)"
    except smtplib.SMTPRecipientsRefused as e:
        return f"RECIPIENTS_REFUSED {e.recipients}"
    except smtplib.SMTPSenderRefused as e:
        return f"SENDER_REFUSED {e.smtp_code} {e.smtp_error.decode(errors='replace')[:120]}"
    except smtplib.SMTPDataError as e:
        return f"DATA_REPLY {e.smtp_code} {e.smtp_error.decode(errors='replace')[:160]}"
    except smtplib.SMTPException as e:
        return f"SMTP_ERROR {type(e).__name__}: {str(e)[:160]}"
    except (socket.timeout, ConnectionError, OSError) as e:
        return f"CONN_ERROR {type(e).__name__}: {str(e)[:120]}"


def main():
    cases = sorted(glob.glob(os.path.join(CASE_DIR, "*.eml")))
    print(f"target {HOST}:{PORT}, {len(cases)} cases, from={MAIL_FROM} to={RCPT_TO}")
    results = {}
    for path in cases:
        name = os.path.basename(path)
        outcome = send_one(path)
        results[name] = outcome
        print(f"{name:42s} => {outcome}")
    print("\nsummary:")
    for name, outcome in results.items():
        tag = "550-REJECTED" if outcome.startswith("DATA_REPLY 550") or "REFUSED" in outcome else (
            "451-TEMPFAIL" if "451" in outcome else "250-ACCEPTED")
        print(f"  {tag:14s} {name}")


if __name__ == "__main__":
    main()
