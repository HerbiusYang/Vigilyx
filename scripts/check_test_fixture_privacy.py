#!/usr/bin/env python3
"""Reject customer-like identifiers in committed test fixtures.

Tests should use RFC-reserved domains, documentation IP ranges, and visibly
synthetic personal-data vectors. Public service domains are allowed only when
their literal spelling is part of the behavior under test (URL rewriting,
provider classification, or interoperability).
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = (ROOT / "crates", ROOT / "frontend", ROOT / "python")
TEXT_SUFFIXES = {".rs", ".py", ".ts", ".tsx", ".eml"}
RESERVED_DOMAIN_SUFFIXES = (".example", ".invalid", ".test", ".localhost")
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
FIXTURE_DOMAIN_MARKERS = {
    "acme",
    "attacker",
    "bank",
    "company",
    "corp",
    "domain",
    "evil",
    "example",
    "external",
    "fake",
    "fixture",
    "other",
    "padded",
    "random",
    "supplier",
    "tech",
    "test",
    "upper",
}
PUBLIC_INTEROP_SUFFIXES = (
    ".126.com",
    ".139.com",
    ".163.com",
    ".aliyuncs.com",
    ".amazonaws.com",
    ".apple.com",
    ".bcebos.com",
    ".cloudses.com",
    ".developer.huawei.com",
    ".foxmail.com",
    ".gmail.com",
    ".microsoft.com",
    ".microsoftonline.com",
    ".office.com",
    ".office365.com",
    ".openxmlformats.org",
    ".outlook.com",
    ".paypal.com",
    ".proofpoint.com",
    ".qq.com",
    ".swift.com",
    ".unionpay.com",
    ".weixin.qq.com",
    ".wecom.work",
    ".hundsun.com",
    ".hundsun.cn",
    ".lenovo.com",
    ".lenovo.com.cn",
)
PUBLIC_INTEROP_DOMAINS = {
    suffix.removeprefix(".") for suffix in PUBLIC_INTEROP_SUFFIXES
} | {
    "mail-online.nosdn.127.net",
    "hotmail.com",
    # Literal public sender identities used by provider-interoperability cases.
    "npmjs.com",
    "crowdstrike.com",
    "msrc.onmicrosoft.com",
    "wecom.work",
    "hundsun.com",
    "hundsun.cn",
    "lenovo.com",
    "lenovo.com.cn",
}
SYNTHETIC_MOBILE_NUMBERS = {
    "13000000000",
    "13600136000",
    "13800138000",
    "13900139000",
    "14700147000",
    "15000150000",
    "15100151000",
    "15200152000",
}

EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+\-]+@([A-Z0-9\-]+(?:\.[A-Z0-9\-]+)*\.[A-Z]{2,})\b"
)
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
MOBILE_RE = re.compile(r"(?<![0-9])1[3-9][0-9]{9}(?![0-9])")
IDENTITY_RE = re.compile(r"(?<![0-9])[0-9]{17}[0-9Xx](?![0-9])")
IDENTITY_CONTEXT_RE = re.compile(r"身份证|ID\s*(?:card|number)?|Customer\s+ID", re.I)
IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b", re.I)
IBAN_CONTEXT_RE = re.compile(
    r"IBAN|iban_mod97|find_ibans|is_valid_iban|请汇款至|汇款到|pay\s+to|wire\s+transfer",
    re.I,
)
BIC_RE = re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
BIC_CONTEXT_RE = re.compile(r"SWIFT|BIC|find_swift_codes", re.I)
ROUTING_RE = re.compile(r"(?:ABA|routing(?:\s+code)?)[^\n0-9]{0,20}([0-9]{9})", re.I)
BTC_RE = re.compile(r"\b(?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34}\b")
BTC_CONTEXT_RE = re.compile(r"bitcoin|btc|crypto|wallet", re.I)
SYNTHETIC_BIC_PREFIXES = {"CERT", "FILE", "PASS", "TEST", "TRUE", "TSTB"}
PROHIBITED_LEGACY_FIXTURES = {
    "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
    "021000021",
    "9111000071093109A",
    "BKCHCNBJ",
    "CH9300762011623852957",
    "CHASUS33",
    "DE89370400440532013000",
    "DEUTDEFF",
    "FR7630006000011234567890189",
    "GB29NWBK60161331926819",
    "HSBCHKHH",
    "NL91ABNA0417164300",
}


def is_test_path(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    parts = {part.lower() for part in relative.parts}
    name = path.name.lower()
    return (
        "tests" in parts
        or "test" in parts
        or name.endswith(".eml")
        or ".test." in name
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def test_text(path: Path, text: str) -> str | None:
    if is_test_path(path):
        return text
    if path.suffix == ".rs":
        marker = text.find("#[cfg(test)]")
        if marker >= 0:
            return text[marker:]
    return None


def domain_allowed(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    if (
        domain in RESERVED_DOMAINS
        or domain.endswith(RESERVED_DOMAIN_SUFFIXES)
        or any(domain.endswith(f".{reserved}") for reserved in RESERVED_DOMAINS)
        or domain.endswith((".internal", ".localdomain"))
    ):
        return True
    if domain in PUBLIC_INTEROP_DOMAINS or domain.endswith(PUBLIC_INTEROP_SUFFIXES):
        return True
    labels = re.split(r"[.\-]", domain)
    return len(labels[0]) == 1 or domain == "contoso.com" or any(
        marker in labels or any(marker in label for label in labels)
        for marker in FIXTURE_DOMAIN_MARKERS
    )


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_file(path: Path, text: str) -> list[str]:
    failures: list[str] = []
    relative = path.relative_to(ROOT)

    for match in EMAIL_RE.finditer(text):
        domain = match.group(1)
        if not domain_allowed(domain):
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                f"non-reserved test mailbox domain {domain!r}"
            )

    for match in IPV4_RE.finditer(text):
        nearby = text[max(0, match.start() - 40) : match.end() + 8]
        if "RFC" in nearby or "Section" in nearby:
            continue
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_global and not (
            address in ipaddress.ip_network("192.0.2.0/24")
            or address in ipaddress.ip_network("198.51.100.0/24")
            or address in ipaddress.ip_network("203.0.113.0/24")
            or address == ipaddress.ip_address("8.8.8.8")
            or address == ipaddress.ip_address("131.0.0.0")
            or address == ipaddress.ip_address("172.32.0.1")
        ):
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                f"non-documentation public test IP {address}"
            )

    for match in MOBILE_RE.finditer(text):
        value = match.group(0)
        if value not in SYNTHETIC_MOBILE_NUMBERS:
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                f"unapproved mobile-like test vector {value}"
            )

    for match in IDENTITY_RE.finditer(text):
        context = text[max(0, match.start() - 48) : match.end() + 48]
        if IDENTITY_CONTEXT_RE.search(context) and not match.group(0).startswith("000000"):
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                "identity-like test vector must use the invalid 000000 region"
            )

    for value in PROHIBITED_LEGACY_FIXTURES:
        offset = text.find(value)
        if offset >= 0:
            failures.append(
                f"{relative}:{line_number(text, offset)}: "
                f"real/public legacy identifier {value!r} must use a synthetic vector"
            )

    for match in IBAN_RE.finditer(text):
        context = text[max(0, match.start() - 64) : match.end() + 64]
        if not IBAN_CONTEXT_RE.search(context):
            continue
        value = match.group(0).upper()
        synthetic = (
            value[:2] in {"US", "XX"}
            or "TST" in value
            or set(value[4:]) <= {"0"}
        )
        if not synthetic:
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                "IBAN-like test vector must use TST or an unassigned all-zero BBAN"
            )

    for match in BIC_RE.finditer(text):
        context = text[max(0, match.start() - 48) : match.end() + 48]
        if not BIC_CONTEXT_RE.search(context):
            continue
        value = match.group(0).upper()
        if value[:4] not in SYNTHETIC_BIC_PREFIXES:
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                "BIC/SWIFT test vector must use an explicit synthetic institution prefix"
            )

    for match in ROUTING_RE.finditer(text):
        if match.group(1) not in {"000000000", "123456780"}:
            failures.append(
                f"{relative}:{line_number(text, match.start(1))}: "
                "routing-number test vector must use an explicit synthetic value"
            )

    for match in BTC_RE.finditer(text):
        context = text[max(0, match.start() - 48) : match.end() + 48]
        if BTC_CONTEXT_RE.search(context) and "Test" not in match.group(0):
            failures.append(
                f"{relative}:{line_number(text, match.start())}: "
                "wallet-like test vector must be visibly synthetic"
            )

    return failures


def main() -> int:
    failures: list[str] = []
    scanned = 0
    for root in SCAN_ROOTS:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            if any(part in {"node_modules", "dist", "target", ".venv"} for part in path.parts):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            scoped = test_text(path, content)
            if scoped is None:
                continue
            scanned += 1
            failures.extend(scan_file(path, scoped))

    if failures:
        print("Test fixture privacy check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"Test fixture privacy check passed ({scanned} files scanned).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
