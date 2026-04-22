"""Tests for VtScraper pure functions: _build_vt_url, _extract_from_api_responses."""

from __future__ import annotations

import hashlib

import pytest

from vigilyx_ai.scraper import VtScraper
from tests.conftest import make_vt_api_response


@pytest.fixture()
def scraper():
    return VtScraper()


# =====================================================================
# _build_vt_url
# =====================================================================


class TestBuildVtUrl:
    """~5 cases for _build_vt_url."""

    def test_domain_type(self, scraper):
        url, vt_hash = scraper._build_vt_url("example.com", "domain")
        assert url == "https://www.virustotal.com/gui/domain/example.com"
        assert vt_hash == ""

    def test_ip_type(self, scraper):
        url, vt_hash = scraper._build_vt_url("1.2.3.4", "ip")
        assert url == "https://www.virustotal.com/gui/ip-address/1.2.3.4"
        assert vt_hash == ""

    def test_url_type_hashed(self, scraper):
        indicator = "https://evil.com/phish"
        url, vt_hash = scraper._build_vt_url(indicator, "url")
        # VT normalizes: append "/" then SHA-256
        expected_hash = hashlib.sha256((indicator + "/").encode()).hexdigest()
        assert vt_hash == expected_hash
        assert expected_hash in url
        assert url == f"https://www.virustotal.com/gui/url/{expected_hash}"

    def test_url_type_already_trailing_slash(self, scraper):
        indicator = "https://evil.com/"
        url, vt_hash = scraper._build_vt_url(indicator, "url")
        expected_hash = hashlib.sha256(indicator.encode()).hexdigest()
        assert vt_hash == expected_hash

    def test_hash_type(self, scraper):
        h = "abc123def456"
        url, vt_hash = scraper._build_vt_url(h, "hash")
        assert url == f"https://www.virustotal.com/gui/file/{h}"
        assert vt_hash == ""


# =====================================================================
# _extract_from_api_responses
# =====================================================================


class TestExtractFromApiResponses:
    """~7 cases for _extract_from_api_responses."""

    def test_clean_result(self, scraper):
        resp = make_vt_api_response(malicious=0, harmless=60, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "example.com", "domain")
        assert result is not None
        assert result.success is True
        assert result.verdict == "clean"
        assert result.malicious_count == 0

    def test_suspicious_result(self, scraper):
        resp = make_vt_api_response(malicious=2, harmless=58, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "suspicious.com", "domain")
        assert result is not None
        assert result.verdict == "suspicious"
        assert result.malicious_count == 2

    def test_malicious_result_by_count(self, scraper):
        resp = make_vt_api_response(malicious=5, harmless=55, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "evil.com", "domain")
        assert result is not None
        assert result.verdict == "malicious"
        assert result.malicious_count == 5

    def test_malicious_result_by_ratio(self, scraper):
        # 30% ratio → malicious
        resp = make_vt_api_response(malicious=21, harmless=39, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "evil.com", "domain")
        assert result is not None
        assert result.verdict == "malicious"

    def test_nested_data_structure(self, scraper):
        resp = make_vt_api_response(malicious=0, harmless=60, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "example.test", "domain")
        assert result is not None
        assert result.success is True

    def test_flat_data_structure(self, scraper):
        resp = make_vt_api_response(malicious=3, harmless=57, undetected=10, nested=False)
        result = scraper._extract_from_api_responses([resp], "example.test", "domain")
        assert result is not None
        assert result.success is True
        assert result.malicious_count == 3

    def test_empty_responses_returns_none(self, scraper):
        result = scraper._extract_from_api_responses([], "example.test", "domain")
        assert result is None

    def test_confidence_calculation_clean(self, scraper):
        resp = make_vt_api_response(malicious=0, harmless=60, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "example.test", "domain")
        assert result is not None
        # ratio=0, clean: confidence = max(0.5, 1.0 - 0.0) = 1.0
        assert result.confidence == pytest.approx(1.0)

    def test_confidence_calculation_malicious(self, scraper):
        # malicious=21, total=70, ratio=0.3
        resp = make_vt_api_response(malicious=21, harmless=39, undetected=10, nested=True)
        result = scraper._extract_from_api_responses([resp], "evil.com", "domain")
        assert result is not None
        # confidence = min(0.5 + 0.3, 1.0) = 0.8
        assert result.confidence == pytest.approx(0.8, abs=0.05)
