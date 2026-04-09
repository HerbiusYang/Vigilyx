"""
VirusTotal Playwright scraper.

Core behavior mirrors the validated strategy in `scripts/virus_total.py`:
- `domcontentloaded` plus smart polling instead of `networkidle`
- immediate exit once `last_analysis_results` appears
- per-indicator VT API interception keywords
- JS-fetch fallback after polling timeout
- basic anti-detection tweaks for browser fingerprinting
"""

import asyncio
import hashlib
import logging
import os
import re
from typing import Optional
from urllib.parse import urlparse

from .vt_models import VtScrapeResponse

logger = logging.getLogger(__name__)

# VT page URL templates (without the `/detection` suffix)
VT_DOMAIN_URL = "https://www.virustotal.com/gui/domain/{indicator}"
VT_IP_URL = "https://www.virustotal.com/gui/ip-address/{indicator}"
VT_URL_URL = "https://www.virustotal.com/gui/url/{hash}"
VT_HASH_URL = "https://www.virustotal.com/gui/file/{indicator}"

# VT internal API path keywords by indicator type
API_KEYWORDS: dict[str, str] = {
    "domain": "/ui/domains/",
    "ip": "/ui/ip_addresses/",
    "url": "/ui/urls/",
    "hash": "/ui/files/",
}

# Fallback JS-fetch path templates
JS_FETCH_PATHS: dict[str, str] = {
    "domain": "/ui/domains/{indicator}",
    "ip": "/ui/ip_addresses/{indicator}",
    "url": "/ui/urls/{vt_hash}",
    "hash": "/ui/files/{indicator}",
}

# Timeout configuration
PAGE_TIMEOUT_MS = 8000    # Page navigation timeout (usually 3-5s through a proxy)
POLL_INTERVAL_S = 0.5     # Polling interval
POLL_MAX_ROUNDS = 8       # At most 8 rounds = 4s

# Anti-detection initialization script
ANTI_DETECT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => false });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
window.chrome = { runtime: {} };
"""


def _parse_proxy_from_env() -> Optional[dict]:
    """Parse proxy configuration from HTTPS_PROXY / https_proxy for Playwright."""
    proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") \
        or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if not proxy_url:
        return None

    parsed = urlparse(proxy_url)
    proxy_cfg: dict = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
    if parsed.username:
        proxy_cfg["username"] = parsed.username
    if parsed.password:
        proxy_cfg["password"] = parsed.password

    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    if no_proxy:
        proxy_cfg["bypass"] = no_proxy

    return proxy_cfg


class VtScraper:
    """VirusTotal page scraper with a shared browser instance."""

    def __init__(self):
        self._browser = None
        self._context = None
        self._lock = asyncio.Lock()
        self._playwright = None

    async def _ensure_browser(self):
        """Lazily initialize the browser instance."""
        if self._browser is not None and self._browser.is_connected():
            return

        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return

            await self._cleanup_browser()

            from playwright.async_api import async_playwright

            proxy_cfg = _parse_proxy_from_env()

            self._playwright = await async_playwright().start()
            # SEC-L05: --no-sandbox is required in Docker containers without user namespaces.
            # Risk accepted: container runs as non-root user 'vigilyx' (SEC-C01), limiting blast radius.
            # --disable-dev-shm-usage: required in Docker (shared memory too small for Chromium).
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                proxy=proxy_cfg,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            self._context = await self._browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/133.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
            )
            await self._context.add_init_script(ANTI_DETECT_SCRIPT)
            if proxy_cfg:
                logger.info("Playwright browser initialized (proxy=%s)", proxy_cfg["server"])
            else:
                logger.info("Playwright browser initialized (no proxy)")

    async def _cleanup_browser(self):
        """Safely clean up browser resources."""
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        self._browser = None
        self._context = None
        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._playwright = None

    async def close(self):
        """Close the browser instance."""
        await self._cleanup_browser()

    # URL building

    def _build_vt_url(self, indicator: str, indicator_type: str) -> tuple[str, str]:
        """
        Build the VT page URL.

        Returns `(vt_page_url, vt_hash)`. `vt_hash` is only populated for URL lookups.
        """
        if indicator_type == "domain":
            return VT_DOMAIN_URL.format(indicator=indicator), ""
        elif indicator_type == "ip":
            return VT_IP_URL.format(indicator=indicator), ""
        elif indicator_type == "url":
            # VT URL lookups require a SHA-256 hash; normalize by appending `/`.
            normalized = indicator if indicator.endswith("/") else indicator + "/"
            vt_hash = hashlib.sha256(normalized.encode()).hexdigest()
            return VT_URL_URL.format(hash=vt_hash), vt_hash
        elif indicator_type == "hash":
            return VT_HASH_URL.format(indicator=indicator), ""
        else:
            return VT_DOMAIN_URL.format(indicator=indicator), ""

    # Main entrypoint

    async def scrape(self, indicator: str, indicator_type: str) -> VtScrapeResponse:
        """Scrape VT detection data, with browser crash recovery."""
        try:
            await self._ensure_browser()
            return await self._do_scrape(indicator, indicator_type)
        except Exception as e:
            err_str = str(e).lower()
            if any(kw in err_str for kw in ("browser has been closed", "target closed",
                                             "connection refused", "not connected")):
                logger.warning("Browser crashed, restarting: %s", e)
                await self._cleanup_browser()
                try:
                    await self._ensure_browser()
                    return await self._do_scrape(indicator, indicator_type)
                except Exception as retry_err:
                    logger.error("VT scrape retry failed for %s: %s", indicator, retry_err)
                    return VtScrapeResponse(success=False, error="SCRAPE_FAILED")

            logger.error("VT scrape failed for %s (%s): %s", indicator, indicator_type, e)
            return VtScrapeResponse(success=False, error="SCRAPE_FAILED")

    # Core scraping flow

    async def _do_scrape(self, indicator: str, indicator_type: str) -> VtScrapeResponse:
        vt_url, vt_hash = self._build_vt_url(indicator, indicator_type)
        api_keyword = API_KEYWORDS.get(indicator_type, "/ui/")
        logger.info("Scraping VT: %s (keyword: %s)", vt_url, api_keyword)

        page = await self._context.new_page()
        api_responses: list[dict] = []
        got_main_data = False

        async def handle_response(response):
            """
            Intercept VT internal API responses.

            Strategy: match by type-specific keyword plus JSON and a broad
            `virustotal.com` fallback.
            """
            nonlocal got_main_data
            req_url = response.url
            ct = response.headers.get("content-type", "")

            if api_keyword in req_url or ("json" in ct and "virustotal.com" in req_url):
                try:
                    body = await response.json()
                    api_responses.append({"url": req_url, "data": body})
                    # Stop polling as soon as the main analysis payload arrives.
                    inner = body.get("data", {})
                    if isinstance(inner, dict):
                        attrs = inner.get("attributes", {})
                        if "last_analysis_results" in attrs:
                            got_main_data = True
                except Exception:
                    pass

        page.on("response", handle_response)

        try:
            # Use `domcontentloaded` instead of `networkidle`.
            # `networkidle` waits for all requests to stop, which often never
            # happens because of GA/reCAPTCHA/background requests.
            await page.goto(vt_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)

            # Poll every 0.5s and exit immediately once API data is available.
            for i in range(POLL_MAX_ROUNDS):
                if got_main_data:
                    logger.info("API data received after %.1fs", (i + 1) * POLL_INTERVAL_S)
                    break
                await asyncio.sleep(POLL_INTERVAL_S)
            else:
                logger.info("Polling timeout, trying JS fetch fallback...")

            # Fallback: call the VT internal API directly from page JS after
            # polling times out without usable data.
            if not got_main_data:
                await self._js_fetch_fallback(
                    page, api_responses, indicator, indicator_type, vt_hash
                )

            # Prefer intercepted API responses if available.
            result = self._extract_from_api_responses(api_responses, indicator, indicator_type)
            if result is not None:
                return result

            # Final fallback: extract the visible counters from the DOM.
            result = await self._extract_from_dom(page, indicator, indicator_type)
            if result is not None:
                return result

            return VtScrapeResponse(
                success=False,
                error="No detection data found in VT page",
            )

        finally:
            await page.close()

    # JS-fetch fallback

    async def _js_fetch_fallback(
        self,
        page,
        api_responses: list[dict],
        indicator: str,
        indicator_type: str,
        vt_hash: str,
    ):
        """Fetch the VT internal API directly from page JS after polling times out."""
        path_template = JS_FETCH_PATHS.get(indicator_type)
        if not path_template:
            return

        js_path = path_template.format(indicator=indicator, vt_hash=vt_hash)

        try:
            # Pass the path as a parameter to avoid string-concatenation injection issues.
            js_result = await page.evaluate("""
            async (path) => {
                try {
                    const r = await fetch(path);
                    return { ok: true, status: r.status, data: await r.json() };
                } catch(e) { return { ok: false, err: e.toString() }; }
            }
            """, js_path)
            if js_result.get("ok") and js_result.get("status") == 200:
                api_responses.append({"url": "[JS fetch]", "data": js_result["data"]})
                logger.info("JS fetch fallback succeeded for %s", indicator)
        except Exception as e:
            logger.debug("JS fetch fallback failed: %s", e)

    # API response parsing

    def _extract_from_api_responses(
        self,
        api_responses: list[dict],
        indicator: str,
        indicator_type: str,
    ) -> Optional[VtScrapeResponse]:
        """
        Extract detection data from intercepted VT API responses.

        Lookup order mirrors `scripts/virus_total.py::_parse_analysis`:
        1. `data.data.attributes` for the standard nested shape
        2. `data.attributes` for flatter VT responses
        """
        for resp in api_responses:
            data = resp.get("data", {})
            if not isinstance(data, dict):
                continue

            # Path 1: data.data.attributes
            attrs = None
            inner = data.get("data", {})
            if isinstance(inner, dict):
                attrs = inner.get("attributes", {})

            # Fallback path 2: data.attributes
            if not attrs or "last_analysis_results" not in attrs:
                candidate = data.get("attributes", {})
                if isinstance(candidate, dict) and "last_analysis_results" in candidate:
                    attrs = candidate

            if not attrs or "last_analysis_results" not in attrs:
                continue

            # Extract summary counters.
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            # Collect engines flagged as malicious/malware/suspicious.
            results = attrs.get("last_analysis_results", {})
            malicious_engines = [
                f"{eng}: {v.get('result', 'malicious')}"
                for eng, v in sorted(results.items())
                if v.get("category") in ("malicious", "malware", "suspicious")
            ]

            # Derive a coarse verdict from the malicious ratio.
            if total > 0:
                ratio = malicious / total
            else:
                ratio = 0.0

            if ratio >= 0.3 or malicious >= 5:
                verdict = "malicious"
                confidence = min(0.5 + ratio, 1.0)
            elif ratio >= 0.1 or malicious >= 2:
                verdict = "suspicious"
                confidence = min(0.3 + ratio, 0.8)
            else:
                verdict = "clean"
                confidence = max(0.5, 1.0 - ratio)

            engines_str = ", ".join(malicious_engines[:10])
            details = f"engines: {engines_str}" if engines_str else ""

            logger.info(
                "VT result: %s -> %s (malicious=%d/%d, flagged_engines=%d)",
                indicator, verdict, malicious, total, len(malicious_engines),
            )

            return VtScrapeResponse(
                success=True,
                verdict=verdict,
                confidence=confidence,
                malicious_count=malicious,
                total_engines=total,
                details=details,
            )

        return None

    # DOM fallback extraction

    async def _extract_from_dom(
        self,
        page,
        indicator: str,
        indicator_type: str,
    ) -> Optional[VtScrapeResponse]:
        """Fallback path: parse detection counters from the rendered DOM."""
        try:
            content = await page.text_content("body")
            if content is None:
                return None

            match = re.search(r"(\d+)\s*/\s*(\d+)\s*(?:security vendors|engines)", content)
            if match:
                malicious = int(match.group(1))
                total = int(match.group(2))

                if total > 0:
                    ratio = malicious / total
                else:
                    ratio = 0.0

                if ratio >= 0.3 or malicious >= 5:
                    verdict = "malicious"
                elif ratio >= 0.1 or malicious >= 2:
                    verdict = "suspicious"
                else:
                    verdict = "clean"

                return VtScrapeResponse(
                    success=True,
                    verdict=verdict,
                    confidence=min(0.5 + ratio, 1.0) if verdict == "malicious" else 0.5,
                    malicious_count=malicious,
                    total_engines=total,
                    details="extracted from DOM",
                )
        except Exception as e:
            logger.warning("DOM extraction failed: %s", e)

        return None


# Global singleton

_scraper: Optional[VtScraper] = None


def get_scraper() -> VtScraper:
    """Return the shared global `VtScraper` instance."""
    global _scraper
    if _scraper is None:
        _scraper = VtScraper()
    return _scraper
