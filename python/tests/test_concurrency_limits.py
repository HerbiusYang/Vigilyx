"""SEC-22 tests: inference and VT-scrape concurrency limits."""

import asyncio
import threading
import time
import unittest

import vigilyx_ai.nlp_phishing as nlp_phishing
from vigilyx_ai.nlp_phishing import ModelManager, NLPPhishingResult
from vigilyx_ai.scraper import VtScraper
from vigilyx_ai.vt_models import VtScrapeResponse


class PredictConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_predict_respects_inference_semaphore(self):
        manager = ModelManager()
        manager._finetuned_model = object()
        manager._inference_semaphore = asyncio.Semaphore(1)

        active = 0
        max_active = 0
        counter_lock = threading.Lock()

        def fake_predict(text: str) -> NLPPhishingResult:
            nonlocal active, max_active
            with counter_lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with counter_lock:
                active -= 1
            return NLPPhishingResult(
                is_phishing=False, threat_level="safe", confidence=0.1,
            )

        manager._predict_finetuned = fake_predict

        results = await asyncio.gather(
            *(manager.predict("hello", "en") for _ in range(4))
        )

        self.assertEqual(len(results), 4)
        self.assertEqual(max_active, 1)

    async def test_predict_semaphore_default_limit(self):
        manager = ModelManager()
        self.assertIsInstance(manager._inference_semaphore, asyncio.Semaphore)
        self.assertEqual(manager._inference_semaphore._value, 4)

    async def test_predict_times_out_stuck_inference(self):
        manager = ModelManager()
        manager._finetuned_model = object()
        original_timeout = nlp_phishing._INFERENCE_TIMEOUT_SECS
        nlp_phishing._INFERENCE_TIMEOUT_SECS = 0.01
        manager._predict_finetuned = lambda _text: time.sleep(0.05)
        try:
            with self.assertRaises(asyncio.TimeoutError):
                await manager.predict("hello", "en")
        finally:
            nlp_phishing._INFERENCE_TIMEOUT_SECS = original_timeout


class ScrapeConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_scrape_respects_semaphore(self):
        scraper = VtScraper()
        scraper._scrape_semaphore = asyncio.Semaphore(1)

        active = 0
        max_active = 0

        async def fake_ensure_browser():
            return None

        async def fake_do_scrape(indicator, indicator_type):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.02)
            active -= 1
            return VtScrapeResponse(success=True)

        scraper._ensure_browser = fake_ensure_browser
        scraper._do_scrape = fake_do_scrape

        results = await asyncio.gather(
            *(scraper.scrape("example.com", "domain") for _ in range(3))
        )

        self.assertTrue(all(r.success for r in results))
        self.assertEqual(max_active, 1)

    async def test_scrape_semaphore_default_limit(self):
        scraper = VtScraper()
        self.assertIsInstance(scraper._scrape_semaphore, asyncio.Semaphore)
        self.assertEqual(scraper._scrape_semaphore._value, 2)


if __name__ == "__main__":
    unittest.main()
