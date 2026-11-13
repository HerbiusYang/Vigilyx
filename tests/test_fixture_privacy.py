"""Privacy gate contracts for shipped synthetic fixture identifiers."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_test_fixture_privacy.py"
SPEC = importlib.util.spec_from_file_location("fixture_privacy", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class FixturePrivacy(unittest.TestCase):
    def test_public_provider_literals_are_exact_exceptions(self):
        for domain in ("npmjs.com", "crowdstrike.com", "msrc.onmicrosoft.com"):
            with self.subTest(domain=domain):
                self.assertTrue(guard.domain_allowed(domain))
                self.assertFalse(guard.domain_allowed(domain + ".unknown.zz"))
        self.assertFalse(guard.domain_allowed("unlisted-recipient.zz"))

    def test_synthetic_financial_identifier_is_accepted(self):
        self.assertEqual(guard.scan_file(guard.ROOT / "crates/tests/synthetic.eml", "SWIFT: TSTBUS44"), [])

    def test_unqualified_institution_identifier_is_rejected(self):
        findings = guard.scan_file(guard.ROOT / "crates/tests/synthetic.eml", "SWIFT: ABCDUS44")
        self.assertTrue(any("synthetic institution prefix" in finding for finding in findings))


if __name__ == "__main__":
    unittest.main()
