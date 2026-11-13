"""Release scope must be checked against tracked files, not ignore rules."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_docs", ROOT / "scripts/check_release_docs.py")
DOCS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCS)


class ReleaseDocumentation(unittest.TestCase):
    def check(self, files, approved):
        return DOCS.validate_documents(set(files), files, approved)

    def test_public_docs_and_relative_links_pass(self):
        files = {"README.md": "[Update](UPDATING.md#steps)", "UPDATING.md": "# Steps"}
        self.assertEqual(self.check(files, list(files)), [])

    def test_unapproved_site_page_fails_even_without_navigation(self):
        errors = self.check({"README.md": "# Public", "site/private-notes.md": "# Notes"}, ["README.md"])
        self.assertTrue(any("unapproved document" in error for error in errors))

    def test_force_added_private_docs_fail_even_if_allowlisted(self):
        for path in ("docs/reviews/release.md", "docs/decisions/decision.md", "AGENTS.md",
                     ".agents/skills/example/SKILL.md", "crates/engine/EVALUATION_RESULTS.md"):
            with self.subTest(path=path):
                errors = self.check({path: "# Private"}, [path])
                self.assertTrue(any("private file" in error for error in errors))

    def test_links_to_removed_docs_fail(self):
        errors = self.check({"README.md": "[Report](docs/review.md)"}, ["README.md"])
        self.assertTrue(any("unpublished document" in error for error in errors))

    def test_environment_specific_instructions_fail(self):
        for content in ("ssh root@198.51.100.7", "/Users/example/private/project/"):
            with self.subTest(content=content):
                self.assertTrue(self.check({"README.md": content}, ["README.md"]))
        self.assertEqual(self.check({"README.md": "ssh root@<build-server>"}, ["README.md"]), [])

    def test_stale_and_duplicate_manifest_entries_fail(self):
        errors = self.check({"README.md": "# Public"}, ["README.md", "README.md", "missing.md"])
        self.assertTrue(any("duplicate" in error for error in errors))
        self.assertTrue(any("absent" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
