"""Verify audit exceptions cannot conceal an active vulnerable dependency."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FAKE_CARGO = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['AUDIT_TEST_LOG'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\n')
if sys.argv[1] == 'tree':
    print(os.environ.get('AUDIT_TEST_TREE', 'sqlx-postgres v0.9.0'))
    sys.exit(int(os.environ.get('AUDIT_TEST_TREE_STATUS', '0')))
sys.exit(int(os.environ.get('AUDIT_TEST_STATUS', '0')))
'''


class CargoAuditGuards(unittest.TestCase):
    def run_audit(self, lock='', **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / 'cargo'
            cargo.write_text(FAKE_CARGO)
            cargo.chmod(0o755)
            (root / 'Cargo.lock').write_text(lock)
            log = root / 'calls.jsonl'
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       AUDIT_TEST_LOG=str(log), **settings)
            result = subprocess.run(['bash', str(ROOT / 'scripts/cargo-audit.sh')],
                                    cwd=root, env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_lock_only_sqlite_has_one_specific_exception(self):
        result, calls = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], ['tree', '--locked', '--workspace', '--all-features',
                                    '--target', 'all', '--prefix', 'none', '--color', 'never'])
        self.assertEqual(calls[1], ['audit', '--ignore', 'RUSTSEC-2026-0459'])

    def test_active_sqlite_blocks_exception(self):
        for name in ('libsqlite3-sys', 'sqlx-sqlite', 'rusqlite'):
            with self.subTest(name=name):
                result, calls = self.run_audit(AUDIT_TEST_TREE=f'{name} v0.37.0')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)
                self.assertIn('SQLite is active', result.stderr)

    def test_resolution_and_audit_failures_propagate(self):
        result, calls = self.run_audit(AUDIT_TEST_TREE_STATUS='7')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(len(calls), 1)
        result, calls = self.run_audit(AUDIT_TEST_STATUS='9')
        self.assertEqual(result.returncode, 9)
        self.assertEqual(len(calls), 2)

    def test_rsa_reintroduction_blocks_audit(self):
        result, calls = self.run_audit(lock='[[package]]\nname = "rsa"\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
