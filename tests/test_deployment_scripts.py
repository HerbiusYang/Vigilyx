"""Deployment regressions. Docker/SSH mutations are replaced with local fakes."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("deployment_verifier", ROOT / "scripts/verify-deployment.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

FAKE_TOOL = r'''#!/usr/bin/env python3
import json,os,pathlib,signal,sys
tool=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['FAKE_LOG'],'a') as log:log.write(json.dumps([tool,*args])+'\n')
if tool=='ssh':
 command=args[-1]
 if "stat -c '%a'" in command:print('600')
 elif '(?<=^VIGILYX_MODE=)' in command:print(os.environ.get('FAKE_MODE','mirror'))
 elif 'docker exec -i vigilyx-postgres' in command:print(os.environ.get('FAKE_DB_MODE',''))
 elif "cat '/tmp/vigilyx_test_status'" in command:print('0')
 elif '(?<=^AI_ENABLED=)' in command or '(?<=^CLAMAV_ENABLED=)' in command:print('false')
 elif '/api/health/ready' in command:print('{"status":"ready"}')
 sys.exit(0)
if tool=='rsync':sys.exit(0)
if args[:2]==['container','inspect']:
 name=args[-1]
 print('true' if name in json.loads(os.environ.get('FAKE_RUNNING','[]')) else 'false')
 sys.exit(0)
failure=os.environ.get('FAKE_FAIL','')
if args and args[0]=='compose':
 if 'up' in args:
  if failure=='signal':os.kill(os.getppid(),signal.SIGHUP)
  if failure=='dependencies':sys.exit(7)
 elif args[-1]==failure:sys.exit(7)
elif args and args[0]=='stop' and failure=='stop:'+args[-1]:sys.exit(7)
elif args and args[0]=='start' and failure=='start:'+args[-1]:sys.exit(7)
'''


class DeploymentScripts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("ssh", "rsync", "docker"):
            tool = self.bin / name
            tool.write_text(FAKE_TOOL)
            tool.chmod(0o755)
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        FAKE_LOG=str(self.log), VIGILYX_SERVER="example.test",
                        VIGILYX_LOCAL_DIR=str(self.root) + "/", VIGILYX_REMOTE_DIR="/srv/vigilyx")
        (self.root / ".nvmrc").write_text("24.19.0\n")
        (self.root / "frontend").mkdir()
        (self.root / "frontend/package.json").write_text('{"packageManager":"npm@12.0.2"}')
        shutil.copy2(ROOT / "deploy.sh", self.root / "deploy.sh")

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def deploy(self, options, mode="mirror"):
        return subprocess.run(["bash", "deploy.sh", *options], cwd=self.root,
                              env=dict(self.env, FAKE_MODE=mode), text=True, capture_output=True, timeout=20)

    def test_component_migrations_require_new_api_binary(self):
        cases = [([], True, True), (["--backend"], True, True),
                 (["--frontend"], False, False), (["--sniffer"], False, True),
                 (["--config-only"], False, False),
                 (["--backend", "--config-only"], False, False),
                 (["--production", "--frontend"], True, True),
                 (["--mta"], True, True)]
        for options, migrate, rust_checks in cases:
            with self.subTest(options=options):
                self.log.write_text("")
                result = self.deploy(options)
                self.assertEqual(result.returncode, 0, result.stderr)
                commands = self.commands()
                remote = [c[-1] for c in commands if c[0] == "ssh"]
                reconcile = [c for c in remote if "bash scripts/reconcile-deployment.sh" in c]
                self.assertEqual(len(reconcile), 1)
                self.assertIn("'true'" if migrate else "'false'", reconcile[0])
                self.assertEqual(any("cargo clippy --workspace" in c for c in remote), rust_checks)
                self.assertTrue(any("python3 scripts/verify-deployment.py" in c for c in remote))
                self.assertFalse(any("apply-capture-host-tuning.sh" in c for c in remote))
                sync = next(c for c in commands if c[0] == "rsync")
                for protected in (".env", "deploy.conf", ".rollback/", "backups/"):
                    self.assertIn(protected, sync)

    def test_backend_honors_active_mta_mode(self):
        result = self.deploy(["--backend"], mode="mta")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = "\n".join(c[-1] for c in self.commands() if c[0] == "ssh")
        self.assertIn("cargo build --profile release-fast", commands)
        self.assertIn("-p vigilyx-mta", commands)
        self.assertNotIn("-p vigilyx-sniffer", commands)

    def test_backend_uses_database_mode_when_env_is_unset(self):
        self.env["FAKE_DB_MODE"] = "mta"
        result = self.deploy(["--backend"], mode="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Deployment mode: mta (source: db)", result.stdout)
        commands = "\n".join(c[-1] for c in self.commands() if c[0] == "ssh")
        self.assertIn("-p vigilyx-mta", commands)
        self.assertNotIn("-p vigilyx-sniffer", commands)

    def test_generator_does_not_overwrite_existing_env_and_exposes_memory_options(self):
        script = self.root / "scripts/generate-secrets.sh"
        script.parent.mkdir()
        shutil.copy2(ROOT / "scripts/generate-secrets.sh", script)
        envfile = self.root / "deploy/docker/.env"
        envfile.parent.mkdir(parents=True)
        original = "PG_SHARED_BUFFERS=8GB\nPG_EFFECTIVE_CACHE_SIZE=64GB\n"
        envfile.write_text(original)
        result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        preview = subprocess.run(["bash", str(script), "--print"], capture_output=True, text=True, check=True)
        self.assertIn("# PG_SHARED_BUFFERS=256MB", preview.stdout)
        self.assertIn("# PG_EFFECTIVE_CACHE_SIZE=512MB", preview.stdout)
        self.assertIn("# PG_MAINTENANCE_WORK_MEM=128MB", preview.stdout)
        self.assertEqual(envfile.read_text(), original)

    def reconcile(self, migrate=True, failure="", running=None):
        if running is None:
            running = ["vigilyx", "vigilyx-engine-standalone", "vigilyx-sniffer"]
        self.log.write_text("")
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/reconcile-deployment.sh"), str(migrate).lower()],
            cwd=self.root, env=dict(self.env, FAKE_FAIL=failure, FAKE_RUNNING=json.dumps(running)),
            text=True, capture_output=True, timeout=10,
        )
        commands = [c[1:] for c in self.commands() if c[0] == "docker"]
        return result, commands

    def test_pause_precedes_dependency_restart_and_restore_reverses_order(self):
        result, commands = self.reconcile()
        self.assertEqual(result.returncode, 0, result.stderr)
        pause = [i for i, c in enumerate(commands) if c[0] == "stop"]
        dependency = next(i for i, c in enumerate(commands) if c[0] == "compose" and "up" in c)
        self.assertLess(max(pause), dependency)
        self.assertIn("--wait", commands[dependency])
        self.assertEqual([c[-1] for c in commands if c[0] == "start"],
                         ["vigilyx", "vigilyx-engine-standalone", "vigilyx-sniffer"])

    def test_every_failure_restores_original_services(self):
        for failure in ("dependencies", "postgres-role-init", "postgres-migrate", "audit-bootstrap", "signal"):
            with self.subTest(failure=failure):
                result, commands = self.reconcile(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([c[-1] for c in commands if c[0] == "start"],
                                 ["vigilyx", "vigilyx-engine-standalone", "vigilyx-sniffer"])

    def test_partial_pause_failure_restores_stopped_capture(self):
        result, commands = self.reconcile(failure="stop:vigilyx-engine-standalone")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("compose", [c[0] for c in commands])
        self.assertEqual([c[-1] for c in commands if c[0] == "start"],
                         ["vigilyx-engine-standalone", "vigilyx-sniffer"])

    def test_restore_failure_is_not_reported_as_success(self):
        result, commands = self.reconcile(failure="start:vigilyx")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(["start", "vigilyx-sniffer"], commands)

    def test_component_reconcile_does_not_run_old_migrator(self):
        result, commands = self.reconcile(migrate=False, running=["vigilyx"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[-1] == "postgres-migrate" for c in commands))
        self.assertEqual([c[-1] for c in commands if c[0] == "start"], ["vigilyx"])

    def test_no_running_services_are_started_implicitly(self):
        result, commands = self.reconcile(running=[])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c[0] in ("start", "stop") for c in commands))


class DeploymentVerifier(unittest.TestCase):
    def test_config_mismatch_fails(self):
        config = {"services": {"postgres": {"command": ["postgres", "-c", "shared_buffers=8GB",
                  "-c", "effective_cache_size=64GB", "-c", "maintenance_work_mem=512MB", "-c", "log_lock_waits=on"]}}}
        with patch.object(VERIFY, "run", side_effect=[json.dumps(config), '{"matches":false}']):
            with self.assertRaisesRegex(RuntimeError, "differ from Compose"):
                VERIFY.postgres_settings()

    def test_backlog_must_recover_for_two_observations(self):
        clock = [0.0]
        def sleep(seconds): clock[0] += seconds
        snapshots = [{"email": {"lag": 900}}, {"email": {"lag": 50}}, {"email": {"lag": 0}}]
        with patch.object(VERIFY, "stream_groups", side_effect=snapshots), \
             patch.object(VERIFY.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(VERIFY.time, "sleep", side_effect=sleep), contextlib.redirect_stdout(io.StringIO()):
            result = VERIFY.wait_for_streams("unused", 10, 1, 100)
        self.assertEqual(result["email"]["lag"], 0)
        self.assertEqual(clock[0], 2)

    def test_stalled_backlog_fails_even_when_services_are_ready(self):
        clock = [0.0]
        def sleep(seconds): clock[0] += seconds
        with patch.object(VERIFY, "stream_groups", return_value={"email": {"lag": 9000}}), \
             patch.object(VERIFY.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(VERIFY.time, "sleep", side_effect=sleep), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "backlog did not recover"):
                VERIFY.wait_for_streams("unused", 2, 1, 100)

    def test_mta_does_not_wait_for_inactive_mirror_streams(self):
        with patch("sys.argv", ["verify-deployment.py", "--mode", "mta"]), \
             patch.object(VERIFY, "postgres_settings", return_value={}), \
             patch.object(VERIFY, "wait_for_streams") as wait, contextlib.redirect_stdout(io.StringIO()):
            VERIFY.main()
        wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
