#!/usr/bin/env python3
"""Test the migration's login trigger in an isolated, disposable PostgreSQL.

Run on the remote build host, passing an already available PostgreSQL 17 image:
    python3 scripts/test-login-hourly-trigger.py --image <image-id>
No ports, host data directories, or application credentials are used.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Locally available PostgreSQL 17 image")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / "crates/vigilyx-db/src/infra/migrate.rs").read_text()
    fixture = (root / "crates/vigilyx-db/tests/external_login_trigger.sql").read_text()
    functions = []
    for function in ("vigilyx_login_hourly_delta", "trg_external_login_hourly_fn"):
        match = re.search(
            r"CREATE OR REPLACE FUNCTION " + function + r"\(.*?\$\$ LANGUAGE plpgsql",
            source,
            re.S,
        )
        if match is None:
            raise RuntimeError(f"Migration function not found: {function}")
        functions.append(match.group(0) + ";")

    subprocess.run(["docker", "image", "inspect", args.image], check=True, capture_output=True)
    name = "vigilyx-login-trigger-test-" + uuid.uuid4().hex[:12]
    subprocess.run(
        ["docker", "run", "--rm", "--pull=never", "-d", "--name", name,
         "--network", "none", "--memory", "512m", "--cpus", "2",
         "--tmpfs", "/var/lib/postgresql/data:size=256m",
         "-e", "POSTGRES_HOST_AUTH_METHOD=trust", args.image],
        check=True, capture_output=True,
    )
    try:
        for _ in range(30):
            ready = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-U", "postgres"],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Disposable PostgreSQL did not become ready")
        setup = """
BEGIN;
CREATE TABLE sessions(id text PRIMARY KEY, started_at_ts timestamptz,
    protocol text, auth_info jsonb, client_ip text);
CREATE TABLE external_login_hourly(hour_start timestamptz, protocol text,
    login_count bigint, success_count bigint, failed_count bigint,
    PRIMARY KEY(hour_start, protocol));
CREATE TABLE external_login_hourly_sources(hour_start timestamptz, client_ip text,
    PRIMARY KEY(hour_start, client_ip));
"""
        trigger = """
CREATE TRIGGER trg_external_login_hourly AFTER INSERT OR DELETE OR UPDATE OF
    started_at_ts, protocol, auth_info, client_ip ON sessions
    FOR EACH ROW EXECUTE FUNCTION trg_external_login_hourly_fn();
"""
        result = subprocess.run(
            ["docker", "exec", "-i", name, "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-At"],
            input=setup + "\n".join(functions) + trigger + fixture + "ROLLBACK;",
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode:
            raise RuntimeError(result.stderr)
        print(json.dumps({"passed": True, "test": "external_login_trigger"}))
    finally:
        subprocess.run(["docker", "stop", "-t", "5", name], check=True, capture_output=True)


if __name__ == "__main__":
    main()
