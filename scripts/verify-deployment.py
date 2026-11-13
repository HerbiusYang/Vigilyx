#!/usr/bin/env python3
"""Read-only deployment checks for effective PostgreSQL settings and Stream lag."""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Deployment check command failed: {result.stderr[:300]}")
    return result.stdout


def postgres_settings():
    # Consume the resolved configuration in memory; it contains credentials and
    # must never be printed. Check exactly what the next Compose up would use.
    config = json.loads(run([
        "docker", "compose", "-f", "deploy/docker/docker-compose.yml", "config", "--format", "json",
    ]))
    command = config["services"]["postgres"]["command"]
    if isinstance(command, str):
        command = shlex.split(command)
    settings = dict(word.split("=", 1) for word in command if "=" in word)
    names = ("shared_buffers", "effective_cache_size", "maintenance_work_mem", "log_lock_waits")
    variables = [f"--set={name}={settings[name]}" for name in names]
    # psql variables are SQL-quoted through :'name'; do not interpolate values
    # into shell code or SQL literals.
    query = """
BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT json_build_object(
 'shared_buffers', current_setting('shared_buffers'),
 'effective_cache_size', current_setting('effective_cache_size'),
 'maintenance_work_mem', current_setting('maintenance_work_mem'),
 'log_lock_waits', current_setting('log_lock_waits'),
 'matches',
 pg_size_bytes(current_setting('shared_buffers'))=pg_size_bytes(:'shared_buffers') AND
 pg_size_bytes(current_setting('effective_cache_size'))=pg_size_bytes(:'effective_cache_size') AND
 pg_size_bytes(current_setting('maintenance_work_mem'))=pg_size_bytes(:'maintenance_work_mem') AND
 current_setting('log_lock_waits')::boolean=:'log_lock_waits'::boolean);
ROLLBACK;
"""
    # SQL arrives over stdin. The shell command only expands container-owned
    # PG identity variables; none of the expected settings are shell-quoted.
    result = run([
        "docker", "exec", "-i", "vigilyx-postgres", "sh", "-lc",
        'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"',
        "psql", *variables,
    ], input=query)
    actual = json.loads(result.strip())
    if not actual.pop("matches"):
        raise RuntimeError("Effective PostgreSQL settings differ from Compose; dependency recreation did not apply them")
    return actual


def stream_groups(env_file):
    values = {}
    for line in Path(env_file).read_text().splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition("=")
        parsed = shlex.split(value, comments=True)
        values[key.strip()] = parsed[0] if parsed else ""
    password = values.get("REDIS_API_PASSWORD")
    if not password:
        raise RuntimeError("REDIS_API_PASSWORD is required for Stream verification")
    env = dict(os.environ, REDISCLI_AUTH=password)
    result = {}
    for stream in ("vigilyx:stream:sessions", "vigilyx:stream:http_sessions"):
        raw = json.loads(run([
            "docker", "exec", "-e", "REDISCLI_AUTH", "vigilyx-redis", "valkey-cli",
            "--user", "vigilyx_api", "--no-auth-warning", "--json", "XINFO", "GROUPS", stream,
        ], env=env))
        if not isinstance(raw, list):
            raise RuntimeError(f"Cannot inspect consumer groups for {stream}")
        groups = [dict(zip(g[::2], g[1::2])) if isinstance(g, list) else g for g in raw]
        group = next((g for g in groups if g.get("name") == "vigilyx-engine"), None)
        if group is None or not isinstance(group.get("lag"), int):
            raise RuntimeError(f"Engine consumer group or measurable lag missing for {stream}")
        result[stream] = {"lag": group["lag"], "pending": group["pending"]}
    return result


def wait_for_streams(env_file, timeout, interval, max_lag):
    deadline = time.monotonic() + timeout
    consecutive = 0
    last_report = 0
    while True:
        groups = stream_groups(env_file)
        consecutive = consecutive + 1 if all(g["lag"] <= max_lag for g in groups.values()) else 0
        if consecutive >= 2:
            return groups
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Stream backlog did not recover within {timeout}s: {json.dumps(groups)}")
        if time.monotonic() - last_report >= 15:
            print(json.dumps({"waiting_for_streams": groups}), flush=True)
            last_report = time.monotonic()
        time.sleep(min(interval, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("mirror", "mta"), required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--interval", type=float, default=3)
    parser.add_argument("--max-lag", type=int, default=100)
    args = parser.parse_args()
    if args.timeout <= 0 or args.interval <= 0 or args.max_lag < 0:
        parser.error("timeout/interval must be positive and max-lag nonnegative")
    report = {"postgres_settings": postgres_settings()}
    if args.mode == "mirror":
        report["streams"] = wait_for_streams("deploy/docker/.env", args.timeout, args.interval, args.max_lag)
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError, OSError) as error:
        raise SystemExit(f"Error: {error}")
