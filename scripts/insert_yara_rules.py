#!/usr/bin/env python3
"""Bulk insert YARA rules into PostgreSQL."""
import json
import uuid
import subprocess
import os
from datetime import datetime, timezone

RULES_FILE = "/tmp/yara_rules_batch.json"
PG_HOST = "localhost"
PG_PORT = "5433"
PG_USER = "vigilyx"
PG_DB = "vigilyx"
PG_PASS = os.environ.get("PGPASSWORD", "changeme")

def main():
    with open(RULES_FILE) as f:
        rules = json.load(f)

    env = {**os.environ, "PGPASSWORD": PG_PASS}
    success = 0
    failed = 0

    for rule in rules:
        rid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        name = rule["rule_name"].replace("'", "''")
        cat = rule["category"]
        sev = rule["severity"]
        desc = rule["description"].replace("'", "''")
        src = rule["rule_source"].replace("'", "''")

        sql = (
            f"INSERT INTO security_yara_rules "
            f"(id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at) "
            f"VALUES ('{rid}', '{name}', '{cat}', '{sev}', 'custom', '{src}', '{desc}', TRUE, 0, '{now}', '{now}') "
            f"ON CONFLICT (rule_name) DO UPDATE SET "
            f"rule_source = EXCLUDED.rule_source, category = EXCLUDED.category, "
            f"severity = EXCLUDED.severity, description = EXCLUDED.description, "
            f"updated_at = EXCLUDED.updated_at;"
        )

        result = subprocess.run(
            ["psql", "-h", PG_HOST, "-p", PG_PORT, "-U", PG_USER, "-d", PG_DB, "-c", sql],
            capture_output=True, text=True, env=env
        )
        if result.returncode == 0:
            success += 1
        else:
            print(f"FAILED {rule['rule_name']}: {result.stderr[:200]}")
            failed += 1

    print(f"Done: {success} success, {failed} failed, total {len(rules)}")

if __name__ == "__main__":
    main()
