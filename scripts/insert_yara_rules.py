#!/usr/bin/env python3
"""Bulk insert YARA rules into PostgreSQL."""
import json
import uuid
import sys
import os
from datetime import datetime, timezone

import psycopg2

RULES_FILE = "/tmp/yara_rules_batch.json"
PG_HOST = "localhost"
PG_PORT = "5433"
PG_USER = "vigilyx"
PG_DB = "vigilyx"
PG_PASS = os.environ.get("PGPASSWORD")

def main():
    if not PG_PASS:
        print("Error: PGPASSWORD environment variable is not set.")
        sys.exit(1)

    with open(RULES_FILE) as f:
        rules = json.load(f)

    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        dbname=PG_DB,
        password=PG_PASS,
    )
    conn.autocommit = True
    cur = conn.cursor()

    success = 0
    failed = 0

    sql = (
        "INSERT INTO security_yara_rules "
        "(id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at) "
        "VALUES (%s, %s, %s, %s, 'custom', %s, %s, TRUE, 0, %s, %s) "
        "ON CONFLICT (rule_name) DO UPDATE SET "
        "rule_source = EXCLUDED.rule_source, category = EXCLUDED.category, "
        "severity = EXCLUDED.severity, description = EXCLUDED.description, "
        "updated_at = EXCLUDED.updated_at;"
    )

    for rule in rules:
        rid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        params = (
            rid,
            rule["rule_name"],
            rule["category"],
            rule["severity"],
            rule["rule_source"],
            rule["description"],
            now,
            now,
        )
        try:
            cur.execute(sql, params)
            success += 1
        except Exception as e:
            print(f"FAILED {rule['rule_name']}: {str(e)[:200]}")
            failed += 1

    cur.close()
    conn.close()
    print(f"Done: {success} success, {failed} failed, total {len(rules)}")

if __name__ == "__main__":
    main()
