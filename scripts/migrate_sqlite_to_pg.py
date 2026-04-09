#!/usr/bin/env python3
"""
Vigilyx SQLite -> PostgreSQL migration script

Usage:
  # Run on the remote server (containers must be stopped)
  python3 scripts/migrate_sqlite_to_pg.py \
    --sqlite /var/lib/docker/volumes/docker_vigilyx_data/_data/vigilyx.db \
    --pg "host=127.0.0.1 port=5433 dbname=vigilyx user=vigilyx password=<YOUR_PASSWORD>"

  # Validate only (do not write)
  python3 scripts/migrate_sqlite_to_pg.py --sqlite ... --pg ... --dry-run

Notes:
  - Stop all Vigilyx containers before migrating
  - The PostgreSQL container must be running and the tables must already exist (the API creates them at startup)
  - The SQLite database file is accessed directly through the volume path
"""

import argparse
import json
import sqlite3
import sys
import time

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2 未安装。运行: pip3 install psycopg2-binary")
    sys.exit(1)


# Migration order (respecting foreign-key dependencies)
MIGRATION_ORDER = [
    "config",
    "stats_cache",
    "sessions",
    "packets",
    "audit_logs",
    "login_history",
    "security_verdicts",
    "security_module_results",
    "security_ioc",
    "security_whitelist",
    "security_feedback",
    "security_sender_baselines",
    "security_disposition_rules",
    "security_temporal_cusum",
    "security_temporal_ewma",
    "security_entity_risk",
    "training_samples",
    "security_alerts",
    "data_security_http_sessions",
    "data_security_incidents",
]

# INTEGER boolean columns: SQLite 0/1 -> PostgreSQL true/false
BOOLEAN_COLUMNS = {
    "login_history": ["success"],
    "security_temporal_cusum": ["alarm_active"],
    "security_temporal_ewma": ["initialized"],
    "security_alerts": ["cusum_alarm", "acknowledged"],
    "security_disposition_rules": ["enabled"],
    "data_security_http_sessions": ["body_is_binary"],
}

# JSONB columns: TEXT -> JSONB (PostgreSQL auto-converts valid JSON strings)
JSONB_COLUMNS = {
    "sessions": ["content", "auth_info"],
}


def _validate_identifier(name, allowed):
    """SEC-REMAINING-005: Validate identifiers against an allowlist (defensive SQL injection protection, CWE-89)."""
    if name not in allowed:
        raise ValueError(f"非法标识符: '{name}' 不在允许列表中")
    # Extra validation: allow only letters/digits/underscores (defense in depth)
    if not all(c.isalnum() or c == '_' for c in name):
        raise ValueError(f"标识符包含非法字符: '{name}'")


def get_sqlite_columns(sqlite_cur, table_name):
    """Return the column names for a SQLite table."""
    _validate_identifier(table_name, set(MIGRATION_ORDER))
    sqlite_cur.execute(f"PRAGMA table_info('{table_name}')")
    return [row[1] for row in sqlite_cur.fetchall()]


def get_pg_columns(pg_cur, table_name):
    """Return the column names for a PostgreSQL table."""
    pg_cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = %s ORDER BY ordinal_position",
        (table_name,),
    )
    return [row[0] for row in pg_cur.fetchall()]


def transform_row(table_name, columns, row):
    """Transform a single row: booleans, JSON, and similar fields."""
    row = list(row)
    bool_cols = BOOLEAN_COLUMNS.get(table_name, [])
    jsonb_cols = JSONB_COLUMNS.get(table_name, [])

    for i, col_name in enumerate(columns):
        if col_name in bool_cols and row[i] is not None:
            row[i] = bool(row[i])
        elif col_name in jsonb_cols and row[i] is not None:
            # Validate JSON; set invalid values to NULL
            try:
                json.loads(row[i])
                # Keep it as a string; PostgreSQL will coerce it to JSONB
            except (json.JSONDecodeError, TypeError):
                row[i] = None

    return tuple(row)


def migrate_table(sqlite_cur, pg_cur, table_name, dry_run=False):
    """Migrate a single table."""
    _validate_identifier(table_name, set(MIGRATION_ORDER))
    # Get the column names from both sides
    sqlite_cols = get_sqlite_columns(sqlite_cur, table_name)
    pg_cols = get_pg_columns(pg_cur, table_name)

    if not sqlite_cols:
        print(f"  [SKIP] {table_name}: SQLite 中不存在")
        return 0
    if not pg_cols:
        print(f"  [SKIP] {table_name}: PostgreSQL 中不存在")
        return 0

    # Migrate only columns that exist on both sides (intersection, preserving SQLite column order)
    common_cols = [c for c in sqlite_cols if c in pg_cols]
    if not common_cols:
        print(f"  [SKIP] {table_name}: 无共同列")
        return 0

    # Read SQLite data
    cols_sql = ", ".join(common_cols)
    sqlite_cur.execute(f"SELECT {cols_sql} FROM {table_name}")
    rows = sqlite_cur.fetchall()
    total = len(rows)

    if total == 0:
        print(f"  [SKIP] {table_name}: 0 行")
        return 0

    if dry_run:
        print(f"  [DRY]  {table_name}: {total} 行")
        return total

    # Truncate the PostgreSQL target table (CASCADE)
    pg_cur.execute(f"TRUNCATE {table_name} CASCADE")

    # Bulk insert
    placeholders = ", ".join(["%s"] * len(common_cols))
    insert_sql = f"INSERT INTO {table_name} ({cols_sql}) VALUES ({placeholders})"

    batch_size = 5000
    inserted = 0
    start = time.time()

    for i in range(0, total, batch_size):
        batch = rows[i : i + batch_size]
        transformed = [transform_row(table_name, common_cols, row) for row in batch]
        psycopg2.extras.execute_batch(pg_cur, insert_sql, transformed, page_size=1000)
        inserted += len(batch)
        elapsed = time.time() - start
        rate = inserted / elapsed if elapsed > 0 else 0
        print(f"  [{table_name}] {inserted}/{total} ({rate:.0f} rows/s)", end="\r")

    elapsed = time.time() - start
    print(f"  [OK]   {table_name}: {total} 行 ({elapsed:.1f}s)          ")
    return total


def recalculate_stats_cache(pg_cur):
    """Recalculate stats_cache instead of reusing values maintained by SQLite migration triggers."""
    pg_cur.execute("""
        UPDATE stats_cache SET
            total_sessions = (SELECT COUNT(*) FROM sessions),
            active_sessions = (SELECT COUNT(*) FROM sessions WHERE status = 'Active'),
            total_bytes = (SELECT COALESCE(SUM(total_bytes), 0) FROM sessions),
            total_packets = (SELECT COUNT(*) FROM packets),
            smtp_sessions = (SELECT COUNT(*) FROM sessions WHERE protocol IN ('SMTP', 'Smtp')),
            pop3_sessions = (SELECT COUNT(*) FROM sessions WHERE protocol IN ('POP3', 'Pop3')),
            imap_sessions = (SELECT COUNT(*) FROM sessions WHERE protocol IN ('IMAP', 'Imap'))
        WHERE id = 1
    """)
    print("  [OK]   stats_cache 已重新计算")


def verify_counts(sqlite_cur, pg_cur):
    """Verify row-count consistency after migration."""
    print("\n=== 数据验证 ===")
    all_ok = True
    for table in MIGRATION_ORDER:
        try:
            sqlite_cur.execute(f"SELECT COUNT(*) FROM {table}")
            sqlite_count = sqlite_cur.fetchone()[0]
        except sqlite3.OperationalError:
            continue

        try:
            pg_cur.execute(f"SELECT COUNT(*) FROM {table}")
            pg_count = pg_cur.fetchone()[0]
        except Exception:
            continue

        status = "OK" if sqlite_count == pg_count else "MISMATCH"
        if status == "MISMATCH":
            all_ok = False
        print(f"  {table}: SQLite={sqlite_count}, PG={pg_count} [{status}]")

    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Vigilyx SQLite → PostgreSQL 迁移")
    parser.add_argument("--sqlite", required=True, help="SQLite 数据库文件路径")
    parser.add_argument("--pg", required=True, help="PostgreSQL 连接字符串")
    parser.add_argument("--dry-run", action="store_true", help="仅检查，不写入")
    args = parser.parse_args()

    print("=" * 60)
    print("Vigilyx SQLite → PostgreSQL 数据迁移")
    print("=" * 60)
    print(f"源: {args.sqlite}")
    print(f"目标: {args.pg}")
    if args.dry_run:
        print("模式: DRY RUN (不写入)")
    print()

    # Connect to the databases
    sqlite_conn = sqlite3.connect(args.sqlite)
    sqlite_cur = sqlite_conn.cursor()

    pg_conn = psycopg2.connect(args.pg)
    pg_conn.autocommit = False
    pg_cur = pg_conn.cursor()

    total_rows = 0
    start_time = time.time()

    try:
        # Disable triggers to keep stats_cache triggers from interfering during migration
        if not args.dry_run:
            pg_cur.execute("SET session_replication_role = 'replica'")

        print("=== 开始迁移 ===")
        for table in MIGRATION_ORDER:
            count = migrate_table(sqlite_cur, pg_cur, table, dry_run=args.dry_run)
            total_rows += count

        if not args.dry_run:
            # Re-enable triggers
            pg_cur.execute("SET session_replication_role = 'origin'")

            # Recalculate the stats cache
            recalculate_stats_cache(pg_cur)

            # Commit the transaction
            pg_conn.commit()

        elapsed = time.time() - start_time
        print(f"\n迁移完成: {total_rows} 行, 耗时 {elapsed:.1f}s")

        # Verify
        if not args.dry_run:
            ok = verify_counts(sqlite_cur, pg_cur)
            if ok:
                print("\n所有表行数一致!")
            else:
                print("\n!!! 部分表行数不一致，请手动检查 !!!")
                sys.exit(1)

    except Exception as e:
        if not args.dry_run:
            pg_conn.rollback()
        print(f"\n迁移失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        sqlite_cur.close()
        sqlite_conn.close()
        pg_cur.close()
        pg_conn.close()


if __name__ == "__main__":
    main()
