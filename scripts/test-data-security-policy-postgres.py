#!/usr/bin/env python3
"""Run the single-transfer engine regression on 77 using disposable PostgreSQL.

Requires the existing vigilyx-rust-builder. No ports are published and no
production database, configuration or other service is modified.
"""
import os
import secrets
import subprocess
import time
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    name = 'vigilyx-policy-test-' + uuid.uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    image = run('docker', 'inspect', '--format', '{{.Image}}', 'vigilyx-postgres', capture_output=True).stdout.strip()
    created = False
    try:
        run('docker', 'run', '--detach', '--name', name, '--network', 'bridge',
            '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,size=512m',
            '-e', 'POSTGRES_DB=vigilyx_test_policy', '-e', 'POSTGRES_PASSWORD', image,
            env={**os.environ, 'POSTGRES_PASSWORD': password}, stdout=subprocess.DEVNULL)
        created = True
        for _ in range(30):
            if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('disposable PostgreSQL did not become ready')
        ip = run('docker', 'inspect', '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', name, capture_output=True).stdout.strip()
        url = f'postgres://postgres:{password}@{ip}:5432/vigilyx_test_policy'
        run('docker', 'exec', '-e', 'VIGILYX_ALLOW_REAL_INFRA_TESTS=1',
            '-e', 'VIGILYX_TEST_DATABASE_URL', 'vigilyx-rust-builder',
            'cargo', 'test', '-p', 'vigilyx-db', '--features', 'infra-tests',
            '--test', 'real_postgres', 'retention_skips_busy_sessions_and_rolls_back_counter_lock_waits',
            '--', '--nocapture', env={**os.environ, 'VIGILYX_TEST_DATABASE_URL': url})
        result = subprocess.run(['docker', 'exec', '-e', 'VIGILYX_ALLOW_REAL_INFRA_TESTS=1',
                                 '-e', 'VIGILYX_TEST_DATABASE_URL', 'vigilyx-rust-builder',
                                 'cargo', 'test', '-p', 'vigilyx-engine', '--features', 'infra-tests',
                                 '--test', 'data_security_single_transfer_postgres', '--', '--nocapture'],
                                env={**os.environ, 'VIGILYX_TEST_DATABASE_URL': url})
        return result.returncode
    finally:
        if created:
            subprocess.run(['docker', 'rm', '-f', '-v', name], check=True, stdout=subprocess.DEVNULL)
            print('Disposable policy-test PostgreSQL removed.', flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
