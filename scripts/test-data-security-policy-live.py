#!/usr/bin/env python3
"""Read-only API benchmark, optionally exercise the live authenticated HTTP queue.

Run on the Vigilyx server. --publish uses reserved IPs, .invalid/.example
identities and synthetic values, never sends SMTP, and removes only its own
fixtures after successful validation. Failed fixtures remain for investigation.
Credentials stay in memory and are never printed.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import hmac
import http.cookies
import json
from pathlib import Path
import shlex
import socket
import subprocess
import time
import urllib.request
import uuid


def settings():
    result = {}
    for line in Path('deploy/docker/.env').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, _, raw = line.partition('=')
            parsed = shlex.split(raw, comments=True)
            result[key.strip()] = parsed[0] if parsed else ''
    return result


def sql(query):
    result = subprocess.run(['docker', 'exec', '-i', 'vigilyx-postgres', 'sh', '-lc',
        'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
        input=query, text=True, capture_output=True, check=True)
    return result.stdout.strip()


class Redis:
    def __init__(self, config):
        self.conn = socket.create_connection(('127.0.0.1', int(config.get('REDIS_PORT', '6379'))), timeout=10)
        self.reader = self.conn.makefile('rb')
        self.command('AUTH', 'vigilyx_sniffer', config['REDIS_SNIFFER_PASSWORD'])

    def command(self, *args):
        data = [str(arg).encode() for arg in args]
        self.conn.sendall(b'*' + str(len(data)).encode() + b'\r\n' + b''.join(b'$'+str(len(arg)).encode()+b'\r\n'+arg+b'\r\n' for arg in data))
        line = self.reader.readline().rstrip(b'\r\n')
        if line.startswith(b'-'):
            raise RuntimeError('Redis rejected synthetic test operation')
        if line.startswith(b'$'):
            size = int(line[1:]); value = self.reader.read(size); self.reader.read(2); return value.decode()
        return line[1:].decode()

    def publish(self, payload, token):
        data = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        timestamp = int(time.time()); nonce = uuid.uuid4().hex
        signature = 'v1:' + hmac.new(token.encode(), f'{timestamp}:{nonce}:{data}'.encode(), hashlib.sha256).hexdigest()
        return self.command('XADD', 'vigilyx:stream:http_sessions', 'MAXLEN', '~', 100000, '*', 'data', data, 'ts', timestamp, 'nonce', nonce, 'auth', signature)


def login(config):
    request = urllib.request.Request('http://127.0.0.1:8088/api/auth/login',
        data=json.dumps({'username': config.get('API_USERNAME', 'admin'), 'password': config['API_PASSWORD']}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=15) as response:
        cookies = http.cookies.SimpleCookie()
        for header in response.headers.get_all('Set-Cookie', []): cookies.load(header)
        if 'vigilyx_token' not in cookies: raise RuntimeError('login did not return session cookie')
        return cookies['vigilyx_token'].value


def get(path, token):
    start = time.perf_counter()
    request = urllib.request.Request('http://127.0.0.1:8088' + path, headers={'Cookie': 'vigilyx_token=' + token})
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
        if not data.get('success'): raise RuntimeError(f'API failed: {path}')
        return data['data'], (time.perf_counter() - start)*1000


def fixture(name, body, user, uri='/mail/send'):
    return {'id': str(uuid.uuid4()), 'client_ip': '192.0.2.77', 'client_port': 45670,
            'server_ip': '198.51.100.77', 'server_port': 80, 'method': 'POST', 'uri': uri,
            'host': 'synthetic-policy-test.invalid', 'request_body': body,
            'request_body_size': len((body or '').encode()), 'detected_user': user,
            'detected_sender': user+'@corp.example', 'detected_recipients': ['recipient@external.example'],
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'has_gaps': False, 'body_is_binary': False}


def live(config, token):
    run_id = 'synthetic-policy-' + uuid.uuid4().hex[:12]
    cases = [
        ('phone_first', '客户手机号：13800138000', '/mail/send', 'sensitive_data_transfer'),
        ('phone_separate_send', '客户手机号：13800138000', '/mail/send', 'sensitive_data_transfer'),
        ('single_id', '客户身份证：000000200001010005', '/mail/send', 'sensitive_data_transfer'),
        ('single_cvv', 'CVV: 731', '/mail/send', 'sensitive_data_transfer'),
        ('single_bank_account', '请转账到 账号：1234567890123', '/mail/send', 'sensitive_data_transfer'),
        ('account_otp', '请转账到 账号：1234567890123 OTP: 384921', '/mail/send', 'sensitive_data_transfer'),
        ('public_swift', 'SWIFT: CITIUS33', '/mail/send', None),
        ('metadata_only', '{"from":"alice@example.com","to":["bob@example.net"],"body":"Meeting at noon"}', '/mail/send', None),
        ('owa_save', '{"Body":{"MessageDisposition":"SaveOnly","Content":"客户手机13800138000"}}', '/owa/service.svc?action=CreateItem', 'draft_box_abuse'),
        ('login', 'username=synthetic&password=SyntheticOnly729!', '/login', None),
        ('public_swift_pdf', None, '/upload', None),
        ('draft_last', '{"action":"save","attrs":{"content":"客户手机 13800138000"}}', '/coremail/common/mbox/compose.jsp', 'draft_box_abuse'),
    ]
    entries = [(name, fixture(name, body, run_id, uri), expected) for name, body, uri, expected in cases]
    pdf = entries[-2][1]
    path = '/app/data/tmp/http/' + pdf['id'] + '.bin'
    stream = b'BT /F1 12 Tf 72 720 Td (Public SWIFT: CITIUS33) Tj ET'
    document = b'%PDF-1.4\n1 0 obj\n<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream\nendobj\n%%EOF\n'
    # The engine consumes the spool read-only; the API owns its writable mount.
    subprocess.run(['docker', 'exec', '-i', 'vigilyx', 'sh', '-c', 'mkdir -p /app/data/tmp/http && cat > "$1"', 'fixture', path], input=document, check=True)
    pdf.update(body_is_binary=True, body_temp_file=path, detected_file_type='pdf', uploaded_filename=run_id+'.pdf', uploaded_file_size=len(document), request_body_size=len(document), content_type='application/pdf')
    redis = Redis(config)
    for index, (_, payload, _) in enumerate(entries):
        redis.publish(payload, config['MQ_AUTH_TOKEN'])
        if index == 0: redis.publish(payload, config['MQ_AUTH_TOKEN'])
    identifiers = ','.join("'"+item['id']+"'" for _, item, _ in entries)
    query = f"SELECT COALESCE(json_agg(row_to_json(i)), '[]') FROM (SELECT id,http_session_id,incident_type,severity,dlp_matches,details FROM data_security_incidents WHERE http_session_id IN ({identifiers})) i;"
    deadline = time.monotonic()+60
    while True:
        rows = json.loads(sql(query))
        if any(row['http_session_id'] == entries[-1][1]['id'] for row in rows): break
        if time.monotonic() > deadline: raise RuntimeError('live engine did not finish synthetic fixtures')
        time.sleep(0.5)
    results = []
    for name, payload, expected in entries:
        matching = [row for row in rows if row['http_session_id'] == payload['id']]
        primary = [row for row in matching if row['incident_type'] == expected]
        allowed = {expected, 'volume_anomaly'} if expected == 'sensitive_data_transfer' else {expected}
        assert len(primary) == (1 if expected else 0) and all(row['incident_type'] in allowed for row in matching), (name, matching)
        if expected:
            if expected == 'sensitive_data_transfer':
                assert primary[0]['severity'] == ('critical' if name in ('single_cvv', 'account_otp') else 'high'), name
            if expected == 'draft_box_abuse':
                details = primary[0]['details']
                if isinstance(details, str): details = json.loads(details)
                assert details['observation'] == 'draft_save' and details['delivery_confirmed'] is False, name
        results.append({'case': name, 'incidents': len(primary), 'type': expected,
                        'additional_types': [row['incident_type'] for row in matching if row['incident_type'] != expected]})
    api_rows, _ = get('/api/data-security/incidents?limit=100&client_ip=192.0.2.77', token)
    api_by_id = {row['id']: row for row in api_rows['items']}
    for row in rows:
        assert row['id'] in api_by_id, 'API omitted live incident'
        detail, _ = get('/api/data-security/incidents/' + row['id'], token)
        assert detail['incident_type'] == row['incident_type']
        if row['incident_type'] == 'sensitive_data_transfer':
            assert detail['details']['authorization_status'] == 'unverified'
            assert detail['details']['legal_assessment'] == 'not_determined'
    secret_leaks = int(sql(f"SELECT COUNT(*) FROM data_security_http_sessions WHERE id IN ({identifiers}) AND (request_body LIKE '%CVV: 731%' OR request_body LIKE '%SyntheticOnly729!%');"))
    assert secret_leaks == 0, 'synthetic authentication secret retained in stored body'
    # Remove only the exact synthetic session IDs generated by this invocation.
    sql(f"BEGIN; DELETE FROM data_security_incidents WHERE http_session_id IN ({identifiers}); DELETE FROM data_security_email_reviews WHERE session_id IN ({identifiers}); DELETE FROM data_security_http_sessions WHERE id IN ({identifiers}); COMMIT;")
    subprocess.run(['docker', 'exec', 'vigilyx', 'rm', '-f', path], check=True)
    return {'run_id': run_id, 'fixtures': results, 'same_session_retry_incidents': 1, 'authentication_secret_leaks': secret_leaks, 'fixtures_cleaned': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish', action='store_true', help='exercise the live authenticated queue with synthetic HTTP fixtures')
    args = parser.parse_args()
    config = settings(); token = login(config)
    report = {}
    if args.publish: report['live_chain'] = live(config, token)
    paths = ['/api/data-security/stats', '/api/data-security/engine-status', '/api/data-security/email-reviews/stats', '/api/stats/external-logins', '/api/data-security/incidents?limit=20']
    report['api_timings_ms'] = {}
    for path in paths:
        durations = [get(path, token)[1] for _ in range(10)]
        report['api_timings_ms'][path] = {'first': round(durations[0],2), 'median': round(sorted(durations)[len(durations)//2],2), 'max': round(max(durations),2)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        durations = list(pool.map(lambda _: get('/api/stats/external-logins', token)[1], range(12)))
    report['parallel_external_stats'] = {'requests': 12, 'all_success': True, 'max_ms': round(max(durations),2)}
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
