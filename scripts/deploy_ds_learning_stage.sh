#!/usr/bin/env bash
# Run on 77, never on the editing workstation. No Cargo, rsync, secret creation,
# learned-model activation, or sniffer/MTA image build occurs in this script.
# Without --execute this only checks immutable inputs and prepares a release directory.
set -euo pipefail
exec python3 - "$@" <<'PY'
import argparse
import atexit
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import time


def fail(message):
    raise RuntimeError(message)


def command(argv, *, capture=False, stdin=None, timeout=None):
    return subprocess.run(argv, input=stdin, text=True, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None,
                          timeout=timeout).stdout


def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(root):
    """SHA256 of compact sorted-key JSON records, paths sorted lexically.

    Files: {path,sha256}. Internal relative symlinks: {path,symlink}.
    Directories have no record. Absolute/escaping links and special files fail.
    """
    if not root.is_dir() or root.is_symlink():
        fail('missing or symlinked artifact tree: ' + str(root))
    records = []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if os.path.isabs(target) or not path.resolve().is_relative_to(root.resolve()):
                fail('artifact symlink escapes its tree: ' + rel)
            records.append({'path': rel, 'symlink': target})
        elif path.is_file():
            records.append({'path': rel, 'sha256': file_hash(path)})
        elif not path.is_dir():
            fail('special artifact file: ' + rel)
    if not records:
        fail('empty artifact tree: ' + str(root))
    encoded = json.dumps(records, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def require_sha(value, name):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        fail('invalid SHA256: ' + name)
    return value


def inspect(name):
    result = subprocess.run(['docker', 'container', 'inspect', name], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode:
        return None
    d = json.loads(result.stdout)[0]
    return {'id': d['Id'], 'image': d['Image'], 'image_reference': d['Config']['Image'],
            'running': d['State']['Running'], 'health': d['State'].get('Health', {}).get('Status'),
            'environment_sha256': hashlib.sha256(json.dumps(sorted(d['Config'].get('Env') or [])).encode()).hexdigest()}


def database(sql):
    # Credentials remain inside the existing PostgreSQL container environment.
    return command(['docker', 'exec', '-i', 'vigilyx-postgres', 'sh', '-c',
                    'exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atq'],
                   stdin=sql, capture=True, timeout=30).strip()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)


def safe_source_path(raw):
    path = PurePosixPath(raw)
    if path.is_absolute() or '..' in path.parts or str(path) != raw or not path.parts:
        fail('invalid source path')
    if any(part.startswith('.') or part in ('node_modules', 'target', 'dist', 'data', 'models', 'model', 'backups') for part in path.parts):
        fail('source scope contains runtime or hidden data: ' + raw)
    if not (path.parts[0] in ('crates', 'frontend', 'scripts', 'shared', 'tests')
            or raw in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')):
        fail('source scope must not alter deployment settings: ' + raw)
    if path.name == 'deploy.conf' or path.name.startswith('.env'):
        fail('environment files are forbidden')
    return path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, default=Path('/home/CCAB_VIGILYX'))
parser.add_argument('--builder', default='vigilyx-rust-builder')
parser.add_argument('--builder-stage', required=True)
parser.add_argument('--frontend-dist', type=Path, required=True, help='validated dist directory on 77 host')
parser.add_argument('--manifest', type=Path, required=True)
parser.add_argument('--manifest-sha256', required=True, help='SHA256 of the exact manifest file bytes')
parser.add_argument('--expected-api-image', required=True, help='baseline sha256:d8715b8e...')
parser.add_argument('--expected-engine-image', required=True, help='baseline sha256:4a470a82...')
parser.add_argument('--execute', action='store_true')
args = parser.parse_args()
if os.geteuid() != 0 or args.root.resolve() != Path('/home/CCAB_VIGILYX'):
    fail('run as root on the named 77 deployment directory')
if not args.builder_stage.startswith('/tmp/vigilyx-ds-self-learning-') or '..' in PurePosixPath(args.builder_stage).parts:
    fail('builder stage must be the isolated DS self-learning checkout')
for name in ('expected_api_image', 'expected_engine_image'):
    if not re.fullmatch('sha256:[0-9a-f]{64}', getattr(args, name)):
        fail('an exact expected image ID is required')
require_sha(args.manifest_sha256, 'manifest')
if file_hash(args.manifest) != args.manifest_sha256:
    fail('manifest file hash mismatch')
manifest = json.loads(args.manifest.read_text())
if manifest.get('schema_version') != 1:
    fail('unsupported deployment manifest')
required_gates = ('clippy', 'workspace', 'frontend', 'capability_preservation')
if any(manifest.get('validation', {}).get(key) is not True for key in required_gates):
    fail('the manifest must record all completed validation gates')
source_files = manifest.get('source_files')
if not isinstance(source_files, list) or not source_files:
    fail('an explicit nonempty source file list is required')
seen = set()
for row in source_files:
    raw = row['path']
    safe_source_path(raw)
    if raw in seen:
        fail('duplicate source path')
    seen.add(raw)
    require_sha(row['sha256'], raw)
    if row['baseline_sha256'] is not None:
        require_sha(row['baseline_sha256'], raw + ' baseline')
        if row['baseline_sha256'] == row['sha256']:
            fail('source manifest must list actual changes only: ' + raw)
artifacts = manifest['artifacts']
for key in ('api_sha256', 'engine_sha256', 'frontend_tree_sha256', 'corpus_tree_sha256', 'onnxruntime_tree_sha256'):
    require_sha(artifacts[key], key)
packaging_paths = ('deploy/docker/Dockerfile.api.fast', 'deploy/docker/Dockerfile.engine.fast', 'deploy/docker/entrypoint.sh')
if set(manifest['packaging_files']) != set(packaging_paths):
    fail('packaging_files must bind both fast Dockerfiles and entrypoint.sh')
for raw, sha in manifest['packaging_files'].items():
    require_sha(sha, raw)

os.umask(0o077)
lock = open('/var/lock/vigilyx-ds-learning-deploy.lock', 'a')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
root = args.root.resolve()
compose_path = root / 'deploy/docker/docker-compose.yml'
env_path = root / 'deploy/docker/.env'
if env_path.stat().st_mode & 0o777 != 0o600:
    fail('existing .env must have mode 0600; this script never rewrites it')
guard_paths = (compose_path, env_path, root / 'deploy/docker/postgres-role-init.sh', root / 'deploy/docker/valkey-entrypoint.sh')
guard_hashes = {str(path): file_hash(path) for path in guard_paths}
canonical_binary_paths = {name: root / '.build-output' / name for name in ('vigilyx-api', 'vigilyx-engine')}
if any(path.is_symlink() for path in canonical_binary_paths.values()):
    fail('canonical build outputs must not be symlinks')
canonical_binary_hashes = {name: file_hash(path) if path.is_file() else None for name, path in canonical_binary_paths.items()}
canonical_dist = root / 'frontend/dist'
canonical_dist_hash = tree_hash(canonical_dist) if canonical_dist.exists() else None
compose_base = ['docker', 'compose', '--project-directory', str(root / 'deploy/docker'), '--env-file', str(env_path), '-f', str(compose_path)]
command(compose_base + ['config', '--quiet'], capture=True)
snapshot = {name: inspect(name) for name in ('vigilyx', 'vigilyx-engine-standalone', 'vigilyx-sniffer', 'vigilyx-mta')}
for name, expected in (('vigilyx', args.expected_api_image), ('vigilyx-engine-standalone', args.expected_engine_image)):
    if not snapshot[name] or not snapshot[name]['running'] or snapshot[name]['image'] != expected:
        fail('baseline image or running state changed: ' + name)
    reference = snapshot[name]['image_reference']
    if reference.startswith('sha256:') or '@sha256:' in reference:
        fail('baseline uses a digest reference; review future Compose image selection explicitly')
for name in ('vigilyx-postgres', 'vigilyx-redis'):
    if not inspect(name) or not inspect(name)['running']:
        fail('existing dependency must already be running: ' + name)
if database('SELECT COUNT(DISTINCT session_id) FROM security_feedback;') != '6':
    fail('feedback baseline changed; review the new cohort before deployment')
active = database("SELECT COALESCE(value::jsonb->'active','null'::jsonb) FROM config WHERE key='ds_learning_state';")
if active not in ('', 'null'):
    fail('an active learned model already exists; this release must not replace it')

stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
release = Path('/var/lib/vigilyx-releases') / ('ds-learning-' + stamp + '-' + args.manifest_sha256[:12])
release.mkdir(parents=True, exist_ok=False)
if not args.execute:
    # A preflight context is private and disposable. Never retain a duplicate
    # of large binaries when the operator later executes the same manifest.
    atexit.register(shutil.rmtree, release, ignore_errors=True)
context = release / 'context'
context.mkdir()
source_after = release / 'source-after'
source_after.mkdir()
shutil.copy2(args.manifest, release / 'manifest.json')
write_json(release / 'baseline.json', {'containers': snapshot, 'guard_hashes': guard_hashes,
                                     'canonical_binary_hashes': canonical_binary_hashes,
                                     'canonical_dist_tree_sha256': canonical_dist_hash})


def copy_builder(relative, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    command(['docker', 'cp', args.builder + ':' + args.builder_stage.rstrip('/') + '/' + relative, str(destination)], capture=True)


def check_source_baselines():
    for row in source_files:
        path = root / row['path']
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            fail('canonical source is symlinked or escapes root: ' + row['path'])
        current = file_hash(path) if path.is_file() else None
        if current != row['baseline_sha256'] or (path.exists() and not path.is_file()):
            fail('canonical source changed: ' + row['path'])


def check_external_guards():
    if any(file_hash(Path(path)) != sha for path, sha in guard_hashes.items()):
        fail('current Compose, credentials or dependency scripts changed during preparation')


check_source_baselines()
for row in source_files:
    target = source_after / row['path']
    copy_builder(row['path'], target)
    if not target.is_file() or target.is_symlink() or file_hash(target) != row['sha256']:
        fail('candidate source hash mismatch: ' + row['path'])
for raw, sha in manifest['packaging_files'].items():
    target = context / raw
    copy_builder(raw, target)
    if file_hash(target) != sha:
        fail('packaging file hash mismatch: ' + raw)
for binary, key in (('vigilyx-api', 'api_sha256'), ('vigilyx-engine', 'engine_sha256')):
    target = context / '.build-output' / binary
    copy_builder('.build-output/' + binary, target)
    if target.is_symlink() or file_hash(target) != artifacts[key] or not os.access(target, os.X_OK):
        fail('validated binary missing, non-executable or changed: ' + binary)
dist = context / 'frontend/dist'
dist.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(args.frontend_dist, dist, symlinks=True)
corpus = context / 'crates/vigilyx-engine/tests/redteam_cases'
copy_builder('crates/vigilyx-engine/tests/redteam_cases', corpus)
onnx = context / '.build-output/onnxruntime'
shutil.copytree(root / '.build-output/onnxruntime', onnx, symlinks=True)
for tree, key in ((dist, 'frontend_tree_sha256'), (corpus, 'corpus_tree_sha256'), (onnx, 'onnxruntime_tree_sha256')):
    if tree_hash(tree) != artifacts[key]:
        fail('validated artifact tree mismatch: ' + key)
if not (dist / 'index.html').is_file() or not (onnx / 'libonnxruntime.so.1.20.1').is_file():
    fail('frontend index or baseline ONNX Runtime missing')
dist_size = sum(path.stat().st_size for path in dist.rglob('*') if path.is_file() and not path.is_symlink())
source_largest = max((source_after / row['path']).stat().st_size for row in source_files)
largest_binary = max((context / '.build-output' / name).stat().st_size for name in canonical_binary_paths)
required_home_free = largest_binary + dist_size + source_largest + 128 * 1024 * 1024
if shutil.disk_usage(root).free < required_home_free:
    fail('insufficient /home space for one atomic binary replacement and frontend staging')
check_external_guards()
print('Validated release inputs: ' + str(release), flush=True)
if not args.execute:
    print('Preflight only: no image build, migration, service change or canonical source write; this temporary context is removed on exit.')
    sys.exit(0)

tag = 'ds-learning-' + stamp.lower() + '-' + args.manifest_sha256[:16]
api_tag, engine_tag = 'vigilyx-api:' + tag, 'vigilyx-engine:' + tag
for image_tag in (api_tag, engine_tag):
    if subprocess.run(['docker', 'image', 'inspect', image_tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        fail('release tag already exists; do not overwrite a previously addressable artifact')
for dockerfile, image_tag in ((packaging_paths[0], api_tag), (packaging_paths[1], engine_tag)):
    build = ['docker', 'build', '-f', str(context / dockerfile), '-t', image_tag]
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'):
        if key in os.environ:
            build += ['--build-arg', key]
    command(build + [str(context)])
candidate_images = {name: command(['docker', 'image', 'inspect', '-f', '{{.Id}}', tag], capture=True).strip()
                    for name, tag in (('vigilyx', api_tag), ('engine', engine_tag))}
overlay = release / 'candidate-compose.json'
rollback_overlay = release / 'rollback-compose.json'
write_json(overlay, {'services': {'vigilyx': {'image': candidate_images['vigilyx']}, 'engine': {'image': candidate_images['engine']},
                                 'postgres-migrate': {'image': candidate_images['vigilyx']}, 'audit-bootstrap': {'image': candidate_images['vigilyx']}}})
write_json(rollback_overlay, {'services': {'vigilyx': {'image': args.expected_api_image}, 'engine': {'image': args.expected_engine_image}}})
compose_candidate = compose_base + ['-f', str(overlay)]
compose_rollback = compose_base + ['-f', str(rollback_overlay)]
write_json(release / 'candidate-images.json', candidate_images)
check_source_baselines()
check_external_guards()
for name, old in snapshot.items():
    if inspect(name) != old:
        fail('service changed during image preparation: ' + name)

paused = []
replacement_started = False
sources_written = []
tags_changed = []
artifacts_written = []
dist_change_started = False
dist_before_local = canonical_dist.with_name('dist.ds-learning-before-' + args.manifest_sha256[:12])
dist_staged_local = canonical_dist.with_name('dist.ds-learning-staged-' + args.manifest_sha256[:12])
if dist_before_local.exists() or dist_staged_local.exists():
    fail('an earlier frontend switch requires review before retrying')


def resume_unchanged(name):
    old = snapshot[name]
    current = inspect(name)
    if not old or not old['running']:
        return
    if not current or current['id'] != old['id']:
        fail('refusing to start an externally replaced service: ' + name)
    command(['docker', 'start', name], capture=True)


def wait_ready(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        api = subprocess.run(['docker', 'exec', 'vigilyx', 'curl', '-fsS', '--max-time', '5',
                              'http://127.0.0.1:8088/api/health/ready'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        engine = inspect('vigilyx-engine-standalone')
        if api.returncode == 0 and engine and engine['running'] and engine['health'] == 'healthy':
            return
        time.sleep(2)
    fail('API readiness or engine heartbeat did not recover')


def interrupted(signum, frame):
    raise RuntimeError('deployment interrupted by signal ' + str(signum))


for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, interrupted)
try:
    # Preserve the exact running set; never start absent/stopped sniffer or MTA.
    for name in ('vigilyx-sniffer', 'vigilyx-mta', 'vigilyx-engine-standalone', 'vigilyx'):
        if snapshot[name] and snapshot[name]['running']:
            paused.append(name)
            command(['docker', 'stop', name], capture=True)
    check_external_guards()
    command(compose_base + ['up', '-d', '--wait', '--wait-timeout', '120', 'postgres', 'redis'])
    command(compose_candidate + ['run', '--rm', '--no-deps', 'postgres-role-init'])
    command(compose_candidate + ['run', '--rm', '--no-deps', 'postgres-migrate'])
    command(compose_candidate + ['run', '--rm', '--no-deps', 'audit-bootstrap'])
    if database("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='security_feedback' AND column_name IN ('corrected_threat_level','evidence_snapshot','snapshot_sha256','learning_status','learning_reason');") != '5':
        fail('feedback migration did not create all required columns')
    check_external_guards()
    replacement_started = True
    command(compose_candidate + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'vigilyx', 'engine'])
    wait_ready(150)
    for name in ('vigilyx-mta', 'vigilyx-sniffer'):
        resume_unchanged(name)
    deadline = time.monotonic() + 180
    state = None
    while time.monotonic() < deadline:
        raw = database("SELECT json_build_object('feedback_count',value::jsonb->'feedback_count','eligible_count',value::jsonb->'eligible_count','excluded_count',value::jsonb->'excluded_count','active',value::jsonb->'active','candidate',value::jsonb->'candidate') FROM config WHERE key='ds_learning_state';")
        state = json.loads(raw) if raw else None
        if state and state['feedback_count'] == 6:
            break
        time.sleep(3)
    if not state or state != {'feedback_count': 6, 'eligible_count': 0, 'excluded_count': 6, 'active': None, 'candidate': None}:
        fail('unexpected feedback learning state; expected 6 historical / 0 eligible / no model')
    if database('SELECT COUNT(DISTINCT session_id) FROM security_feedback;') != '6':
        fail('feedback cohort changed during deployment')
    check_external_guards()
    check_source_baselines()
    for name, path in canonical_binary_paths.items():
        if (file_hash(path) if path.is_file() else None) != canonical_binary_hashes[name]:
            fail('canonical binary changed during deployment: ' + name)
    if (tree_hash(canonical_dist) if canonical_dist.exists() else None) != canonical_dist_hash:
        fail('canonical frontend dist changed during deployment')
    for row in source_files:
        target = root / row['path']
        backup = release / 'source-before' / row['path']
        if target.is_file():
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + '.ds-learning-staged')
        if temporary.exists():
            fail('unexpected source staging file: ' + row['path'])
        shutil.copy2(source_after / row['path'], temporary)
        sources_written.append(row)
        os.replace(temporary, target)
    for name, path in canonical_binary_paths.items():
        backup = release / 'artifacts-before' / name
        if path.exists():
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, backup)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.ds-learning-staged')
        if temporary.exists():
            fail('unexpected binary staging file: ' + name)
        shutil.copy2(context / '.build-output' / name, temporary)
        artifacts_written.append(name)
        os.replace(temporary, path)
    dist_change_started = True
    shutil.copytree(dist, dist_staged_local, symlinks=True)
    if canonical_dist.exists():
        shutil.copytree(canonical_dist, release / 'frontend-dist-before', symlinks=True)
        os.replace(canonical_dist, dist_before_local)
    os.replace(dist_staged_local, canonical_dist)
    # Keep later ordinary Compose starts on the deployed images, preserving the
    # original tag names. The manifest-named tags and exact old IDs remain available.
    for name, image in (('vigilyx', candidate_images['vigilyx']), ('vigilyx-engine-standalone', candidate_images['engine'])):
        reference = snapshot[name]['image_reference']
        tags_changed.append(name)
        command(['docker', 'tag', image, reference])
    for name, old in snapshot.items():
        current = inspect(name)
        if bool(current and current['running']) != bool(old and old['running']):
            fail('original service running set was not restored: ' + name)
    wait_ready(30)
    if dist_before_local.exists():
        if tree_hash(dist_before_local) != canonical_dist_hash:
            fail('frontend backup changed during deployment')
        shutil.rmtree(dist_before_local)
    write_json(release / 'result.json', {'status': 'deployed', 'candidate_images': candidate_images,
                                       'learning_state': state, 'source_file_count': len(source_files)})
    print('Deployment verified: ' + str(release), flush=True)
except BaseException as error:
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    restore_errors = []
    def restore(action):
        try:
            action()
        except BaseException as exc:
            restore_errors.append(type(exc).__name__ + ': ' + str(exc)[:200])
    for name in reversed(tags_changed):
        restore(lambda name=name: command(['docker', 'tag', snapshot[name]['image'], snapshot[name]['image_reference']]))
    def restore_dist():
        if not dist_change_started:
            return
        backup = release / 'frontend-dist-before'
        if canonical_dist.exists():
            current = tree_hash(canonical_dist)
            if current == canonical_dist_hash and not dist_before_local.exists():
                if dist_staged_local.exists():
                    shutil.rmtree(dist_staged_local)
                return
            if current != artifacts['frontend_tree_sha256']:
                fail('frontend dist changed after deployment; manual restoration required')
            # The exact failed candidate remains in release/context; deleting
            # this verified copy avoids cross-filesystem rename and extra space.
            shutil.rmtree(canonical_dist)
        if dist_before_local.exists():
            os.replace(dist_before_local, canonical_dist)
        elif backup.exists():
            if dist_staged_local.exists():
                shutil.rmtree(dist_staged_local)
            shutil.copytree(backup, dist_staged_local, symlinks=True)
            os.replace(dist_staged_local, canonical_dist)
        if dist_staged_local.exists():
            shutil.rmtree(dist_staged_local)
    restore(restore_dist)
    for name in reversed(artifacts_written):
        def restore_binary(name=name):
            path = canonical_binary_paths[name]
            expected_new = artifacts['api_sha256' if name == 'vigilyx-api' else 'engine_sha256']
            temporary = path.with_name(path.name + '.ds-learning-staged')
            if temporary.exists():
                if file_hash(temporary) != expected_new:
                    fail('binary staging file changed; manual restoration required: ' + name)
                temporary.unlink()
            current = file_hash(path) if path.is_file() else None
            if current == canonical_binary_hashes[name]:
                return
            if current != expected_new:
                fail('canonical binary changed after deployment; manual restoration required: ' + name)
            backup = release / 'artifacts-before' / name
            if canonical_binary_hashes[name] is None:
                path.unlink(missing_ok=True)
            else:
                shutil.copy2(backup, path)
        restore(restore_binary)
    for row in reversed(sources_written):
        target, backup = root / row['path'], release / 'source-before' / row['path']
        def restore_source(target=target, backup=backup, row=row):
            # Do not overwrite a concurrent editor during rollback.
            temporary = target.with_name(target.name + '.ds-learning-staged')
            if temporary.exists():
                if file_hash(temporary) != row['sha256']:
                    fail('source staging file changed; manual restoration required: ' + row['path'])
                temporary.unlink()
            current = file_hash(target) if target.is_file() else None
            if current == row['baseline_sha256']:
                return
            if current != row['sha256']:
                fail('source changed after deployment; manual restoration required: ' + row['path'])
            if row['baseline_sha256'] is None:
                target.unlink(missing_ok=True)
            else:
                shutil.copy2(backup, target)
        restore(restore_source)
    if replacement_started:
        restore(lambda: command(compose_rollback + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'vigilyx', 'engine']))
    else:
        for name in ('vigilyx', 'vigilyx-engine-standalone'):
            if name in paused:
                restore(lambda name=name: resume_unchanged(name))
    for name in ('vigilyx-mta', 'vigilyx-sniffer'):
        if name in paused:
            restore(lambda name=name: resume_unchanged(name))
    restore(lambda: wait_ready(150))
    def verify_restored():
        for name, old in snapshot.items():
            current = inspect(name)
            if bool(current and current['running']) != bool(old and old['running']):
                fail('original running state not restored: ' + name)
            if old and (not current or current['image'] != old['image']):
                fail('original image not restored: ' + name)
    restore(verify_restored)
    write_json(release / 'result.json', {'status': 'failed', 'error_type': type(error).__name__,
                                       'restore_errors': restore_errors, 'migration_retained': True})
    print('Deployment failed; baseline restoration attempted. Record: ' + str(release), file=sys.stderr)
    for restore_error in restore_errors:
        print('RESTORE ERROR: ' + restore_error, file=sys.stderr)
    raise
PY
