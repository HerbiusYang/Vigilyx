# Updating an existing Vigilyx deployment

Use this guide when Vigilyx is already installed. For a new server, follow
[Deployment](DEPLOYMENT.md). Do not run `generate-secrets.sh` or replace the
server's `.env` during an update.

Commands marked **workstation** run in the new source checkout. Commands marked
**server** run over SSH in the existing deployment directory. All builds and
tests run on the server. The examples use `/home/CCAB_VIGILYX`; substitute your
configured `VIGILYX_REMOTE_DIR` consistently.

## Example: 0.9.3 → 0.9.4

Use the **final published** 0.9.4 source, not an in-progress checkout or an old
image carrying the same version string. After publication, for example:

```bash
git clone --branch v0.9.4 --single-branch \
  https://github.com/HerbiusYang/Vigilyx.git Vigilyx-0.9.4
cd Vigilyx-0.9.4
git rev-parse HEAD
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
```

Set the **existing** server and directory. The 0.9.3 example used
`/home/vigilyx`; the current example uses `/home/CCAB_VIGILYX`. Keep whichever
path actually contains your installation, rather than changing it to match a
new template. Verify the commit against the release record.

Then complete steps 2–6 below. The version-specific sequence is:

1. On the server, save the old configuration/images and complete the database
   backup in step 2. Keep the existing `.env` and login credentials.
2. The 0.9.3 source pins Rust 1.97.1; 0.9.4 pins 1.98.0. On the workstation,
   pre-pull the new builder image on the target, then initialize it:

   ```bash
   ssh root@<server> \
     "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
   ./deploy.sh --init
   ```

3. Review the retained remote `.env`, then run `./deploy.sh --production`.
   The helper fills missing per-service PostgreSQL/Redis credentials, the
   independent configuration-encryption key, and the audit-bootstrap identity;
   it then applies roles and schema changes before starting the new services.
   Do not use `--frontend` or `--config-only` for this whole-version upgrade.
4. Both versions use PostgreSQL 17; no SQLite conversion is involved. Retain
   the existing database volume, message-bus volume, TLS material, and optional
   models. Do not run `docker compose down -v`.
5. **Existing encrypted integrations need attention.** 0.9.3 stores SMTP/AI
   secrets using the JWT-derived `ENC:` format; new workers require `ENC:v2:`
   under `VIGILYX_CONFIG_ENCRYPTION_KEY`. The deployment helper does not convert
   those stored values. Keep the old `API_JWT_SECRET`, re-enter the original
   credentials in each configured integration's settings, and save them to
   create v2 values. Keeping a masked/blank field does not convert its stored
   ciphertext. Verify configured integrations through their approved test
   procedures before accepting the update. Prepare the original integration
   credentials before the maintenance window; if they are unavailable, resolve
   this before upgrading an environment that depends on those integrations.
6. Run step 5 acceptance using the original mode and existing user account.
   Provision/change the new independent audit account's bootstrap password as
   appropriate. Existing accounts are not reset by the update.

This is an in-place application/database upgrade, not a fresh installation.
If this upgrade must be reversed, use the dedicated 0.9.3 recovery below, not
the image-only rollback procedure: 0.9.3 uses default-user Redis authentication
and runs database initialization during API startup.

## 1. Confirm the source and target — workstation

Obtain the complete release source, including `scripts/`, `shared/`, fixtures,
and lockfiles. Record its commit or source-archive checksum. Use the release's
actual published commit; a version string alone does not identify the source.

```bash
test -f deploy.conf || cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
./deploy.sh --help
```

Set `VIGILYX_SERVER` to the existing SSH target and `VIGILYX_REMOTE_DIR` to its
existing directory. Keep `VIGILYX_LOCAL_DIR` unset to use this checkout.
The workstation requires Bash, SSH, rsync, and Python 3; the server requires
Bash, Python 3, rsync, OpenSSL, Docker, and Compose v2.20 or later.

## 2. Record and back up the existing deployment — server

Reserve a maintenance window. Deployments briefly pause the API and data plane
while coordinating database/message-bus dependencies and roles. Finish backups
and other long database transactions before deploying schema changes.

```bash
cd /home/CCAB_VIGILYX
set -euo pipefail
umask 077
install -d -m 700 /var/backups/vigilyx
update_backup=$(mktemp -d /var/backups/vigilyx/update-XXXXXXXX)
cp -a deploy/docker "$update_backup/docker"

# Store immutable image IDs for application rollback, including one-shot jobs.
python3 - "$update_backup/images.compose.json" <<'PY'
import json, pathlib, subprocess, sys
services = {}
for service, container in {
    'vigilyx': 'vigilyx',
    'engine': 'vigilyx-engine-standalone',
    'sniffer': 'vigilyx-sniffer',
    'mta': 'vigilyx-mta',
    'redis': 'vigilyx-redis',
}.items():
    result = subprocess.run(['docker', 'inspect', container], capture_output=True, text=True)
    if result.returncode:
        if service == 'vigilyx':
            raise SystemExit('Existing API container is required for an update snapshot')
        continue
    image = json.loads(result.stdout)[0]['Image']
    services[service] = {'image': image, 'pull_policy': 'never'}
services['postgres-migrate'] = dict(services['vigilyx'])
services['audit-bootstrap'] = dict(services['vigilyx'])
pathlib.Path(sys.argv[1]).write_text(json.dumps({'services': services}, indent=2) + '\n')
PY

# Logical database backup; wait for it to finish before starting deployment.
docker exec vigilyx-postgres sh -lc \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=zstd:3' \
  > "$update_backup/database.dump.partial" && \
docker exec -i vigilyx-postgres pg_restore --list \
  < "$update_backup/database.dump.partial" > /dev/null && \
mv "$update_backup/database.dump.partial" "$update_backup/database.dump"
test -s "$update_backup/database.dump"
printf 'Keep this backup path: %s\n' "$update_backup"
```

Stop if any backup command fails. A `.partial` file is not a completed backup.
Keep this directory private: it contains passwords and potentially TLS keys.
Do not prune the recorded images during the rollback window. Database dumps do
not include attachment/spool files or model volumes; retain the corresponding
volume backups for disaster recovery as described in [Deployment §7](DEPLOYMENT.md#7-backup-and-recovery).

Review the existing `.env` against the new `deploy/docker/.env.example`; retain its passwords,
encryption key, mode, interface, TLS paths, optional models, and memory settings.
The helper fills missing runtime-role/bootstrap secrets without replacing
existing values. Do not copy an example file over `.env`. The current 128 GiB
server uses `PG_SHARED_BUFFERS=8GB`, `PG_EFFECTIVE_CACHE_SIZE=64GB`, and
`PG_MAINTENANCE_WORK_MEM=512MB`; size other hosts separately.

## 3. Verify the builder — workstation

```bash
ssh root@<server> "docker exec vigilyx-rust-builder rustc --version"
```

Compare this with `rust-toolchain.toml`. If the builder is absent or the pinned
toolchain changed, pre-pull the exact image shown in
`deploy/docker/setup-builder.sh`, then run `./deploy.sh --init`. This preserves
an existing `.env` and the persistent Cargo cache. Routine updates do not need
initialization. The server must reach the Rust, npm, Debian, and OCI registries;
configure an approved proxy there if required.

## 4. Update — workstation

For a complete version update, use:

```bash
./deploy.sh --production
```

This follows the existing remote mode (`VIGILYX_MODE`, then stored database
mode, then mirror). On an existing MTA deployment it rebuilds the embedded MTA
engine too. `--mta` explicitly selects/switches to MTA; do not add it to a mirror
update. Keep an existing HTTPS reverse proxy running. Add `--tls` only when
intentionally provisioning the bundled file-certificate entry point.

For subsequent component-specific changes:

| Change | Command | Schema migration |
|---|---|---|
| API / engine / database schema | `./deploy.sh --production --backend` | Yes |
| Frontend | `./deploy.sh --production --frontend` | Yes; the production API image recompiles Rust |
| Mirror sniffer | `./deploy.sh --production --sniffer` | No |
| Runtime configuration only | `./deploy.sh --config-only` | No; reuses installed images |

Without `--production`, the helper uses incremental `release-fast` builds.
Fast frontend updates also reuse the existing API binary and skip schema
migration. Use the complete update for a new release; targeted commands assume
the other components and their required artifacts already exist.

The helper syncs source while preserving `.env`, `deploy.conf`, TLS material,
`.rollback/`, `backups/`, and runtime volumes. It runs checks, builds images,
pauses running clients, coordinates dependencies/roles, migrates with the new
API when applicable, restores previously running clients, and deploys selected
components. On a failed migration it attempts to resume the prior containers;
this is service recovery, not an automatic image or database rollback.

## 5. Accept the update — server

```bash
cd /home/CCAB_VIGILYX
docker compose -f deploy/docker/docker-compose.yml ps -a
curl -fsS http://127.0.0.1:8088/api/health/ready
python3 scripts/verify-deployment.py --mode mirror
# Use --mode mta for an MTA deployment.
```

Require exit code 0, `{"status":"ready"}`, the intended data plane running,
and no unexpected restart loop. Mirror verification checks both consumer groups
twice with lag at most 100, waiting up to 120 seconds; pending work is reported
separately. Check the existing HTTPS entry point and log in with the existing
account. In mirror mode, confirm that newly observed SMTP traffic gets a new
record; no incoming traffic means this last check is pending, not failed.
For MTA, verify the configured TLS listeners and approved normal mail delivery
to the configured downstream. Record image IDs and the command's final result.

## 6. Recover a failed update — server

Keep the failed command's logs. If it failed waiting for a database lock, finish
the conflicting backup/transaction and rerun the same command. Do not bypass
the error with `--skip-test` or `--skip-lint`.

For application-only rollback, first confirm the old application is compatible
with the current schema/authentication, does not rerun an older initializer,
and that credentials were not rotated. This path does **not** apply to 0.9.3.
Use the backup path
printed in step 2 and select exactly one data plane:

```bash
update_backup=/var/backups/vigilyx/update-XXXXXXXX  # actual saved directory
docker compose --env-file "$update_backup/docker/.env" \
  -f "$update_backup/docker/docker-compose.yml" \
  -f "$update_backup/images.compose.json" \
  up -d --no-deps --no-build --pull never vigilyx engine sniffer
# MTA: replace the final three services with: vigilyx mta
curl -fsS http://127.0.0.1:8088/api/health/ready
```

This uses the saved configuration and exact old images without running the old
migration job. Repeat step 5 using the saved source/configuration. Keep the failed
source and backup until the recovery is accepted; correct the workstation
checkout before the next deploy so it does not reapply the failed update.

An incompatible schema or rotated credentials requires coordinated database,
configuration, and application recovery. Use the tested backup/restore process
in [Deployment §7](DEPLOYMENT.md#7-backup-and-recovery), validate on a separate
host first, and account for records received after the backup. Do not try to
reverse a migration by running an older binary's migrator.

### Recover 0.9.3 after a failed 0.9.4 upgrade

Use the backup taken while 0.9.3 was running. Reserve enough additional disk
space to restore its database alongside the current database. This returns the
application to the backup's point in time; retain and reconcile records/files
received afterwards. The current database is retained by this procedure.

```bash
set -euo pipefail
cd /home/CCAB_VIGILYX                      # actual existing deployment directory
update_backup=/var/backups/vigilyx/update-XXXXXXXX
test -s "$update_backup/database.dump"

# Pause all application writers; leave PostgreSQL up.
docker compose -f deploy/docker/docker-compose.yml --profile '*' \
  stop sniffer mta engine vigilyx

# Restore into a NEW empty database; do not overwrite the failed database.
rollback_db="vigilyx_restore_$(date -u +%Y%m%d%H%M%S)"
docker exec vigilyx-postgres sh -lc \
  'createdb -U "$POSTGRES_USER" "$1"' sh "$rollback_db"
docker exec -i vigilyx-postgres sh -lc \
  'exec pg_restore -U "$POSTGRES_USER" -d "$1" --exit-on-error' sh "$rollback_db" \
  < "$update_backup/database.dump"

# Work on a copy so the original backup remains intact.
cp -a "$update_backup/docker" "$update_backup/recovery-docker"
python3 - "$update_backup/recovery-docker/.env" "$rollback_db" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = [line for line in p.read_text().splitlines() if not line.startswith('PG_DB=')]
p.write_text('\n'.join(lines + ['PG_DB=' + sys.argv[2]]) + '\n')
p.chmod(0o600)
PY

recovery_compose=(docker compose --env-file "$update_backup/recovery-docker/.env"
  -f "$update_backup/recovery-docker/docker-compose.yml"
  -f "$update_backup/images.compose.json")

# Restore 0.9.3's Redis entrypoint/configuration and authentication first.
"${recovery_compose[@]}" up -d --wait --wait-timeout 120 \
  --no-deps --no-build --pull never redis
"${recovery_compose[@]}" up -d --no-deps --no-build --pull never vigilyx engine sniffer
# MTA: replace the final three services with: vigilyx mta
```

Check the old release's readiness, existing login, logs, and arrival of approved
new mail. The 0.9.4 verifier requires new Redis ACL credentials, so it is not a
0.9.3 acceptance tool. The old API may initialize its **restored old database**;
do not point it at the failed 0.9.4 database. Keep both databases and the failed
release's files until reconciliation is accepted. Before any later deployment,
restore the accepted source/configuration to the canonical deployment directory,
including the recovery `PG_DB`, so a future command cannot reconnect to the
failed database or reapply the failed source.
