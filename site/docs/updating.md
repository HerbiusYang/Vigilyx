---
title: Updating and Recovery
description: Update an installed Vigilyx environment with backups, configuration preservation, migration, verification, and recovery.
---

# Updating and Recovery

Use this page for an existing installation. For a new server, start with
[First deployment](/docs/deployment).

## Example: 0.9.3 → 0.9.4

After publication, obtain the final release on the workstation:

```bash
git clone --branch v0.9.4 --single-branch \
  https://github.com/HerbiusYang/Vigilyx.git Vigilyx-0.9.4
cd Vigilyx-0.9.4
git rev-parse HEAD
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
```

Set the **existing** server and directory and verify the release commit. The 0.9.3 example used `/home/vigilyx`; the new template uses `/home/CCAB_VIGILYX`. Retain the actual installed path. Complete the backup in step 1 below first.

0.9.3 pins Rust 1.97.1 and 0.9.4 pins 1.98.0, so this update needs a builder refresh. From the workstation:

```bash
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
./deploy.sh --init
# Retain and review the existing remote .env, then update the complete stack:
./deploy.sh --production
```

The helper fills missing PostgreSQL/Redis role credentials, the independent configuration-encryption key, and the audit-bootstrap identity, then coordinates roles and migrates the schema. Do not substitute `--frontend` or `--config-only` for this version upgrade. Both releases use PostgreSQL 17; retain its volume, with no SQLite conversion or `down -v`.

**Existing integration secrets need separate handling:** 0.9.3 SMTP/AI settings may contain JWT-derived `ENC:` values; new workers require independent-key `ENC:v2:` values. The helper does not convert stored ciphertext. Prepare original integration credentials before the update, retain `API_JWT_SECRET`, then re-enter and save the actual credentials in each configured integration and follow its approved test procedure. Keeping a masked/blank value does not convert the old ciphertext. Resolve unavailable credentials before upgrading an environment that relies on those integrations.

Finish step 4 acceptance using existing accounts; change the new independent audit account's password at first login. For failure recovery use the dedicated **Recover 0.9.3** procedure in `UPDATING.md`: old startup initializes the database and uses old Redis authentication, so restore into a new empty database and restore matching Redis configuration rather than rolling back application images alone.

## 1. Prepare source and backups

Obtain the complete new release source and record its commit or archive checksum. Point the workstation's `deploy.conf` at the existing server and deployment directory. Builds and tests still run remotely.

On the server, follow [step 2 of the repository's `UPDATING.md`](https://github.com/HerbiusYang/Vigilyx/blob/main/UPDATING.md#2-record-and-back-up-the-existing-deployment--server) to save configuration, exact image IDs, and a logical database backup. This file is also included in the source archive; GitHub access is not needed to execute it. Finish and verify the backup before deployment; large databases may take a long time.

Retain the server's `.env`, passwords, encryption key, mode, capture interface, TLS material, model volumes, and database settings. Compare new settings with `deploy/docker/.env.example`; **do not replace `.env` or regenerate secrets**. The helper fills missing runtime-role/audit-bootstrap secrets while preserving existing values. Existing account passwords remain database-backed.

## 2. Check the builder

On the workstation:

```bash
ssh root@<server> "docker exec vigilyx-rust-builder rustc --version"
```

Compare with the new release's `rust-toolchain.toml`. Only if the builder is absent or the pinned toolchain changed, pull the exact image from `setup-builder.sh`, then run `./deploy.sh --init`. It retains the existing `.env` and Cargo caches. Routine updates do not require initialization.

## 3. Update

From the new workstation checkout:

```bash
./deploy.sh --production
```

This updates the complete existing topology. An MTA environment also rebuilds its embedded engine. `--mta` explicitly selects or switches to MTA; it is not needed for every update. Keep the existing HTTPS reverse proxy; add `--tls` only when intentionally provisioning bundled TLS.

For later targeted changes:

| Change | Command | Schema migration |
|---|---|---|
| API / engine / database | `./deploy.sh --production --backend` | Yes |
| Frontend | `./deploy.sh --production --frontend` | Yes; production also compiles Rust |
| Mirror sniffer | `./deploy.sh --production --sniffer` | No |
| Runtime configuration only | `./deploy.sh --config-only` | No; reuses installed images |

Omitting `--production` selects developer `release-fast` builds. Fast frontend updates reuse the API binary and skip migration. Use the complete update for a new version.

Deployment pauses current API/data-plane clients while coordinating PostgreSQL, Valkey, and roles; targeted updates also need a maintenance window. Migration lock acquisition defaults to 15 seconds. Finish a conflicting backup or transaction before retrying; do not skip failed checks.

## 4. Accept the update

From the server's deployment directory:

```bash
docker compose -f deploy/docker/docker-compose.yml ps -a
curl -fsS http://127.0.0.1:8088/api/health/ready
python3 scripts/verify-deployment.py --mode mirror
# Use --mode mta for MTA.
```

Require exit code 0, ready status, the selected data plane running, and no unexpected restart loop. Mirror verification checks effective database settings and requires both email and HTTP group lag to stay at most 100 for two observations within 120 seconds; pending work is reported separately.

Open the existing HTTPS entry point and log in with the existing account. When new SMTP traffic arrives, verify new records continue appearing; otherwise mark that check pending. In MTA mode, check TLS listeners and approved normal delivery to the configured downstream. Record image IDs and the final command result.

## 5. Recover a failure

After migration failure the helper attempts to resume previously running services; this is not automatic image/database rollback. Keep failure logs. Application-only rollback requires compatibility with the current schema/authentication, no older startup initializer, and unchanged credentials. Use the saved configuration and exact image IDs in [step 6 of `UPDATING.md`](https://github.com/HerbiusYang/Vigilyx/blob/main/UPDATING.md#6-recover-a-failed-update--server). **0.9.3 does not qualify for image-only rollback**; use that file's dedicated recovery procedure.

An incompatible schema or rotated credentials requires coordinated database, configuration, and application recovery. Validate restoration on a separate host first and account for records received after the backup. Do not reverse migrations with an older binary or delete data volumes to recover.
