# Cerberus operations guide

## Install

See the [complete installation guide](INSTALL.md) for requirements, remote-host
access, the optional Docker Hub AIO method, and removal semantics.

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
./scripts/setup.sh
```

Open the printed URL and create the first owner with a password of at least 12
characters. For unattended setup, create
`secrets/cerberus_bootstrap_password`, then set these in `.env`:

```dotenv
CERBERUS_BOOTSTRAP_USERNAME=admin
CERBERUS_BOOTSTRAP_PASSWORD_FILE=/run/cerberus-secrets/bootstrap_password
```

Rerun setup and check the stack:

```bash
docker compose ps
curl http://127.0.0.1:8099/health
```

## Safe exposure

Cerberus binds to `127.0.0.1` by default. Use an HTTPS reverse proxy for remote
access and forward the original scheme so secure session cookies work. You may
instead bind to one private interface and enforce access with the host firewall.
Never publish the tools worker or ZAP ports.

## Scans, history, reports, and models

Active scans are off by default and require target authorization when enabled.
Only one scan runs globally so shared ZAP state cannot mix jobs. **Stop scan**
cancels active tools and discards the partial report.

History is grouped by site and run. **View run** restores findings and saved AI
analysis. **Report** opens the client view; **Print / Save as PDF** uses the
browser's PDF destination.

AI analysis is optional. API credentials are encrypted with the installation
master key. A ChatGPT plan can connect through the official Codex CLI in a
dedicated volume. Models explain saved findings; they do not control scanners.
Deleting a profile removes local credentials, tokens, and its saved analyses,
not the upstream provider account.

## Backup and restore

```bash
./scripts/backup.sh
```

Store the archive and `.sha256` receipt separately from
`secrets/cerberus_master_key`. Restore with:

```bash
./scripts/restore.sh backups/cerberus-TIMESTAMP.tar.gz --confirm-replace
```

Restore validates the receipt, extracts into a fresh volume, runs SQLite and
schema checks, verifies encrypted provider credentials using the separately
held key, fences the writer, switches `.env`, recreates the app, and waits for
health. The prior volume is preserved and a journal is written under
`.cerberus-restore/`.

Rollback using the environment file printed by restore:

```bash
./scripts/rollback-restore.sh .env.pre-restore-TIMESTAMP --confirm-rollback
```

Do not use `docker compose down --volumes` unless permanent deletion is the
goal.

## Password recovery

```bash
docker compose exec cerberus \
  python -m cerberus.userctl reset-password --username admin
```

The prompt does not echo. Reset revokes all browser sessions. Automation can
use a protected mounted file with `--password-file`.

## Update

Review release notes, then:

```bash
git pull --ff-only
./scripts/update.sh
```

The script creates a verified backup, pulls release images, refreshes secrets
and volume ownership, recreates changed services, and waits for health. Keep
the backup and master key until accepting the new version.

## Troubleshooting

```bash
docker compose ps
docker compose logs --tail=200 cerberus
docker compose logs --tail=200 cerberus-tools
docker compose logs --tail=200 zap
curl http://127.0.0.1:8099/health
```

Setup is idempotent and preserves existing secrets. If restore fails after the
writer is fenced, inspect its journal and use the preserved rollback state;
do not delete candidate or previous volumes while investigating.

Report security issues privately through [SECURITY.md](../SECURITY.md). Do not
put credentials or private scan data in public issues.
