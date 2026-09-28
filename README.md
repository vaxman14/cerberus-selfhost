# Cerberus

Cerberus is a free, self-hosted website security and quality scanner. Local
users, scan history, reports, and encrypted model credentials stay on your
Docker host.

- **The Surface** — HTTPS, headers, cookies, exposed files, source maps, and
  common client-side secret patterns.
- **The Nose** — technology disclosures, SPF, DMARC, `security.txt`, directory
  listings, and WordPress user exposure.
- **The Health** — local Lighthouse in an isolated Chromium worker.
- **The Hunt** — authorized Nuclei, OWASP ZAP, and conservative sqlmap checks.

Cerberus includes local owner authentication, per-site run history, stoppable
jobs, PDF-ready client reports, and optional AI analysis through API providers
or a ChatGPT plan using OpenAI's official Codex CLI.

## Quick start

For both the recommended Compose setup and the optional Docker Hub AIO method,
read the [complete installation guide](docs/INSTALL.md).

Requires Docker Engine, Docker Compose v2, OpenSSL, and roughly 8 GB of free
disk for images and working space.

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
./scripts/setup.sh
```

Open <http://127.0.0.1:8099> and create the first local owner. Setup generates
installation secrets, pulls release images, starts the stack, waits for health,
and prints the URL.

Safe defaults bind only to localhost, publish no scanner ports, require local
login, and disable active Nuclei/ZAP/sqlmap scans. To enable active tools, set
`CERBERUS_ENABLE_ACTIVE_SCANS=true` in `.env` and run
`docker compose up -d`. Every active run still requires explicit authorization
and production-risk confirmation.

## Operations

```bash
docker compose ps
docker compose logs --tail=200 cerberus
./scripts/backup.sh
./scripts/restore.sh backups/cerberus-TIMESTAMP.tar.gz --confirm-replace
./scripts/rollback-restore.sh .env.pre-restore-TIMESTAMP --confirm-rollback
docker compose exec cerberus python -m cerberus.userctl reset-password --username admin
./scripts/update.sh
docker compose down
```

Back up `secrets/cerberus_master_key` **separately** from database archives. A
database backup without the original key cannot decrypt saved provider
credentials. `docker compose down --volumes` deliberately destroys local
volumes; ordinary `docker compose down` preserves them.

See the [public installation page](https://cerberusscan.com/install) and
[operations guide](docs/HELP.md) for full recovery, reverse-proxy,
configuration, and troubleshooting instructions.

## Resource expectations

- Images: `linux/amd64` and `linux/arm64`
- Recommended host: 4 CPU cores, 8 GB RAM, and 8 GB free disk plus report growth
- Lighthouse, Nuclei, and ZAP create short CPU/RAM spikes while scanning
- One scan runs at a time because the shared ZAP worker is serialized

## Unraid AIO

The optional `romanvaxman/cerberus-aio:0.2.0` master image provides a
single-container Community Apps entry while launching the isolated child
stack. It requires `/var/run/docker.sock`, which grants effective control of
the Docker host. The ordinary Compose install does not mount the socket and is
safer when one-click Unraid installation is unnecessary. See
[the Unraid notes](docs/UNRAID.md).

## Security boundary

The stack contains the app, a secret-initialization job, an isolated
Lighthouse/Nuclei/sqlmap worker, and ZAP. Workers have no host ports, Docker
socket, provider vault, or database access. Containers use read-only roots,
dropped capabilities, `no-new-privileges`, tmpfs workspaces, resource ceilings,
and authenticated private APIs.

Owner passwords use Argon2id. Provider keys are AES-256-GCM sealed in SQLite
with a master key outside the database. API responses never return secrets.
Requests to a remote model provider leave your host under that provider's
terms.

Only scan targets you own or are authorized to assess. Active tools can create
load or alter state; prefer staging.

## Network and configuration

The default bind is `127.0.0.1`. For remote access, use an HTTPS reverse proxy
or a specific private interface plus firewall rules. Do not publish the default
plain-HTTP port to the internet.

| Variable | Default | Purpose |
|---|---|---|
| `CERBERUS_BIND` | `127.0.0.1` | Published host interface |
| `CERBERUS_PORT` | `8099` | Published host port |
| `CERBERUS_ENABLE_ACTIVE_SCANS` | `false` | Enables the confirmed active head |
| `CERBERUS_API_KEY` | empty | Optional script/API authentication |
| `CERBERUS_DATA_VOLUME` | `cerberus-data` | Active database generation |
| `CERBERUS_CODEX_VOLUME` | `cerberus-codex` | Dedicated Codex sign-in state |

Release images are `romanvaxman/cerberus-selfhost:0.2.0`,
`romanvaxman/cerberus-tools:0.2.0`, `romanvaxman/cerberus-zap:0.2.0`, and the
optional `romanvaxman/cerberus-aio:0.2.0` launcher. Public installs pull images;
development builds use `compose.dev.yaml`.

## API

Set `CERBERUS_API_KEY`, then:

```bash
curl -H "X-API-Key: $CERBERUS_API_KEY" http://127.0.0.1:8099/history
curl -X POST http://127.0.0.1:8099/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $CERBERUS_API_KEY" \
  -d '{"url":"https://example.com","heads":["frontend","nose","speed"]}'
```

Poll `GET /scan/<job_id>`. Public `GET /health` reports app/schema versions
without exposing credentials.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests
docker compose -f compose.yaml -f compose.dev.yaml build
```

## Support and policies

Cerberus is free software. If it saves you time, you can
[feed Cerberus's dad a coffee](https://buymeacoffee.com/romanvaxman).
Contributions do not purchase support, features, or an SLA.

- [Help and operations](docs/HELP.md)
- [Installation guide](docs/INSTALL.md)
- [Public Help](https://cerberusscan.com/help)
- [Public installation instructions](https://cerberusscan.com/install)
- [Privacy](PRIVACY.md)
- [Terms](TERMS.md)
- [Security and authorization disclaimer](DISCLAIMER.md)
- [Security policy](SECURITY.md)

Copyright 2026 CTF Designs. Licensed under the GNU Affero General Public
License v3.0. The Cerberus and CTF Designs names and logos are not licensed for
misleading endorsement.
