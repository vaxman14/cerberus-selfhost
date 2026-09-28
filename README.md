# Cerberus

Cerberus is a free, self-hosted website security and quality scanner. Its
Docker quick start runs passive checks against public website content:

- **The Surface** checks HTTPS, security headers, cookie flags, exposed files,
  source maps, and common client-side secret patterns.
- **The Nose** checks public technology disclosures, SPF, DMARC,
  `security.txt`, directory listings, and WordPress user exposure.
- **The Health** runs Lighthouse locally in an isolated Chromium worker.
- **The Hunt** runs explicitly authorized Nuclei, OWASP ZAP, and conservative
  sqlmap checks from isolated containers.

Results and history stay in a local SQLite database inside a Docker volume.
There is no required cloud account, hosted database, analytics service, or
external login provider.

## Local users and AI analysis

The web console is protected by a local owner account stored in SQLite with an
Argon2id password hash. On an empty installation the first page creates that
owner. For a non-interactive deployment, create
`secrets/cerberus_bootstrap_password`, set the three documented bootstrap
variables in `.env`, or run:

```bash
docker compose run --rm cerberus python -m cerberus.userctl create --username admin
```

`CERBERUS_API_KEY` remains optional for scripts; it is not the browser login.

Cerberus can use a connected API provider, ChatGPT plan through the official
Codex CLI, or Claude plan through Claude Code to explain and prioritize saved
scanner findings. The model analyzes results; it does not replace or control
the scanners.

Generate the installation master key as a file, not an environment variable:

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/cerberus_master_key
chmod 600 secrets/cerberus_master_key
./scripts/init-vault.sh
```

Back that file up separately from the database. A database backup without the
original key deliberately cannot decrypt saved provider credentials. The script
copies it through stdin into the external `cerberus-master-key` Docker volume;
the application container remains non-root and the host copy remains mode 600.

Generate the two internal service credentials too:

```bash
openssl rand -out secrets/cerberus_tools_token -hex 32
openssl rand -out secrets/cerberus_zap_api_key -hex 32
chmod 600 secrets/*
```

The tools worker and ZAP have no published ports. They use read-only root
filesystems, dropped capabilities, `no-new-privileges`, resource ceilings, and
a private runtime-secret volume. Host secret files remain mode 600.

Provider keys are AES-256-GCM sealed in Cerberus's database with the
installation master key kept outside the database; API responses expose only
`has_api_key`. Requests to a remote model provider leave your machine and are
governed by that provider's terms and privacy policy.

Website, installation guide, and policies: <https://cerberusscan.com>

## Quick start

Requirements: Docker Engine with Docker Compose v2.

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
cp .env.example .env
```

Initialize the master-key volume and internal scanner credentials:

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/cerberus_master_key
openssl rand -out secrets/cerberus_tools_token -hex 32
openssl rand -out secrets/cerberus_zap_api_key -hex 32
chmod 600 secrets/*
./scripts/init-vault.sh
```

Start Cerberus:

```bash
docker compose up -d --build
docker compose ps
```

Open <http://127.0.0.1:8099> and create the first local owner account.

To stop:

```bash
docker compose down
```

`docker compose down` preserves scan history. Do not use `--volumes` unless
you deliberately intend to remove saved data and runtime volumes.

## Network access

The default bind is localhost. For access from another device, put Cerberus
behind an HTTPS reverse proxy, or set `CERBERUS_BIND` to a specific private
interface address and protect it with a firewall. Do not expose plain HTTP and
the API key directly to the public internet.

## Configuration

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `CERBERUS_API_KEY` | no | empty | Optional script/API authentication |
| `CERBERUS_BIND` | no | `127.0.0.1` | Host interface published by Compose |
| `CERBERUS_PORT` | no | `8099` | Host port published by Compose |
| `CERBERUS_ENABLE_ACTIVE_SCANS` | no | `true` | Makes the owner-confirmed active head available |

SQLite is stored at `/data/cerberus.db` in the `cerberus-data` volume.

## API

```bash
curl -H "X-API-Key: $CERBERUS_API_KEY" http://127.0.0.1:8099/history

curl -X POST http://127.0.0.1:8099/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $CERBERUS_API_KEY" \
  -d '{"url":"https://example.com","heads":["frontend","nose","speed"]}'
```

Poll the returned job at `GET /scan/<job_id>`. `GET /health` is public so
Docker can monitor the container without embedding the API key in image
metadata.

## Safety boundary

Only scan sites you own or are authorized to assess. Active testing requires a
local owner, an explicit per-scan authorization confirmation, and a separate
production-risk confirmation when the target is not a staging system. Nuclei,
ZAP, and sqlmap can create load or alter state; use staging whenever possible.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests
```

## Support the project

Cerberus is free software. If it saves you time, you can
[buy me a coffee](https://buymeacoffee.com/romanvaxman). Contributions do not
purchase support, features, or an SLA.

## Documentation and policies

- [Help and operations guide](docs/HELP.md)
- [Privacy](PRIVACY.md)
- [Terms of use](TERMS.md)
- [Security and authorization disclaimer](DISCLAIMER.md)
- [Security policy](SECURITY.md)

## License

Copyright 2026 CTF Designs. Licensed under the GNU Affero General Public
License v3.0. See the complete [LICENSE](LICENSE). The Cerberus and CTF
Designs names and logos are not licensed for misleading endorsement.
