# Cerberus Self-Hosted Help

## AI Lab

AI Lab is an optional companion service for source-assisted testing of your own
application. Set a separate `CERBERUS_AI_PASSWORD` in `.env`, then start it:

```bash
docker compose -f compose.yaml -f compose.ai-lab.yaml up -d
```

Its dashboard listens on `127.0.0.1:9137` by default. Configure your own LLM
in Settings, supply a Git repository or source archive, and choose source-only
**Review** or **Provision + DAST**. Provision mode builds and runs untrusted
project code inside the isolated AI Lab service; use sanitized source and data.

To remove retained Lab settings, model credentials, scans, and reports, stop
the stack, inspect the exact name with `docker volume ls`, then remove its
`cerberus-ai-data` volume intentionally.

## Install

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
cp .env.example .env
# Set a long, random CERBERUS_API_KEY in .env
docker compose up -d --build
```

Open <http://127.0.0.1:8099> on the Docker host. Keep the default localhost
bind unless you place Cerberus behind a TLS reverse proxy and restrict access.

## Check and troubleshoot

```bash
docker compose ps
docker compose logs --tail=200 cerberus
curl http://127.0.0.1:8099/health
```

If unlock fails, verify the key in `.env` and recreate the container. Never
commit `.env`. Scan history is in `/data/cerberus.db` in the named volume.

## Update

```bash
git pull --ff-only
docker compose up -d --build
```

Back up the Docker volume before upgrades. `docker compose down` preserves it;
`docker compose down --volumes` intentionally destroys saved history.

Only scan authorized targets. For more help, see
<https://cerberusscan.com/help.html> or open a GitHub issue. Report security
problems privately using [SECURITY.md](../SECURITY.md).
