# Cerberus Self-Hosted Help

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
