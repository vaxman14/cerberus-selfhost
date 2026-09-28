# Cerberus Self-Hosted Help

## AI Lab

AI Lab is an optional companion service for source-assisted testing of your own
application. Set a separate `CERBERUS_AI_PASSWORD` in `.env`, then create the
installation master-key file and start it:

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/cerberus_master_key
chmod 600 secrets/cerberus_master_key
./scripts/init-vault.sh
docker compose -f compose.yaml -f compose.ai-lab.yaml up -d
```

Back up `secrets/cerberus_master_key` separately. The key is never stored in the
database or image; losing it makes the encrypted provider credentials
unrecoverable. The external key volume is not removed by
`docker compose down --volumes`. Configure the model in the Cerberus console, discover its real
model list, save it, and run the four capability probes. Supply a Git repository
and choose source-only **Review** or **Provision + DAST**. Provision mode builds
and runs untrusted project code inside the isolated AI Lab service; use
sanitized source and data.

Provider profiles live encrypted in `cerberus-data`; scans and reports live in
`cerberus-ai-data`. To remove retained data, stop the stack, inspect the exact
names with `docker volume ls`, then remove the intended volumes explicitly.

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
