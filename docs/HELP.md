# Cerberus Self-Hosted Help

## Local scanner stack and AI analysis

Cerberus runs Lighthouse, Nuclei, and sqlmap in the `cerberus-tools` worker and
OWASP ZAP in its own container. Neither service publishes a host port. Create
the installation master key and internal service credentials before starting:

```bash
mkdir -p secrets
openssl rand -base64 32 > secrets/cerberus_master_key
openssl rand -out secrets/cerberus_tools_token -hex 32
openssl rand -out secrets/cerberus_zap_api_key -hex 32
chmod 600 secrets/*
./scripts/init-vault.sh
docker compose up -d --build
```

Back up `secrets/cerberus_master_key` separately. The key is never stored in the
database or image; losing it makes the encrypted provider credentials
unrecoverable. The external key volume is not removed by
`docker compose down --volumes`. Configure a model in **AI report analysis**,
discover its model list, save it, and run the capability probes. Proven profiles
can summarize a saved scan; they do not run the security tools. Use **Delete**
beside a saved model profile to remove its local profile, sealed credential,
bridge tokens, and analyses created with it. This does not delete the upstream
provider account.

While a scan is running, **Stop scan** cancels the active local scanner process
or ZAP operation and discards partial results rather than saving an incomplete
report.

## Install

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
cp .env.example .env
# Create secrets as shown above; optionally set CERBERUS_API_KEY for scripts
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

If login fails, use the local owner created on first run. A first owner can also
be created with `python -m cerberus.userctl create` inside the container. Never
commit `.env` or `secrets/`. Scan history is in `/data/cerberus.db`.

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
