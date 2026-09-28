# Cerberus

Cerberus is a free, self-hosted website security and quality scanner with local
users, scan history, reports, and optional AI analysis. It combines passive
checks with local Lighthouse and explicitly authorized Nuclei, OWASP ZAP, and
sqlmap testing.

> **This image is the application service, not the complete stack.** Cerberus
> also uses isolated tools, ZAP, and secret-initialization containers. Use the
> Compose quick start below instead of running this image by itself.

## Install

Requirements: Docker Engine, Docker Compose v2, OpenSSL, Git, and roughly 8 GB
of free disk space.

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
./scripts/setup.sh
```

Setup generates local secrets, pulls the versioned Docker Hub images, starts
the complete stack, waits for health, and prints the URL. Open
<http://127.0.0.1:8099> and create the first local owner.

If Docker is on another machine, keep the safe localhost bind and create an SSH
tunnel from your computer:

```bash
ssh -L 8099:127.0.0.1:8099 user@docker-host
```

Then open <http://127.0.0.1:8099> locally.

## Safe defaults

- Binds only to `127.0.0.1`
- Requires a local owner login
- Keeps the app database and provider vault on your Docker host
- Publishes no scanner-worker ports
- Disables active Nuclei, ZAP, and sqlmap scans
- Runs containers with read-only roots, dropped capabilities, and
  `no-new-privileges`

To enable active tools, set `CERBERUS_ENABLE_ACTIVE_SCANS=true` in `.env` and
run `docker compose up -d`. Every active run still requires explicit
authorization and production-risk confirmation. Only scan systems you own or
are authorized to assess.

## Operations

```bash
docker compose ps
docker compose logs --tail=200 cerberus
./scripts/backup.sh
./scripts/update.sh
docker compose down
```

Ordinary `docker compose down` preserves data. `docker compose down --volumes`
permanently deletes local volumes. Back up `secrets/cerberus_master_key`
separately from database archives; saved provider credentials cannot be
decrypted without it.

## Images

- `romanvaxman/cerberus-selfhost:0.2.0`
- `romanvaxman/cerberus-tools:0.2.0`
- `romanvaxman/cerberus-zap:0.2.0`
- `romanvaxman/cerberus-aio:0.2.0` — optional Docker-socket launcher

Images support `linux/amd64` and `linux/arm64`.

## Links

- [Step-by-step installation guide](https://cerberusscan.com/install)
- [Help and operations](https://cerberusscan.com/help)
- [Source and complete documentation](https://github.com/vaxman14/cerberus-selfhost)
- [Release v0.2.0](https://github.com/vaxman14/cerberus-selfhost/releases/tag/v0.2.0)
- [Help and operations](https://github.com/vaxman14/cerberus-selfhost/blob/main/docs/HELP.md)
- [Security policy](https://github.com/vaxman14/cerberus-selfhost/blob/main/SECURITY.md)
- [Terms and authorization requirements](https://github.com/vaxman14/cerberus-selfhost/blob/main/TERMS.md)
- [AGPL-3.0 license](https://github.com/vaxman14/cerberus-selfhost/blob/main/LICENSE)

Cerberus is free software. Contributions do not purchase support, features, or
an SLA.
