# Cerberus AIO

Cerberus AIO is the Docker Hub-only launcher for Cerberus. It generates local
secrets and starts the isolated Cerberus app, Lighthouse/Nuclei/sqlmap tools,
and OWASP ZAP containers for you.

## Security warning

The AIO launcher mounts `/var/run/docker.sock`. That gives it effective control
of the Docker host. Use only the official image and review release notes before
updating. The ordinary
[Compose installation](https://github.com/vaxman14/cerberus-selfhost#quick-start)
does not mount the Docker socket and is the safer recommended option.

## Install directly from Docker Hub

Requirements: Docker Engine and roughly 8 GB of free disk space.

```bash
docker volume create cerberus-aio-config

docker run -d \
  --name cerberus-aio \
  --restart unless-stopped \
  -p 127.0.0.1:8099:8099 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v cerberus-aio-config:/config \
  -e CERBERUS_AIO_CONFIG_VOLUME=cerberus-aio-config \
  -e CERBERUS_ENABLE_ACTIVE_SCANS=false \
  romanvaxman/cerberus-aio:0.2.0
```

Follow startup progress:

```bash
docker logs -f cerberus-aio
```

When the log reports that the proxy is listening, open
<http://127.0.0.1:8099> and create the first local owner.

If Docker is on another machine, create an SSH tunnel from your computer:

```bash
ssh -L 8099:127.0.0.1:8099 user@docker-host
```

Then open <http://127.0.0.1:8099> locally.

## Data and updates

The database, Codex state, master key, and runtime secrets use named Docker
volumes. Restarting the AIO launcher pulls the configured child images and
reconciles the stack:

```bash
docker restart cerberus-aio
```

Back up both `cerberus-aio-config` and `cerberus-aio-data`. The configuration
volume contains the encryption key required to decrypt saved provider
credentials.

Active Nuclei, ZAP, and sqlmap scans are disabled by default. Only scan systems
you own or are authorized to assess.

## Links

- [Step-by-step installation guide](https://cerberusscan.com/install)
- [Help and operations](https://cerberusscan.com/help)
- [Source and complete documentation](https://github.com/vaxman14/cerberus-selfhost)
- [AIO security and operations notes](https://github.com/vaxman14/cerberus-selfhost/blob/main/docs/UNRAID.md)
- [Release v0.2.0](https://github.com/vaxman14/cerberus-selfhost/releases/tag/v0.2.0)
- [Security policy](https://github.com/vaxman14/cerberus-selfhost/blob/main/SECURITY.md)
- [AGPL-3.0 license](https://github.com/vaxman14/cerberus-selfhost/blob/main/LICENSE)

Cerberus is free software. Contributions do not purchase support, features, or
an SLA.
