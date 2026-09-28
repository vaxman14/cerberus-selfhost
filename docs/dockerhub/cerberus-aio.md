![Cerberus Scan](https://raw.githubusercontent.com/vaxman14/cerberus-selfhost/main/console/cerberus-logo.jpg)

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
  -p 8099:8099 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v cerberus-aio-config:/config \
  -e CERBERUS_AIO_CONFIG_VOLUME=cerberus-aio-config \
  -e CERBERUS_ENABLE_ACTIVE_SCANS=false \
  romanvaxman/cerberus-aio:0.2.1
```

### What every line does

- `docker volume create cerberus-aio-config` creates a persistent Docker volume
  for generated secrets and AIO configuration. Replacing the launcher container
  does not delete this volume.
- `docker run -d` creates and starts the launcher in the background. The `\` at
  the end of each following line means the command continues on the next line.
- `--name cerberus-aio` gives the launcher a predictable name for logs,
  restarts, and replacement commands.
- `--restart unless-stopped` starts the launcher again after a Docker-host
  reboot unless you deliberately stopped it.
- `-p 8099:8099` publishes the Cerberus web interface on port `8099` of every
  host interface, making it reachable from your LAN. Do not expose this port to
  the public internet.
- `-v /var/run/docker.sock:/var/run/docker.sock` lets the launcher ask the host
  Docker daemon to create the isolated app, tools, and ZAP containers. This is
  required by AIO and grants the launcher effective control of the Docker host.
- `-v cerberus-aio-config:/config` mounts the persistent configuration volume at
  `/config` inside the launcher.
- `-e CERBERUS_AIO_CONFIG_VOLUME=cerberus-aio-config` tells the launcher the
  exact named volume its child containers must use for shared generated
  secrets. The name must match the volume mounted at `/config`.
- `-e CERBERUS_ENABLE_ACTIVE_SCANS=false` keeps Nuclei, ZAP, and sqlmap scans
  disabled. Passive checks still work; enable active scans only when you
  understand their impact and have authorization for every target.
- `romanvaxman/cerberus-aio:0.2.1` is the exact launcher image and immutable
  release tag Docker runs. Pinning the version avoids an unexpected launcher
  upgrade.

## Open Cerberus after installation

The AIO command publishes port `8099` on the Docker host so a browser on your
LAN can reach it. Do not expose or port-forward `8099` to the public internet.
If the host has a public interface, restrict the port with its firewall or bind
it to a specific private address, for example
`-p 192.168.1.50:8099:8099`.

Follow startup progress:

```bash
docker logs -f cerberus-aio
```

`docker logs` reads the launcher's output, and `-f` keeps following new lines
while the child containers start.

When the log reports `proxy listening on container port 8099`, press `Ctrl+C`
to stop following the logs. This does not stop Cerberus. Then open
**`http://DOCKER-HOST-IP:8099`** in a browser and create the first local owner
immediately. On the Docker host itself, <http://127.0.0.1:8099> also works.

If LAN access is unavailable or you prefer not to publish a LAN port, bind to
localhost instead with `-p 127.0.0.1:8099:8099`, then create an SSH tunnel from
your computer:

```bash
ssh -L 8099:127.0.0.1:8099 user@docker-host
```

Keep the SSH session open, then open **<http://127.0.0.1:8099>** in the browser
on your computer.

## Data and updates

The database, Codex state, master key, and runtime secrets use named Docker
volumes. Restarting the AIO launcher pulls the configured child images and
reconciles the stack:

```bash
docker restart cerberus-aio
```

This restarts only the AIO launcher. On startup it pulls the configured child
images and reconciles the child stack. Named data and configuration volumes are
preserved.

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
- [Release v0.2.1](https://github.com/vaxman14/cerberus-selfhost/releases/tag/v0.2.1)
- [Security policy](https://github.com/vaxman14/cerberus-selfhost/blob/main/SECURITY.md)
- [AGPL-3.0 license](https://github.com/vaxman14/cerberus-selfhost/blob/main/LICENSE)

Cerberus is free software. Contributions do not purchase support, features, or
an SLA.
