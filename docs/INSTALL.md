# Install Cerberus

Cerberus supports `linux/amd64` and `linux/arm64`. The standard Docker Compose
installation is recommended because it does not mount the Docker socket.

## Requirements

- Docker Engine with Docker Compose v2
- Git and OpenSSL
- Approximately 8 GB of free disk space
- Recommended: 4 CPU cores and 8 GB RAM

## Standard Docker Compose installation

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
./scripts/setup.sh
```

- `git clone ...` downloads the public Cerberus source and Compose files into a
  new `cerberus-selfhost` directory.
- `cd cerberus-selfhost` makes that new directory the current working directory
  so the remaining commands use its files.
- `./scripts/setup.sh` generates local secrets, pulls the pinned public images,
  starts the isolated stack, waits for its health check, and prints the URL.

Setup generates local secrets, pulls the versioned public images, starts the
isolated stack, waits for health, and prints the local URL. Open
<http://127.0.0.1:8099> and create the first local owner with a password of at
least 12 characters.

Verify the installation:

```bash
docker compose ps
curl http://127.0.0.1:8099/health
```

- `docker compose ps` shows each service and whether it is running and healthy.
- `curl .../health` asks the local unauthenticated health endpoint to confirm
  that the web application is responding.

Active Nuclei, OWASP ZAP, and sqlmap scans are disabled by default. Enabling
them still requires explicit authorization and production-risk confirmation
for every target. Only scan systems you own or are authorized to assess.

## Remote Docker host

Keep the default localhost bind and create a tunnel from your computer:

```bash
ssh -L 8099:127.0.0.1:8099 user@docker-host
```

This opens an SSH session and forwards port `8099` on your computer to the
localhost-only Cerberus port on the Docker host. Replace `user@docker-host` with
your real SSH username and hostname or IP address.

Keep that terminal open, then visit <http://127.0.0.1:8099> locally. For
permanent remote access, use an HTTPS reverse proxy with restricted access.
Never publish the tools or ZAP worker ports.

## Docker Hub AIO alternative

The optional AIO launcher mounts `/var/run/docker.sock`, which gives it
effective control of the Docker host. Use the standard Compose installation
unless you specifically need the one-container launcher.

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

### What every AIO line does

- `docker volume create cerberus-aio-config` creates persistent storage for
  generated secrets and AIO configuration. Replacing the launcher does not
  delete it.
- `docker run -d` creates and starts the launcher in the background. A trailing
  `\` continues the same command on the next line.
- `--name cerberus-aio` gives the launcher a predictable name for later log,
  restart, and replacement commands.
- `--restart unless-stopped` starts it after a host reboot unless you manually
  stopped it.
- `-p 8099:8099` publishes the web interface on port `8099` of every host
  interface for LAN access. Do not expose or port-forward it to the internet.
- `-v /var/run/docker.sock:/var/run/docker.sock` lets AIO create the child app,
  tools, and ZAP containers through the host Docker daemon. It is required for
  AIO and grants effective control of the Docker host.
- `-v cerberus-aio-config:/config` mounts the persistent configuration volume
  inside the launcher.
- `-e CERBERUS_AIO_CONFIG_VOLUME=cerberus-aio-config` tells AIO which exact
  named volume its child containers must use. It must match the `/config`
  volume name.
- `-e CERBERUS_ENABLE_ACTIVE_SCANS=false` keeps Nuclei, ZAP, and sqlmap disabled
  while leaving passive checks available.
- `romanvaxman/cerberus-aio:0.2.1` selects the exact immutable AIO release image
  instead of accepting an unexpected launcher upgrade.

The AIO command publishes port `8099` on the Docker host. Do not expose or
port-forward it to the public internet. If the host has a public interface,
restrict the port with its firewall or bind it to a specific private address,
for example `-p 192.168.1.50:8099:8099`.

Follow startup progress with `docker logs -f cerberus-aio`. When the log reports
`proxy listening on container port 8099`, press `Ctrl+C`; this stops following
the logs but leaves Cerberus running. Then open
**`http://DOCKER-HOST-IP:8099`** in a browser and create the first owner
immediately. On the Docker host itself, <http://127.0.0.1:8099> also works. To
keep AIO localhost-only, use `-p 127.0.0.1:8099:8099` and the SSH tunnel
described above.

Restarting AIO with `docker restart cerberus-aio` makes the launcher pull the
configured child images and reconcile the child stack. It preserves the named
configuration and data volumes.

## Standard Compose data, updates, and removal

```bash
./scripts/backup.sh
./scripts/update.sh
docker compose down
```

- `./scripts/backup.sh` creates and verifies a timestamped backup archive.
- `./scripts/update.sh` creates a safety backup, pulls the configured images,
  restarts the stack, and waits for health.
- `docker compose down` stops and removes the Compose containers and network but
  preserves named volumes and their data.

Ordinary `docker compose down` preserves local volumes.
`docker compose down --volumes` permanently deletes them. Back up
`secrets/cerberus_master_key` separately from database archives or saved
provider credentials cannot be decrypted after recovery.

Continue with the [Help and operations guide](HELP.md) for backup, restore,
password recovery, updates, troubleshooting, and safe network exposure.

Public web documentation:

- [Installation guide](https://cerberusscan.com/install)
- [Help and operations](https://cerberusscan.com/help)
