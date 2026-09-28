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

Setup generates local secrets, pulls the versioned public images, starts the
isolated stack, waits for health, and prints the local URL. Open
<http://127.0.0.1:8099> and create the first local owner with a password of at
least 12 characters.

Verify the installation:

```bash
docker compose ps
curl http://127.0.0.1:8099/health
```

Active Nuclei, OWASP ZAP, and sqlmap scans are disabled by default. Enabling
them still requires explicit authorization and production-risk confirmation
for every target. Only scan systems you own or are authorized to assess.

## Remote Docker host

Keep the default localhost bind and create a tunnel from your computer:

```bash
ssh -L 8099:127.0.0.1:8099 user@docker-host
```

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
  romanvaxman/cerberus-aio:0.2.0
```

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

## Data, updates, and removal

```bash
./scripts/backup.sh
./scripts/update.sh
docker compose down
```

Ordinary `docker compose down` preserves local volumes.
`docker compose down --volumes` permanently deletes them. Back up
`secrets/cerberus_master_key` separately from database archives or saved
provider credentials cannot be decrypted after recovery.

Continue with the [Help and operations guide](HELP.md) for backup, restore,
password recovery, updates, troubleshooting, and safe network exposure.

Public web documentation:

- [Installation guide](https://cerberusscan.com/install)
- [Help and operations](https://cerberusscan.com/help)
