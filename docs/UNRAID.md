# Unraid AIO

The optional `cerberus-aio` image gives Unraid Community Apps one installable
container while retaining Cerberus's isolated app, tools, and ZAP containers.
The master generates secrets in the `cerberus-aio-config` named volume and uses
Docker Compose through the host Docker socket to create the child stack.

## Security disclosure

Mounting `/var/run/docker.sock` gives the AIO master effective control of the
Docker host. Use only the official release image and review updates. The
ordinary repository Compose install does **not** mount the Docker socket and is
the safer choice when one-click Unraid installation is not required.

The web UI is published on host port `8099` for LAN access. Do not expose or
port-forward that port to the public internet; use the host firewall or a
restricted HTTPS reverse proxy when the Docker host has a public interface.

## Updates and data

Restarting the AIO master pulls the configured child images and reconciles the
stack. The database, Codex state, master key, and runtime secrets use named
volumes and survive master replacement. Back up `cerberus-aio-config` separately
from `cerberus-aio-data` because the former contains the encryption key.

The template must be validated and scanned at <https://ca.unraid.net/submit>
before anyone describes it as available in Community Apps.
