#!/bin/sh
set -eu

die() {
  echo "Cerberus AIO: $*" >&2
  exit 1
}

[ -S /var/run/docker.sock ] || die "mount /var/run/docker.sock to use the AIO launcher"
docker version >/dev/null 2>&1 || die "cannot reach the host Docker daemon"

umask 077
mkdir -p /config
if [ ! -s /config/cerberus_master_key ]; then
  openssl rand -base64 32 > /config/cerberus_master_key
fi
if [ ! -s /config/cerberus_tools_token ]; then
  openssl rand -hex 32 > /config/cerberus_tools_token
fi
if [ ! -s /config/cerberus_zap_api_key ]; then
  openssl rand -hex 32 > /config/cerberus_zap_api_key
fi
chmod 600 /config/cerberus_master_key /config/cerberus_tools_token /config/cerberus_zap_api_key

decoded_bytes=$(openssl base64 -d -A < /config/cerberus_master_key | wc -c | tr -d ' ')
[ "$decoded_bytes" = 32 ] || die "the persisted master key is invalid"

export CERBERUS_AIO_CONFIG_VOLUME="${CERBERUS_AIO_CONFIG_VOLUME:-cerberus-aio-config}"
docker volume inspect "$CERBERUS_AIO_CONFIG_VOLUME" >/dev/null 2>&1 || \
  die "the /config mount must use the named volume $CERBERUS_AIO_CONFIG_VOLUME"

compose() {
  docker compose --project-name cerberus-aio --file /opt/cerberus/compose.yaml "$@"
}

echo "Cerberus AIO: pulling child images"
if [ "${CERBERUS_AIO_SKIP_PULL:-0}" != 1 ]; then
  compose pull
fi
compose up --no-deps --force-recreate secret-init
compose up -d --remove-orphans

master_container=$(hostname)
docker network connect cerberus-aio_default "$master_container" 2>/dev/null || true

echo "Cerberus AIO: child stack started; proxy listening on container port 8099"
echo "Cerberus AIO: open http://DOCKER-HOST-IP:8099 (or http://127.0.0.1:8099 on the Docker host)"
echo "Cerberus AIO: restarting this master checks for image updates"
exec socat TCP-LISTEN:8099,fork,reuseaddr TCP:cerberus:8099
