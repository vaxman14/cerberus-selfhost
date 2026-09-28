#!/bin/sh
set -eu

die() {
  echo "Cerberus setup: $*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || die "Docker is required"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
command -v openssl >/dev/null 2>&1 || die "OpenSSL is required"

umask 077
mkdir -p secrets backups .cerberus-restore

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
fi

generate_hex() {
  destination=$1
  if [ ! -s "$destination" ]; then
    openssl rand -out "$destination" -hex 32
    chmod 600 "$destination"
  fi
}

if [ ! -s secrets/cerberus_master_key ]; then
  openssl rand -base64 32 > secrets/cerberus_master_key
  chmod 600 secrets/cerberus_master_key
fi

decoded_bytes=$(openssl base64 -d -A < secrets/cerberus_master_key | wc -c | tr -d ' ')
[ "$decoded_bytes" = 32 ] || die "secrets/cerberus_master_key must decode to 32 bytes"

generate_hex secrets/cerberus_tools_token
generate_hex secrets/cerberus_zap_api_key

if [ "${CERBERUS_SETUP_SKIP_PULL:-0}" != 1 ]; then
  docker compose pull
fi
docker compose up --no-deps --force-recreate secret-init
docker compose up -d

container_id=$(docker compose ps -q cerberus)
[ -n "$container_id" ] || die "Cerberus container did not start"

tries=0
while :; do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")
  [ "$health" = healthy ] && break
  tries=$((tries + 1))
  [ "$tries" -lt 90 ] || die "Cerberus did not become healthy; run: docker compose logs --tail=200"
  sleep 2
done

bind=${CERBERUS_BIND:-$(sed -n 's/^CERBERUS_BIND=//p' .env | tail -n1)}
port=${CERBERUS_PORT:-$(sed -n 's/^CERBERUS_PORT=//p' .env | tail -n1)}
bind=${bind:-127.0.0.1}
port=${port:-8099}

echo "Cerberus is healthy: http://$bind:$port"
echo "Open that URL and create the first local owner account."
echo "Back up secrets/cerberus_master_key separately from database backups."
