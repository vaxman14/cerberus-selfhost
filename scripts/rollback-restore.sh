#!/bin/sh
set -eu

usage() {
  echo "Usage: $0 .env.pre-restore-TIMESTAMP --confirm-rollback" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
saved_env=$1
[ "$2" = "--confirm-rollback" ] || usage
[ -f "$saved_env" ] || { echo "Rollback environment not found: $saved_env" >&2; exit 1; }

old_volume=$(sed -n 's/^CERBERUS_DATA_VOLUME=//p' "$saved_env" | tail -n1)
old_volume=${old_volume:-cerberus-data}
docker volume inspect "$old_volume" >/dev/null 2>&1 || {
  echo "Rollback volume is missing: $old_volume" >&2; exit 1;
}

current_env=".env.pre-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
cp .env "$current_env"
chmod 600 "$current_env"

app=$(docker compose ps -q cerberus)
if [ -n "$app" ]; then
  docker update --restart=no "$app" >/dev/null
  docker compose stop cerberus >/dev/null
fi

cp "$saved_env" .env
chmod 600 .env
sync .env 2>/dev/null || sync
docker compose up --no-deps --force-recreate secret-init >/dev/null
docker compose up -d --no-deps --force-recreate cerberus >/dev/null

app=$(docker compose ps -q cerberus)
tries=0
while :; do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$app")
  [ "$health" = healthy ] && break
  tries=$((tries + 1))
  [ "$tries" -lt 60 ] || {
    echo "Rollback app did not become healthy; inspect docker compose logs" >&2
    exit 1
  }
  sleep 2
done
docker update --restart=unless-stopped "$app" >/dev/null

echo "Rollback complete. Active volume: $old_volume"
echo "Pre-rollback environment preserved: $current_env"
