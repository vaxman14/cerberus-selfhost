#!/bin/sh
set -eu

command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }

echo "Creating a verified pre-update backup..."
backup_output=$(./scripts/backup.sh)
printf '%s\n' "$backup_output"

docker compose pull
docker compose up --no-deps --force-recreate secret-init
docker compose up -d --remove-orphans

container_id=$(docker compose ps -q cerberus)
[ -n "$container_id" ] || { echo "Cerberus container did not start" >&2; exit 1; }
tries=0
while :; do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")
  [ "$health" = healthy ] && break
  tries=$((tries + 1))
  [ "$tries" -lt 90 ] || {
    echo "Update did not become healthy. The verified backup above is preserved." >&2
    exit 1
  }
  sleep 2
done

docker image prune -f --filter 'until=168h' >/dev/null 2>&1 || true
echo "Cerberus update complete and healthy."
