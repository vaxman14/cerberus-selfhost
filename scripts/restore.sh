#!/bin/sh
set -eu

usage() {
  echo "Usage: $0 BACKUP.tar.gz --confirm-replace" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
archive=$1
[ "$2" = "--confirm-replace" ] || usage
[ -f "$archive" ] || { echo "Backup not found: $archive" >&2; exit 1; }
[ -f "$archive.sha256" ] || { echo "Missing digest receipt: $archive.sha256" >&2; exit 1; }

umask 077
mkdir -p .cerberus-restore
request=$(date -u +%Y%m%dT%H%M%SZ)-$$
journal=".cerberus-restore/$request.json"
old_volume=$(docker compose config --format json | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["volumes"]["cerberus-data"]["name"])')
candidate="$old_volume-restore-$request"
image=$(docker compose config --images | awk '/cerberus-selfhost/{print; exit}')
key_volume=$(docker compose config --format json | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["volumes"]["cerberus-master-key"]["name"])')

write_journal() {
  phase=$1
  tmp="$journal.pending"
  printf '{"request":"%s","phase":"%s","archive":"%s","old_volume":"%s","candidate_volume":"%s"}\n' \
    "$request" "$phase" "$archive" "$old_volume" "$candidate" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$journal"
  sync "$journal" 2>/dev/null || sync
}

expected=$(awk 'NR==1{print $1}' "$archive.sha256")
actual=$(openssl dgst -sha256 "$archive" | awk '{print $NF}')
[ "$expected" = "$actual" ] || { echo "Backup digest mismatch" >&2; exit 1; }
write_journal candidate_pending

[ -z "$(docker ps -aq --filter volume="$candidate")" ] || {
  echo "Candidate volume is already attached: $candidate" >&2; exit 1;
}
docker volume create "$candidate" >/dev/null
docker run --rm --user 0 --network none --read-only \
  -v "$candidate:/restore" "$image" chown cerberus:cerberus /restore
docker run --rm -i --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  -v "$candidate:/restore" \
  "$image" sh -c \
  'cat > /tmp/backup.tar.gz && python -m cerberus.backupctl restore /tmp/backup.tar.gz /restore/cerberus.db' \
  < "$archive" >/dev/null
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  -v "$candidate:/data:ro" -v "$key_volume:/run/cerberus-vault:ro" \
  "$image" python -m cerberus.backupctl prove \
  /data/cerberus.db /run/cerberus-vault/master_key >/dev/null
write_journal candidate_proven

running_writers=$(docker ps -q --filter volume="$old_volume" | wc -l | tr -d ' ')
[ "$running_writers" -le 1 ] || {
  echo "Refusing restore: multiple running containers mount $old_volume" >&2; exit 1;
}

app=$(docker compose ps -q cerberus)
[ -n "$app" ] || { echo "Cerberus app container is not present" >&2; exit 1; }
write_journal fencing_pending
docker update --restart=no "$app" >/dev/null
docker compose stop cerberus >/dev/null
[ -z "$(docker ps -q --filter volume="$old_volume")" ] || {
  echo "Refusing restore: a writer still mounts $old_volume" >&2; exit 1;
}
write_journal fenced

cp .env ".env.pre-restore-$request"
env_pending=".env.restore-pending"
awk -v volume="$candidate" '
  BEGIN { replaced=0 }
  /^CERBERUS_DATA_VOLUME=/ { print "CERBERUS_DATA_VOLUME=" volume; replaced=1; next }
  { print }
  END { if (!replaced) print "CERBERUS_DATA_VOLUME=" volume }
' .env > "$env_pending"
chmod 600 "$env_pending"
mv "$env_pending" .env
sync .env 2>/dev/null || sync
write_journal switch_pending

docker compose up -d --no-deps --force-recreate cerberus >/dev/null
new_app=$(docker compose ps -q cerberus)
tries=0
while :; do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$new_app")
  [ "$health" = healthy ] && break
  tries=$((tries + 1))
  [ "$tries" -lt 60 ] || {
    echo "Restored app did not become healthy. Writers remain fenced; inspect $journal" >&2
    exit 1
  }
  sleep 2
done

mounted=$(docker inspect "$new_app" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')
[ "$mounted" = "$candidate" ] || {
  echo "Restored app mounted unexpected data volume: $mounted" >&2; exit 1;
}
docker update --restart=unless-stopped "$new_app" >/dev/null
write_journal complete

echo "Restore complete. Active volume: $candidate"
echo "Rollback volume preserved: $old_volume"
echo "Rollback environment preserved: .env.pre-restore-$request"
echo "Journal: $journal"
