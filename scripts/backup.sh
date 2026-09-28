#!/bin/sh
set -eu

umask 077
mkdir -p backups
stamp=$(date -u +%Y%m%dT%H%M%SZ)
final="backups/cerberus-$stamp.tar.gz"
pending="$final.pending"
trap 'rm -f "$pending"' EXIT HUP INT TERM

docker compose exec -T cerberus python -m cerberus.backupctl export > "$pending"
image=$(docker compose config --images | awk '/cerberus-selfhost/{print; exit}')
[ -n "$image" ] || { echo "Cannot resolve the Cerberus image" >&2; exit 1; }

docker run --rm -i --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  "$image" sh -c \
  'cat > /tmp/backup.tar.gz && python -m cerberus.backupctl verify /tmp/backup.tar.gz' \
  < "$pending" >/dev/null

digest=$(openssl dgst -sha256 "$pending" | awk '{print $NF}')
mv "$pending" "$final"
printf '%s  %s\n' "$digest" "$(basename "$final")" > "$final.sha256"
chmod 600 "$final" "$final.sha256"
sync "$final" "$final.sha256" 2>/dev/null || sync
trap - EXIT HUP INT TERM

echo "Backup verified: $final"
echo "Digest: $digest"
echo "Keep secrets/cerberus_master_key in a separate protected backup."
