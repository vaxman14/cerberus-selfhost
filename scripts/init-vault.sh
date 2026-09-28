#!/bin/sh
set -eu

key_file=${1:-secrets/cerberus_master_key}
volume=${CERBERUS_MASTER_KEY_VOLUME:-cerberus-master-key}

if [ ! -f "$key_file" ]; then
  echo "No master key at $key_file" >&2
  echo "Generate one with: mkdir -p secrets && openssl rand -base64 32 > $key_file && chmod 600 $key_file" >&2
  exit 1
fi

mode=$(stat -c '%a' "$key_file" 2>/dev/null || stat -f '%Lp' "$key_file")
case "$mode" in
  600|400) ;;
  *) echo "Master key must be mode 600 or 400; got $mode" >&2; exit 1 ;;
esac

decoded_bytes=$(openssl base64 -d -A < "$key_file" | wc -c | tr -d ' ')
if [ "$decoded_bytes" != "32" ]; then
  echo "Master key must decode to exactly 32 bytes" >&2
  exit 1
fi

docker volume create "$volume" >/dev/null
docker run --rm -i --user 0 -v "$volume:/vault" python:3.12-slim sh -ceu '
  umask 077
  tmp=/vault/.master_key.tmp
  target=/vault/master_key
  trap "rm -f $tmp" EXIT
  cat > "$tmp"
  chmod 600 "$tmp"
  chown 100:101 "$tmp"
  mv -f "$tmp" "$target"
  trap - EXIT
' < "$key_file"

echo "Cerberus master key installed in external Docker volume: $volume"
