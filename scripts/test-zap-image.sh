#!/bin/sh
set -eu

zap_image=${1:-cerberus-zap:ci}
app_image=${2:-cerberus-selfhost:ci}
suffix=$$
network="cerberus-zap-proof-${suffix}"
zap="cerberus-zap-proof-${suffix}"
target="cerberus-zap-target-${suffix}"

cleanup() {
    docker rm -f "$zap" "$target" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create "$network" >/dev/null
docker run -d --name "$target" --network "$network" --entrypoint python \
    "$app_image" -m http.server 8080 >/dev/null
docker run -d --name "$zap" --network "$network" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,mode=1777,size=256m \
    --tmpfs /zap/wrk:rw,nosuid,uid=1000,gid=1000,size=512m \
    --tmpfs /home/zap/.ZAP:rw,nosuid,uid=1000,gid=1000,size=512m \
    "$zap_image" zap.sh -daemon -silent -host 0.0.0.0 -port 8080 \
    -config api.disablekey=false -config api.key=testkey \
    '-config' 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true >/dev/null

ready=false
for _ in $(seq 1 45); do
    if docker exec "$zap" wget -q -O- \
        'http://127.0.0.1:8080/JSON/core/view/version/?apikey=testkey' >/dev/null 2>&1 \
        && docker exec "$zap" wget -q -O- "http://${target}:8080/" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
[ "$ready" = true ] || { docker logs "$zap"; exit 1; }

addons=$(docker exec "$zap" wget -q -O- \
    'http://127.0.0.1:8080/JSON/autoupdate/view/installedAddons/?apikey=testkey')
for addon in network spider ascanrules pscanrules database oast pscan; do
    printf '%s' "$addons" | grep -q '"id":"'"$addon"'"'
done

encoded_target="http%3A%2F%2F${target}%3A8080%2F"
docker exec "$zap" wget -q -O- \
    "http://127.0.0.1:8080/JSON/core/action/accessUrl/?apikey=testkey&url=${encoded_target}&followRedirects=true" >/dev/null

spider_result=$(docker exec "$zap" wget -q -O- \
    "http://127.0.0.1:8080/JSON/spider/action/scan/?apikey=testkey&url=${encoded_target}")
spider_id=$(printf '%s' "$spider_result" | sed -n 's/.*"scan":"\([^"]*\)".*/\1/p')
[ -n "$spider_id" ]
for _ in $(seq 1 45); do
    spider_status=$(docker exec "$zap" wget -q -O- \
        "http://127.0.0.1:8080/JSON/spider/view/status/?apikey=testkey&scanId=${spider_id}")
    printf '%s' "$spider_status" | grep -q '"status":"100"' && break
    sleep 1
done
printf '%s' "$spider_status" | grep -q '"status":"100"'

active_result=$(docker exec "$zap" wget -q -O- \
    "http://127.0.0.1:8080/JSON/ascan/action/scan/?apikey=testkey&url=${encoded_target}")
active_id=$(printf '%s' "$active_result" | sed -n 's/.*"scan":"\([^"]*\)".*/\1/p')
[ -n "$active_id" ]
for _ in $(seq 1 60); do
    active_status=$(docker exec "$zap" wget -q -O- \
        "http://127.0.0.1:8080/JSON/ascan/view/status/?apikey=testkey&scanId=${active_id}")
    printf '%s' "$active_status" | grep -q '"status":"100"' && break
    sleep 1
done
printf '%s' "$active_status" | grep -q '"status":"100"'

if docker logs "$zap" 2>&1 | grep -E ' ERROR |Failed to initialise|Exception'; then
    exit 1
fi

echo "ZAP image proof passed: required add-ons, spider, and active scan"
