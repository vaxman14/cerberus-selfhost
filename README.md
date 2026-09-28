# Cerberus

Cerberus is a free, self-hosted website security and quality scanner. Its
Docker quick start runs passive checks against public website content:

- **The Surface** checks HTTPS, security headers, cookie flags, exposed files,
  source maps, and common client-side secret patterns.
- **The Nose** checks public technology disclosures, SPF, DMARC,
  `security.txt`, directory listings, and WordPress user exposure.
- **The Health** requests Google PageSpeed/Lighthouse performance and
  best-practices results.

Results and history stay in a local SQLite database inside a Docker volume.
There is no required cloud account, hosted database, analytics service, or
external login provider.

Website, installation guide, and policies: <https://cerberusscan.com>

## Quick start

Requirements: Docker Engine with Docker Compose v2.

```bash
git clone https://github.com/vaxman14/cerberus-selfhost.git
cd cerberus-selfhost
cp .env.example .env
```

Generate the API key and put the output after `CERBERUS_API_KEY=` in `.env`:

```bash
openssl rand -hex 32
```

Start Cerberus:

```bash
docker compose up -d --build
docker compose ps
```

Open <http://127.0.0.1:8099> and enter the same API key. The browser keeps it
in the current tab's session storage, not permanent browser storage.

To stop:

```bash
docker compose down
```

`docker compose down` preserves scan history. To intentionally remove the
named data volume too, use `docker compose down --volumes`.

## Network access

The default bind is localhost. For access from another device, put Cerberus
behind an HTTPS reverse proxy, or set `CERBERUS_BIND` to a specific private
interface address and protect it with a firewall. Do not expose plain HTTP and
the API key directly to the public internet.

## Configuration

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `CERBERUS_API_KEY` | yes | — | Protects the console and API |
| `CERBERUS_BIND` | no | `127.0.0.1` | Host interface published by Compose |
| `CERBERUS_PORT` | no | `8099` | Host port published by Compose |
| `PAGESPEED_API_KEY` | no | empty | Optional Google PageSpeed quota |

SQLite is stored at `/data/cerberus.db` in the `cerberus-data` volume.

## API

```bash
curl -H "X-API-Key: $CERBERUS_API_KEY" http://127.0.0.1:8099/history

curl -X POST http://127.0.0.1:8099/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $CERBERUS_API_KEY" \
  -d '{"url":"https://example.com","heads":["frontend","nose","speed"]}'
```

Poll the returned job at `GET /scan/<job_id>`. `GET /health` is public so
Docker can monitor the container without embedding the API key in image
metadata.

## Safety boundary

Only scan sites you own or are authorized to assess. The standard Docker image
does not expose Cerberus's active testing head and does not install Nuclei,
OWASP ZAP, or sqlmap. Active testing has materially different legal and
operational risk; it is intentionally outside the one-command self-hosted
quick start.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests
```

## Support the project

Cerberus is free software. If it saves you time, you can
[buy me a coffee](https://buymeacoffee.com/romanvaxman). Contributions do not
purchase support, features, or an SLA.

## Documentation and policies

- [Help and operations guide](docs/HELP.md)
- [Privacy](PRIVACY.md)
- [Terms of use](TERMS.md)
- [Security and authorization disclaimer](DISCLAIMER.md)
- [Security policy](SECURITY.md)

## License

Copyright 2026 CTF Designs. Licensed under the GNU Affero General Public
License v3.0. See the complete [LICENSE](LICENSE). The Cerberus and CTF
Designs names and logos are not licensed for misleading endorsement.
