# Privacy

Effective September 27, 2026.

Cerberus is self-hosted. The standard app does not send analytics, telemetry,
API keys, or scan history to CTF Designs. Target URLs, findings, and timestamps
are stored in `/data/cerberus.db` inside the Docker volume controlled by the
operator.

The app contacts websites selected by the operator and may contact Google
PageSpeed Insights when that check is enabled. GitHub or a container registry
processes requests when source code or images are downloaded. Those services
apply their own policies.

Operators control local retention and are responsible for protecting the API
key, Docker host, backups, reverse proxy, and network access. CTF Designs does
not sell personal information or local scan data.

The complete current policy is at <https://cerberusscan.com/privacy.html>.
