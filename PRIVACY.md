# Privacy

Effective September 28, 2026.

Cerberus is self-hosted. The standard app does not send analytics, telemetry,
API keys, or scan history to CTF Designs. Target URLs, findings, and timestamps
are stored in `/data/cerberus.db` inside the Docker volume controlled by the
operator.

The app and its isolated scanner containers contact websites selected by the
operator. Lighthouse runs locally; no Google PageSpeed API is required.

Operators control local retention and are responsible for protecting local
accounts, optional API keys, the Docker host, backups, and network access. CTF Designs does
not sell personal information or local scan data.

Optional provider profiles and generated analyses are stored in the Cerberus
data volume. Provider credentials are encrypted with an installation key kept
outside the database. When an operator uses a remote LLM, the target and scanner
findings are sent to that provider and its privacy policy applies. A local model
can avoid that transmission. CTF Designs does not receive those accounts.

The searchable test manual runs in the browser from content shipped with the
app. Searches are not sent to CTF Designs. The manual provides general
descriptions of checks and results, not personalized advice or remediation.

The complete current policy is at <https://cerberusscan.com/privacy.html>.
