# Security policy

## Supported version

Only the current `main` branch is supported before the first tagged release.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button in the repository Security tab.
Do not open a public issue for API-key exposure, authentication bypasses, scan
scope escapes, or other security-sensitive reports.

Do not include live credentials, private scan results, customer data, or
authorization documents in a public issue.

## AI Lab isolation

The optional AI Lab is separately authenticated and uses a separate data
volume. The shipped Compose overlay does not mount the host Docker socket and
does not grant privileged mode. It drops every capability except `NET_RAW`,
enables `no-new-privileges`, applies CPU/memory ceilings, and binds the
dashboard to localhost by default. Do not weaken these controls or expose the
dashboard directly to the public internet.

Model credentials are encrypted at rest with AES-256-GCM. The installation
master key is a Docker secret file outside the database and image; environment
variables are refused. API responses return only whether a key exists. The AI
engine receives a random, expiring, profile-scoped bridge token stored only as
a hash by Cerberus and never receives the provider credential. Custom endpoints permit loopback and private networks for
self-hosted inference but refuse link-local/cloud-metadata, unspecified,
multicast, reserved, credential-bearing, and redirecting URLs.
