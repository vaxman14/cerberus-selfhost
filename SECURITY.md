# Security policy

## Supported version

The latest `0.2.x` release and current `main` branch receive security fixes.
Older releases are unsupported.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button in the repository Security tab.
Do not open a public issue for API-key exposure, authentication bypasses, scan
scope escapes, or other security-sensitive reports.

Do not include live credentials, private scan results, customer data, or
authorization documents in a public issue.

## Scanner isolation

The tools worker and ZAP have no published ports, host Docker socket, or
privileged mode. They use read-only root filesystems, dropped capabilities,
`no-new-privileges`, tmpfs workspaces, resource ceilings, and authenticated
internal APIs. Do not weaken these controls or expose the services directly.

Model credentials are encrypted at rest with AES-256-GCM. The installation
master key is a Docker secret file outside the database and image; environment
variables are refused. API responses return only whether a key exists. Custom endpoints permit loopback and private networks for
self-hosted inference but refuse link-local/cloud-metadata, unspecified,
multicast, reserved, credential-bearing, and redirecting URLs.
