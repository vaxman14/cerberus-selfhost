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
