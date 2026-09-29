# Changelog

## 0.2.2 - 2026-09-28

- Match the console background to the Cerberus logo.
- Add password visibility and copyable local password-reset commands.
- Combine model saving and capability validation into one action.
- Explain disabled active-scanning capability instead of hiding it silently.
- Add a searchable, descriptive manual for all scanner checks without
  remediation recommendations.
- Collapse model-provider controls until the operator needs them.
- Clarify the Terms and Privacy Policy for descriptive test documentation.

## 0.2.1 - 2026-09-28

- Added the new Cerberus Scan logo across the application, website, registry
  documentation, repository, and Unraid template.
- Corrected the first-owner form so username, password, and confirmation fields
  align evenly on desktop and stack consistently on smaller screens.
- Made the AIO install reachable from the LAN by default, printed the browser
  destination, and documented every install flag, mount, and safety boundary.

## 0.2.0 - 2026-09-28

- Added local owner authentication and sessions.
- Added isolated Lighthouse, Nuclei, sqlmap, and private OWASP ZAP.
- Added active-scan authorization, production confirmation, global scan
  serialization, and real cancellation.
- Added grouped history, saved AI analysis, client reports, and PDF printing.
- Added encrypted model profiles, deletion, and ChatGPT plan support through
  OpenAI Codex CLI.
- Added schema migrations, password reset, verified backup/restore, rollback,
  one-command setup, and backup-first updates.
- Added an optional Nextcloud-style AIO launcher that pulls and manages the
  isolated Cerberus, tools, and ZAP containers from one Unraid-friendly master.
- Added passive-by-default configuration, multi-architecture release builds,
  SBOM/provenance, CodeQL, Dependabot, and container scanning.
- Corrected sqlmap false positives, stale/duplicate ZAP alerts, and
  registrable-domain SPF/DMARC checks.

## 0.1.1

- Initial passive self-hosted scanner release.
