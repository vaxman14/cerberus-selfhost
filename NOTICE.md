# Reused security design

Cerberus's model-provider catalogue, endpoint-discovery rules,
capability-probe contract, master-key handling, and AES-256-GCM sealing format
are adapted from Josi CE's `packages/llm` and `packages/core` implementation.
Josi CE identifies SOCAL RECEPTIONIST LLC as publisher and is licensed
AGPL-3.0-or-later. Cerberus is distributed under the same license.

No Josi CE installation account, database, credential, subscription, or
runtime state is copied. Only the implementation pattern and provider metadata
are reused; every Cerberus operator supplies and owns their own credentials.

## Scanner distributions

The `cerberus-zap` image redistributes OWASP ZAP 2.17.0 and a pinned set of
official ZAP add-ons under the Apache License 2.0. Its Network add-on is built
from upstream commit `d7e0725adb263b5cd4d34bc6dd395004ec865360`, which
updates the Apache HTTP client to its security-fixed release. The image also
replaces vulnerable bundled Jackson JARs with checksum-pinned upstream security
releases during its reproducible build. ZAP remains a project of the OWASP
Foundation; Cerberus is not endorsed by OWASP.

The tools image includes Lighthouse, Nuclei, Nuclei templates, and sqlmap. Their
respective upstream licenses and notices remain authoritative for those
components. Cerberus pins their source or package revisions and verifies remote
artifacts where the upstream distribution provides stable checksums.
