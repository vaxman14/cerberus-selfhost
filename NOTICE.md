# Reused security design

Cerberus's model-provider catalogue, endpoint-discovery rules,
capability-probe contract, master-key handling, and AES-256-GCM sealing format
are adapted from Josi CE's `packages/llm` and `packages/core` implementation.
Josi CE identifies SOCAL RECEPTIONIST LLC as publisher and is licensed
AGPL-3.0-or-later. Cerberus is distributed under the same license.

No Josi CE installation account, database, credential, subscription, or
runtime state is copied. Only the implementation pattern and provider metadata
are reused; every Cerberus operator supplies and owns their own credentials.
