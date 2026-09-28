from __future__ import annotations
import os
import json
import urllib.request

API = "https://www.signwell.com/api/v1"


def is_authorization_complete(document_id: str | None) -> bool | None:
    """True if the SignWell document is fully signed, False if not, None if
    verification is unavailable (no API key configured). The gate treats None as
    'provisional' (ref required but unverifiable in dev) and False as a hard block."""
    key = os.environ.get("SIGNWELL_API_KEY")
    if not key or not document_id:
        return None
    req = urllib.request.Request(
        f"{API}/documents/{document_id}/", headers={"X-Api-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        return data.get("status") == "completed"
    except Exception:
        return None
