from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def status() -> dict:
    """Return a redacted health summary for the optional AI Lab service."""
    configured = _enabled(os.environ.get("CERBERUS_AI_LAB_ENABLED"))
    result = {
        "configured": configured,
        "reachable": False,
        "engine": "Xalgorix",
        "public_port": int(os.environ.get("CERBERUS_AI_PORT", "9137")),
    }
    if not configured:
        return result

    base = os.environ.get("CERBERUS_AI_URL", "http://cerberus-ai:9137").rstrip("/")
    request = urllib.request.Request(f"{base}/api/auth/status")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.load(response)
        result["reachable"] = True
        result["state"] = "ready" if payload.get("auth_required", True) else "ready"
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        result["error"] = type(exc).__name__
    return result
