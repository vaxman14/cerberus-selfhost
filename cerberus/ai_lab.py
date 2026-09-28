from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

from . import llm


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


def start_scan(params: dict) -> dict:
    """Start a source-assisted scan while keeping the provider key in Cerberus."""
    if not _enabled(os.environ.get("CERBERUS_AI_LAB_ENABLED")):
        raise llm.LLMError("AI Lab is not enabled", status=409)
    source_repo = str(params.get("source_repo", "")).strip()
    if not source_repo.startswith(("https://", "http://")) or len(source_repo) > 500:
        raise llm.LLMError("enter an http or https Git repository URL")
    code_scan = str(params.get("code_scan", "provision"))
    if code_scan not in {"review", "provision"}:
        raise llm.LLMError("code_scan must be review or provision")
    connection = llm.engine_connection(str(params.get("profile_id", "")))
    base = os.environ.get("CERBERUS_AI_URL", "http://cerberus-ai:9137").rstrip("/")
    username = os.environ.get("CERBERUS_AI_USERNAME", "admin")
    password = os.environ.get("CERBERUS_AI_PASSWORD", "")
    if not password:
        raise llm.LLMError("AI Lab credentials are unavailable", status=503)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    login = urllib.request.Request(
        f"{base}/api/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json", "Origin": base},
        method="POST",
    )
    try:
        with opener.open(login, timeout=10):
            pass
        payload = {
            "name": str(params.get("name", "Cerberus AI Lab scan"))[:120],
            "source_repo": source_repo,
            "code_scan": code_scan,
            "scan_intensity": str(params.get("scan_intensity", "active")),
            "recon_mode": str(params.get("recon_mode", "active")),
            **connection,
        }
        request = urllib.request.Request(
            f"{base}/api/scan", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Origin": base}, method="POST",
        )
        with opener.open(request, timeout=20) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        raise llm.LLMError(f"AI Lab refused the scan request (HTTP {exc.code})", status=502) from exc
    except (OSError, ValueError) as exc:
        raise llm.LLMError("AI Lab could not be reached", status=502) from exc
    return {"status": result.get("status", "started"), "instance_id": result.get("instance_id")}
