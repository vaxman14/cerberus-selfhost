from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


class ToolServiceError(RuntimeError):
    pass


def _token() -> str:
    path = os.environ.get("CERBERUS_TOOLS_TOKEN_FILE", "/run/cerberus-tools/token")
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ToolServiceError("tools service token is unavailable") from exc


def _base() -> str:
    return os.environ.get("CERBERUS_TOOLS_URL", "http://cerberus-tools:8181").rstrip("/")


def request(path: str, payload: dict | None = None, *, timeout: int = 930) -> dict:
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{_base()}/{path.lstrip('/')}", data=data,
        headers={"Authorization": f"Bearer {_token()}", "Content-Type": "application/json"},
        method="GET" if data is None else "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc).get("error", f"HTTP {exc.code}")
        except Exception:
            detail = f"HTTP {exc.code}"
        raise ToolServiceError(f"tools service refused the request ({detail})") from exc
    except (OSError, ValueError) as exc:
        raise ToolServiceError("tools service is unavailable") from exc


def status() -> dict:
    try:
        return request("health", timeout=4)
    except ToolServiceError as exc:
        return {"ok": False, "error": str(exc)}


def run(tool: str, url: str, *, timeout: int = 930, run_id: str = "") -> dict:
    if tool not in {"lighthouse", "nuclei", "sqlmap"}:
        raise ToolServiceError("unsupported local tool")
    return request(tool, {"url": url, "run_id": run_id}, timeout=timeout)


def cancel(run_id: str) -> bool:
    if not run_id:
        return False
    try:
        return bool(request("cancel", {"run_id": run_id}, timeout=4).get("cancelled"))
    except ToolServiceError:
        return False
