from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


TOKEN_FILE = os.environ.get("CERBERUS_TOOLS_TOKEN_FILE", "/run/cerberus-tools/token")
RUN_LOCK = threading.Lock()
SEVERITY = {"informational": "info", "info": "info", "low": "low",
            "medium": "medium", "high": "high", "critical": "critical"}


def _token() -> str:
    value = Path(TOKEN_FILE).read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise RuntimeError("tools token must contain at least 32 characters")
    return value


def _validate_url(value: object) -> str:
    url = str(value or "").strip()
    parsed = urllib.parse.urlparse(url)
    if len(url) > 2048 or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must use http or https")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)}
    except OSError as exc:
        raise ValueError("target hostname did not resolve") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError("target resolves to a blocked address class")
    return url


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    with RUN_LOCK:
        return subprocess.run(
            command, text=True, capture_output=True, timeout=timeout, check=False,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                 "HOME": "/tmp", "NO_COLOR": "1", "CHROME_PATH": "/usr/bin/chromium"},
        )


def lighthouse(url: str) -> dict:
    result = _run([
        "lighthouse", url, "--quiet", "--output=json", "--output-path=stdout",
        "--only-categories=performance,best-practices",
        "--chrome-flags=--headless=new --no-sandbox --disable-dev-shm-usage --disable-gpu",
    ], timeout=180)
    if result.returncode != 0:
        raise RuntimeError("Lighthouse failed to complete")
    try:
        payload = json.loads(result.stdout)
        categories = payload["categories"]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("Lighthouse returned an unreadable report") from exc
    return {"categories": {
        name: {"score": categories.get(name, {}).get("score")}
        for name in ("performance", "best-practices")
    }}


def nuclei(url: str) -> dict:
    result = _run([
        "nuclei", "-u", url, "-jsonl", "-silent", "-duc", "-ni",
        "-t", "/opt/nuclei-templates", "-severity", "low,medium,high,critical",
        "-tags", "misconfig,exposure,cve,default-login,tech",
        "-timeout", "5", "-retries", "1", "-rl", "75", "-c", "15",
    ], timeout=660)
    findings = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        info = item.get("info") or {}
        findings.append({
            "title": f"nuclei: {info.get('name') or item.get('template-id') or 'finding'}",
            "severity": SEVERITY.get(str(info.get("severity", "info")).lower(), "info"),
            "detail": str(info.get("description") or item.get("template-id") or "")[:400],
            "evidence": str(item.get("matched-at") or "")[:160],
            "remediation": str(info.get("remediation") or "")[:400],
        })
    return {"findings": findings, "completed": result.returncode in {0, 1}}


def sqlmap(url: str) -> dict:
    result = _run([
        "python3", "/opt/sqlmap/sqlmap.py", "-u", url, "--batch", "--smart",
        "--level=1", "--risk=1", "--technique=BEUS", "--flush-session",
        "--disable-coloring", "--output-dir=/tmp/sqlmap-output",
    ], timeout=900)
    output = f"{result.stdout}\n{result.stderr}"
    vulnerable = bool(re.search(r"is vulnerable|injectable", output, re.I))
    return {"vulnerable": vulnerable, "completed": result.returncode in {0, 1}}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {_token()}"
        import hmac
        return hmac.compare_digest(supplied, expected)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            return self._send(200, {"ok": True, "tools": ["lighthouse", "nuclei", "sqlmap"]})
        return self._send(401 if not self._authorized() else 404, {"error": "unauthorized"})

    def do_POST(self):  # noqa: N802
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 4096:
            return self._send(413, {"error": "request too large"})
        try:
            params = json.loads(self.rfile.read(length) or b"{}")
            url = _validate_url(params.get("url"))
            action = self.path.strip("/")
            if action == "lighthouse":
                result = lighthouse(url)
            elif action == "nuclei":
                result = nuclei(url)
            elif action == "sqlmap":
                result = sqlmap(url)
            else:
                return self._send(404, {"error": "not found"})
            return self._send(200, result)
        except subprocess.TimeoutExpired:
            return self._send(504, {"error": "tool timed out"})
        except (ValueError, RuntimeError) as exc:
            return self._send(400, {"error": str(exc)[:200]})

    def log_message(self, *_args):
        pass


def main() -> None:
    _token()
    ThreadingHTTPServer(("0.0.0.0", 8181), Handler).serve_forever()


if __name__ == "__main__":
    main()
