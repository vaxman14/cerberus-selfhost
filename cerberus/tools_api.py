from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


TOKEN_FILE = os.environ.get("CERBERUS_TOOLS_TOKEN_FILE", "/run/cerberus-tools/token")
RUN_LOCK = threading.Lock()
RUNNING_LOCK = threading.Lock()
RUNNING: dict[str, subprocess.Popen] = {}
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


def _run(command: list[str], *, timeout: int, run_id: str = "") -> subprocess.CompletedProcess:
    with RUN_LOCK:
        process = subprocess.Popen(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                 "HOME": "/tmp", "NO_COLOR": "1", "CHROME_PATH": "/usr/bin/chromium"},
        )
        if run_id:
            with RUNNING_LOCK:
                RUNNING[run_id] = process
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate(process)
            process.communicate()
            raise
        finally:
            if run_id:
                with RUNNING_LOCK:
                    RUNNING.pop(run_id, None)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        _terminate_lighthouse_children()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    finally:
        _terminate_lighthouse_children()


def _terminate_lighthouse_children() -> None:
    """Lighthouse may detach Chromium from the Node process group; reap it."""
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            command = (proc / "cmdline").read_bytes().replace(b"\0", b" ")
            if b"/tmp/lighthouse." in command:
                os.kill(int(proc.name), signal.SIGKILL)
        except (OSError, ValueError):
            continue


def cancel(run_id: str) -> bool:
    with RUNNING_LOCK:
        process = RUNNING.get(run_id)
    if process is None:
        return False
    _terminate(process)
    return True


def lighthouse(url: str, run_id: str = "") -> dict:
    result = _run([
        "lighthouse", url, "--quiet", "--output=json", "--output-path=stdout",
        "--only-categories=performance,best-practices",
        "--chrome-flags=--headless=new --no-sandbox --disable-dev-shm-usage --disable-gpu",
    ], timeout=180, run_id=run_id)
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


def nuclei(url: str, run_id: str = "") -> dict:
    result = _run([
        "nuclei", "-u", url, "-jsonl", "-silent", "-duc", "-ni",
        "-t", "/opt/nuclei-templates", "-severity", "low,medium,high,critical",
        "-tags", "misconfig,exposure,cve,default-login,tech",
        "-timeout", "5", "-retries", "1", "-rl", "75", "-c", "15",
    ], timeout=660, run_id=run_id)
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


def sqlmap(url: str, run_id: str = "") -> dict:
    result = _run([
        "python3", "/opt/sqlmap/sqlmap.py", "-u", url, "--batch", "--smart",
        "--level=1", "--risk=1", "--technique=BEUS", "--flush-session",
        "--disable-coloring", "--output-dir=/tmp/sqlmap-output",
    ], timeout=900, run_id=run_id)
    output = f"{result.stdout}\n{result.stderr}"
    negative = bool(re.search(
        r"all tested parameters do not appear to be injectable|"
        r"does not seem to be injectable|not injectable",
        output, re.I,
    ))
    vulnerable = not negative and bool(re.search(
        r"sqlmap identified the following injection point|"
        r"parameter\s+['\"][^'\"]+['\"]\s+is vulnerable|"
        r"Type:\s+(?:boolean-based blind|error-based|time-based blind|UNION query)",
        output, re.I,
    ))
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
            action = self.path.strip("/")
            run_id = str(params.get("run_id", ""))
            if run_id and not re.fullmatch(r"[0-9a-f]{12}", run_id):
                raise ValueError("invalid run id")
            if action == "cancel":
                return self._send(200, {"cancelled": cancel(run_id)})
            url = _validate_url(params.get("url"))
            if action == "lighthouse":
                result = lighthouse(url, run_id)
            elif action == "nuclei":
                result = nuclei(url, run_id)
            elif action == "sqlmap":
                result = sqlmap(url, run_id)
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
