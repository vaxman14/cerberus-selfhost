from __future__ import annotations
import os
import json
import uuid
import threading
import hmac
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from . import ai_lab, llm, runner, reporting, persistence, vault
from .models import ScanResult, Finding, Head, Severity

API_KEY = os.environ.get("CERBERUS_API_KEY", "")
SUPA_URL = os.environ.get("SUPABASE_URL", "")
SUPA_ANON = os.environ.get("SUPABASE_ANON_KEY", "")
AUTH_MODE = os.environ.get(
    "CERBERUS_AUTH_MODE", "supabase" if SUPA_ANON else "apikey").lower()
ADMIN_EMAIL = os.environ.get("CERBERUS_ADMIN_EMAIL", "").lower()
CONSOLE_PATH = Path(__file__).resolve().parent.parent / "console" / "index.html"
JOBS: dict[str, dict] = {}
LOCK = threading.Lock()


def _run_job(job_id: str, params: dict) -> None:
    def log_cb(line: str) -> None:
        with LOCK:
            j = JOBS.get(job_id)
            if j is not None:
                j.setdefault("log", []).append(line)
    try:
        result, scan_id, skipped = runner.run_scan(
            params["url"],
            client=params.get("client", "prospect"),
            heads=tuple(params.get("heads", ["frontend", "speed"])),
            auth_ref=params.get("auth_ref"),
            staging=bool(params.get("staging", False)),
            allow_prod=bool(params.get("allow_prod", False)),
            admin_override=bool(params.get("admin_override", False)),
            log_cb=log_cb,
        )
        with LOCK:
            entry = JOBS.get(job_id, {})
            log = entry.get("log", [])
            owner = entry.get("user")
        payload = {
            "status": "done", "target": result.target, "client": result.client,
            "worst": result.worst().value, "count": len(result.findings),
            "findings": [f.to_dict() for f in result.sorted()],
            "skipped": skipped, "scan_id": scan_id,
            "report_html": reporting.render_client(result), "log": log, "user": owner,
        }
    except Exception as e:  # noqa: BLE001
        with LOCK:
            entry = JOBS.get(job_id, {})
            log = entry.get("log", [])
            owner = entry.get("user")
        log.append(f"!! ERROR: {str(e)[:300]}")
        payload = {"status": "error", "error": str(e)[:300], "log": log, "user": owner}
    with LOCK:
        JOBS[job_id] = payload


class Handler(BaseHTTPRequestHandler):
    def _authed(self) -> bool:
        supplied = self.headers.get("X-API-Key", "")
        return bool(API_KEY) and hmac.compare_digest(supplied, API_KEY)

    def _user(self) -> dict | None:
        """Return the local operator or validate an optional Supabase user."""
        if AUTH_MODE == "apikey":
            return {"id": "selfhost", "email": None}
        if AUTH_MODE != "supabase":
            return None
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not SUPA_ANON:
            return None
        token = auth[7:].strip()
        try:
            req = urllib.request.Request(
                f"{SUPA_URL}/auth/v1/user",
                headers={"Authorization": f"Bearer {token}", "apikey": SUPA_ANON},
            )
            u = json.load(urllib.request.urlopen(req, timeout=8))
            if u.get("id"):
                return {"id": u["id"], "email": u.get("email")}
        except Exception:
            return None
        return None

    def _cors(self) -> None:
        origin = os.environ.get("CERBERUS_CORS_ORIGIN", "").strip()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Access-Control-Allow-Headers", "X-API-Key,Content-Type,Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_console(self) -> None:
        try:
            body = CONSOLE_PATH.read_bytes()
        except OSError:
            return self._send(404, {"error": "console unavailable"})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
                         "img-src 'self' data:; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_llm_error(self, exc: llm.LLMError) -> None:
        self._send(exc.status, {"error": str(exc), "category": exc.category})

    def _relay_provider_response(self, response) -> None:
        try:
            self.send_response(response.status_code)
            self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            for chunk in response.iter_content(chunk_size=16384):
                if chunk:
                    self.wfile.write(chunk)
                    self.wfile.flush()
        finally:
            response.close()

    def do_OPTIONS(self):  # noqa: N802
        self._send(204, {})

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send_console()
        if path == "/health":
            return self._send(200, {"ok": True})
        if path == "/internal/llm/v1/models":
            profile_id = llm.authenticate_bridge(self.headers.get("Authorization", ""))
            if not profile_id:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, llm.bridge_models(profile_id))
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        user = self._user()
        if not user:
            return self._send(401, {"error": "sign in required"})
        if path.startswith("/scan/"):
            jid = path.split("/scan/", 1)[1]
            with LOCK:
                job = JOBS.get(jid)
            if not job:
                return self._send(404, {"error": "no such job"})
            if job.get("user") and job.get("user") != user["id"]:
                return self._send(403, {"error": "not your scan"})
            return self._send(200, job)
        if path == "/history":
            is_admin = AUTH_MODE == "apikey" or (
                bool(ADMIN_EMAIL) and (user.get("email") or "").lower() == ADMIN_EMAIL)
            # admin sees every run; everyone else sees only their own
            scans = persistence.list_scans(
                client=None if is_admin else (user["email"] or user["id"]), limit=100)
            return self._send(200, {"scans": scans})
        if path == "/ai-lab/status":
            return self._send(200, ai_lab.status())
        if path == "/ai-lab/providers":
            return self._send(200, {
                "catalog_version": llm.CATALOG_VERSION,
                "providers": llm.provider_catalog(),
                "profiles": persistence.list_llm_profiles(),
                "vault_ready": vault.master_key_available(),
            })
        if path.startswith("/report/"):
            sid = path.split("/report/", 1)[1]
            scan = persistence.get_scan(sid)
            if not scan:
                return self._send(404, {"error": "no such scan"})
            is_admin = AUTH_MODE == "apikey" or (
                bool(ADMIN_EMAIL) and (user.get("email") or "").lower() == ADMIN_EMAIL)
            if not is_admin and scan.get("client") != (user["email"] or user["id"]):
                return self._send(403, {"error": "not your scan"})
            res = ScanResult(target=scan["target"], client=scan.get("client", ""))
            for f in persistence.get_findings(sid):
                try:
                    res.findings.append(Finding(
                        head=Head(f.get("head", "frontend")),
                        title=f.get("title", ""), severity=Severity(f.get("severity", "info")),
                        detail=f.get("detail", ""), evidence=f.get("evidence", ""),
                        remediation=f.get("remediation", "")))
                except Exception:
                    continue
            # heads run aren't stored per-scan; infer from the finding heads present
            res.heads_run = sorted({f.head.value for f in res.findings}) or ["frontend"]
            return self._send(200, {"target": scan["target"],
                                    "created_at": scan.get("created_at"),
                                    "report_html": reporting.render_client(res)})
        self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        ln = int(self.headers.get("Content-Length", "0") or 0)
        if ln > 1_000_000:
            return self._send(413, {"error": "request too large"})
        if path == "/internal/llm/v1/chat/completions":
            profile_id = llm.authenticate_bridge(self.headers.get("Authorization", ""))
            if not profile_id:
                return self._send(401, {"error": "unauthorized"})
            try:
                params = json.loads(self.rfile.read(ln) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            try:
                return self._relay_provider_response(llm.bridge_chat(profile_id, params))
            except llm.LLMError as exc:
                return self._send_llm_error(exc)

        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        user = self._user()
        if not user:
            return self._send(401, {"error": "sign in required"})
        try:
            params = json.loads(self.rfile.read(ln) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        try:
            if path == "/ai-lab/providers":
                return self._send(200, {"profile": llm.save_profile(params)})
            if path == "/ai-lab/providers/discover":
                return self._send(200, llm.discover_connection(params))
            if path.startswith("/ai-lab/providers/"):
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[3] == "discover":
                    return self._send(200, llm.discover_models(parts[2]))
                if len(parts) == 4 and parts[3] == "probe":
                    return self._send(200, llm.probe_profile(parts[2]))
            if path == "/ai-lab/scans":
                return self._send(202, ai_lab.start_scan(params))
        except llm.LLMError as exc:
            return self._send_llm_error(exc)
        except vault.VaultError as exc:
            return self._send(503, {"error": str(exc), "category": "vault"})

        if path == "/scan":
            if not params.get("url"):
                return self._send(400, {"error": "url required"})
            target = urlparse(str(params["url"]))
            if target.scheme not in ("http", "https") or not target.hostname:
                return self._send(400, {"error": "url must use http or https"})
            params["client"] = (
                str(params.get("client", "selfhost"))[:120]
                if AUTH_MODE == "apikey" else (user["email"] or user["id"]))
            is_admin = AUTH_MODE == "supabase" and bool(ADMIN_EMAIL) and (
                (user.get("email") or "").lower() == ADMIN_EMAIL)
            heads = list(params.get("heads", ["frontend", "speed"]))
            allowed_heads = {"frontend", "nose", "speed", "backend"}
            if not heads or any(head not in allowed_heads for head in heads):
                return self._send(400, {"error": "invalid heads"})
            active_enabled = os.environ.get(
                "CERBERUS_ENABLE_ACTIVE_SCANS", "").lower() in ("1", "true", "yes")
            if "backend" in heads and not (active_enabled and (AUTH_MODE == "apikey" or is_admin)):
                return self._send(
                    403, {"error": "active scans are disabled; set CERBERUS_ENABLE_ACTIVE_SCANS=true"})
            params["heads"] = heads
            jid = uuid.uuid4().hex[:12]
            with LOCK:
                JOBS[jid] = {"status": "running", "log": [], "user": user["id"]}
            threading.Thread(target=_run_job, args=(jid, params), daemon=True).start()
            return self._send(202, {"job_id": jid, "status": "running"})

        self._send(404, {"error": "not found"})

    def do_DELETE(self):  # noqa: N802
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        user = self._user()
        if not user:
            return self._send(401, {"error": "sign in required"})
        path = urlparse(self.path).path
        if path.startswith("/ai-lab/providers/"):
            parts = path.strip("/").split("/")
            if len(parts) == 3:
                removed = persistence.delete_llm_profile(parts[2])
                return self._send(200 if removed else 404, {"removed": removed})
        return self._send(404, {"error": "not found"})

    def log_message(self, *a):  # silence access logs
        pass


def main():
    if not API_KEY:
        raise SystemExit(
            "CERBERUS_API_KEY is required. Generate one with: openssl rand -hex 32")
    port = int(os.environ.get("CERBERUS_API_PORT", "8099"))
    host = os.environ.get("CERBERUS_API_HOST", "0.0.0.0")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
