from __future__ import annotations
import os
import json
import uuid
import threading
import hmac
import time
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from . import llm, local_auth, runner, reporting, persistence, tool_client, vault
from .models import ScanResult, Finding, Head, Severity
from .cancellation import ScanCancelled

API_KEY = os.environ.get("CERBERUS_API_KEY", "")
SUPA_URL = os.environ.get("SUPABASE_URL", "")
SUPA_ANON = os.environ.get("SUPABASE_ANON_KEY", "")
AUTH_MODE = os.environ.get(
    "CERBERUS_AUTH_MODE", "supabase" if SUPA_ANON else "apikey").lower()
ADMIN_EMAIL = os.environ.get("CERBERUS_ADMIN_EMAIL", "").lower()
CONSOLE_PATH = Path(__file__).resolve().parent.parent / "console" / "index.html"
JOBS: dict[str, dict] = {}
CANCEL_EVENTS: dict[str, threading.Event] = {}
LOCK = threading.Lock()
LOGIN_FAILURES: dict[str, list[float]] = {}


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
            cancel_event=CANCEL_EVENTS.get(job_id),
            run_id=job_id,
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
    except ScanCancelled:
        with LOCK:
            entry = JOBS.get(job_id, {})
            log = entry.get("log", [])
            owner = entry.get("user")
        if not log or log[-1] != "!! STOPPED by operator":
            log.append("!! STOPPED by operator")
        payload = {"status": "stopped", "log": log, "user": owner}
    except Exception as e:  # noqa: BLE001
        with LOCK:
            entry = JOBS.get(job_id, {})
            log = entry.get("log", [])
            owner = entry.get("user")
        log.append(f"!! ERROR: {str(e)[:300]}")
        payload = {"status": "error", "error": str(e)[:300], "log": log, "user": owner}
    with LOCK:
        JOBS[job_id] = payload
        CANCEL_EVENTS.pop(job_id, None)


class Handler(BaseHTTPRequestHandler):
    def _api_key_authed(self) -> bool:
        supplied = self.headers.get("X-API-Key", "")
        return bool(API_KEY) and hmac.compare_digest(supplied, API_KEY)

    def _user(self) -> dict | None:
        """Return an API operator, local owner, or optional Supabase user."""
        if self._api_key_authed():
            return {"id": "api", "username": "api", "role": "owner", "api_key": True}
        if AUTH_MODE == "supabase":
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
                    return {"id": u["id"], "username": u.get("email") or u["id"],
                            "role": "owner", "supabase": True}
            except Exception:
                return None
            return None
        user, _ = local_auth.authenticate(self.headers.get("Cookie", ""))
        return user

    def _csrf_ok(self, user: dict) -> bool:
        if user.get("api_key") or user.get("supabase"):
            return True
        return local_auth.csrf_valid(user, self.headers.get("X-CSRF-Token", ""))

    def _cookie_secure(self) -> bool:
        configured = os.environ.get("CERBERUS_COOKIE_SECURE", "").strip().lower()
        if configured:
            return configured in {"1", "true", "yes", "on"}
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _login_rate_limited(self) -> bool:
        now = time.time()
        key = self.client_address[0] if self.client_address else "unknown"
        recent = [stamp for stamp in LOGIN_FAILURES.get(key, []) if now - stamp < 300]
        LOGIN_FAILURES[key] = recent
        return len(recent) >= 8

    def _record_login_failure(self) -> None:
        key = self.client_address[0] if self.client_address else "unknown"
        LOGIN_FAILURES.setdefault(key, []).append(time.time())

    def _cors(self) -> None:
        origin = os.environ.get("CERBERUS_CORS_ORIGIN", "").strip()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send(self, code: int, obj: dict, *, headers=None) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Access-Control-Allow-Headers", "X-API-Key,X-CSRF-Token,Content-Type,Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        values = headers.items() if isinstance(headers, dict) else (headers or [])
        for name, value in values:
            self.send_header(name, value)
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
        if path == "/auth/status":
            user = self._user()
            payload = {"setup_required": local_auth.setup_required(),
                       "authenticated": bool(user)}
            if user:
                payload["user"] = {"username": user["username"], "role": user["role"]}
                if not user.get("api_key") and not user.get("supabase"):
                    csrf = local_auth.csrf_cookie(self.headers.get("Cookie", ""))
                    if local_auth.csrf_valid(user, csrf):
                        payload["csrf_token"] = csrf
            return self._send(200, payload)
        if path == "/internal/llm/v1/models":
            profile_id = llm.authenticate_bridge(self.headers.get("Authorization", ""))
            if not profile_id:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, llm.bridge_models(profile_id))
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
            scans = persistence.list_scans(client=None, limit=100)
            return self._send(200, {"scans": scans})
        if path.startswith("/history/"):
            sid = path.split("/history/", 1)[1]
            value = persistence.get_scan_bundle(sid)
            return self._send(200, value) if value else self._send(
                404, {"error": "no such saved run"})
        if path == "/capabilities":
            return self._send(200, {
                "active_scans": os.environ.get(
                    "CERBERUS_ENABLE_ACTIVE_SCANS", "").lower() in ("1", "true", "yes"),
                "tools": tool_client.status(),
                "zap_configured": bool(os.environ.get("ZAP_API", "")),
            })
        if path == "/ai-lab/providers":
            return self._send(200, {
                "catalog_version": llm.CATALOG_VERSION,
                "providers": llm.provider_catalog(),
                "profiles": persistence.list_llm_profiles(),
                "vault_ready": vault.master_key_available(),
            })
        if path.startswith("/ai-lab/subscriptions/") and path.endswith("/status"):
            parts = path.strip("/").split("/")
            if len(parts) == 4:
                try:
                    return self._send(200, {
                        "status": llm.subscription_status(parts[2]),
                        "login": llm.subscription_login_state(parts[2]),
                    })
                except llm.LLMError as exc:
                    return self._send_llm_error(exc)
        if path.startswith("/report/"):
            sid = path.split("/report/", 1)[1]
            scan = persistence.get_scan(sid)
            if not scan:
                return self._send(404, {"error": "no such scan"})
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
        if path.startswith("/analysis/"):
            sid = path.split("/analysis/", 1)[1]
            value = persistence.get_scan_analysis(sid)
            return self._send(200, {"analysis": value}) if value else self._send(
                404, {"error": "no analysis for that scan"})
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
        try:
            params = json.loads(self.rfile.read(ln) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if path == "/auth/setup":
            if self._login_rate_limited():
                return self._send(429, {"error": "too many attempts; wait five minutes"})
            try:
                local_auth.create_owner(str(params.get("username", "")),
                                        str(params.get("password", "")))
                user, token, csrf = local_auth.login(
                    str(params.get("username", "")), str(params.get("password", "")))
            except local_auth.LocalAuthError as exc:
                self._record_login_failure()
                return self._send(exc.status, {"error": str(exc)})
            secure = self._cookie_secure()
            return self._send(201, {"user": user, "csrf_token": csrf}, headers=[
                ("Set-Cookie", local_auth.cookie_header(token, secure=secure)),
                ("Set-Cookie", local_auth.csrf_cookie_header(csrf, secure=secure)),
            ])
        if path == "/auth/login":
            if self._login_rate_limited():
                return self._send(429, {"error": "too many attempts; wait five minutes"})
            try:
                user, token, csrf = local_auth.login(
                    str(params.get("username", "")), str(params.get("password", "")))
            except local_auth.LocalAuthError as exc:
                self._record_login_failure()
                return self._send(exc.status, {"error": str(exc)})
            secure = self._cookie_secure()
            return self._send(200, {"user": user, "csrf_token": csrf}, headers=[
                ("Set-Cookie", local_auth.cookie_header(token, secure=secure)),
                ("Set-Cookie", local_auth.csrf_cookie_header(csrf, secure=secure)),
            ])

        user = self._user()
        if not user:
            return self._send(401, {"error": "sign in required"})
        if not self._csrf_ok(user):
            return self._send(403, {"error": "invalid CSRF token; sign in again"})
        if path == "/auth/logout":
            local_auth.logout(self.headers.get("Cookie", ""))
            secure = self._cookie_secure()
            return self._send(200, {"ok": True}, headers=[
                ("Set-Cookie", local_auth.clear_cookie_header(secure=secure)),
                ("Set-Cookie", local_auth.clear_csrf_cookie_header(secure=secure)),
            ])
        try:
            if path == "/ai-lab/providers":
                return self._send(200, {"profile": llm.save_profile(params)})
            if path == "/ai-lab/providers/discover":
                return self._send(200, llm.discover_connection(params))
            if path.startswith("/ai-lab/subscriptions/"):
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[3] == "login":
                    return self._send(200, llm.start_subscription_login(parts[2]))
                if len(parts) == 4 and parts[3] == "code":
                    return self._send(200, llm.submit_subscription_code(
                        parts[2], str(params.get("code", ""))))
            if path.startswith("/ai-lab/providers/"):
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[3] == "discover":
                    return self._send(200, llm.discover_models(parts[2]))
                if len(parts) == 4 and parts[3] == "probe":
                    return self._send(200, llm.probe_profile(parts[2]))
        except llm.LLMError as exc:
            return self._send_llm_error(exc)
        except vault.VaultError as exc:
            return self._send(503, {"error": str(exc), "category": "vault"})

        if path == "/analysis":
            scan_id = str(params.get("scan_id", ""))
            profile_id = str(params.get("profile_id", ""))
            scan = persistence.get_scan(scan_id)
            if not scan:
                return self._send(404, {"error": "no such scan"})
            try:
                content = llm.analyze_findings(
                    profile_id, target=scan["target"],
                    findings=persistence.get_findings(scan_id),
                )
                value = persistence.save_scan_analysis(scan_id, profile_id, content)
                return self._send(200, {"analysis": value})
            except llm.LLMError as exc:
                return self._send_llm_error(exc)

        if path == "/scan":
            if not params.get("url"):
                return self._send(400, {"error": "url required"})
            target = urlparse(str(params["url"]))
            if target.scheme not in ("http", "https") or not target.hostname:
                return self._send(400, {"error": "url must use http or https"})
            params["client"] = user.get("username", user["id"])
            heads = list(params.get("heads", ["frontend", "speed"]))
            allowed_heads = {"frontend", "nose", "speed", "backend"}
            if not heads or any(head not in allowed_heads for head in heads):
                return self._send(400, {"error": "invalid heads"})
            active_enabled = os.environ.get(
                "CERBERUS_ENABLE_ACTIVE_SCANS", "").lower() in ("1", "true", "yes")
            if "backend" in heads and not (active_enabled and user.get("role") == "owner"):
                return self._send(
                    403, {"error": "active scans are disabled; set CERBERUS_ENABLE_ACTIVE_SCANS=true"})
            if "backend" in heads:
                if params.get("active_acknowledged") is not True:
                    return self._send(400, {"error": "confirm ownership and active-scan authorization"})
                params["admin_override"] = True
                params["allow_prod"] = bool(params.get("allow_prod", False))
            params["heads"] = heads
            jid = uuid.uuid4().hex[:12]
            with LOCK:
                JOBS[jid] = {"status": "running", "log": [], "user": user["id"]}
                CANCEL_EVENTS[jid] = threading.Event()
            threading.Thread(target=_run_job, args=(jid, params), daemon=True).start()
            return self._send(202, {"job_id": jid, "status": "running"})

        self._send(404, {"error": "not found"})

    def do_DELETE(self):  # noqa: N802
        user = self._user()
        if not user:
            return self._send(401, {"error": "sign in required"})
        if not self._csrf_ok(user):
            return self._send(403, {"error": "invalid CSRF token; sign in again"})
        path = urlparse(self.path).path
        if path.startswith("/scan/"):
            parts = path.strip("/").split("/")
            if len(parts) == 2:
                jid = parts[1]
                with LOCK:
                    job = JOBS.get(jid)
                    event = CANCEL_EVENTS.get(jid)
                    if not job:
                        status, error = 404, "no such job"
                    elif job.get("user") and job.get("user") != user["id"]:
                        status, error = 403, "not your scan"
                    elif job.get("status") not in {"running", "stopping"} or event is None:
                        status, error = 409, "scan is not running"
                    else:
                        status, error = 202, ""
                        event.set()
                        job["status"] = "stopping"
                        job.setdefault("log", []).append(
                            "!! Stop requested; cancelling active tools …")
                if error:
                    return self._send(status, {"error": error})
                tool_client.cancel(jid)
                return self._send(202, {"status": "stopping"})
        if path.startswith("/ai-lab/providers/"):
            parts = path.strip("/").split("/")
            if len(parts) == 3:
                removed = persistence.delete_llm_profile(parts[2])
                return self._send(200 if removed else 404, {"removed": removed})
        return self._send(404, {"error": "not found"})

    def log_message(self, *a):  # silence access logs
        pass


def main():
    local_auth.bootstrap_owner_from_env()
    port = int(os.environ.get("CERBERUS_API_PORT", "8099"))
    host = os.environ.get("CERBERUS_API_HOST", "0.0.0.0")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
