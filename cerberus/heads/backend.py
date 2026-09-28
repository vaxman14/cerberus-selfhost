from __future__ import annotations
import os
import json
import time
import shutil
import subprocess
import urllib.parse
import urllib.request
from ..models import Finding, Severity, Head, AuthRecord
from . import _steps

TOOL_TIMEOUT = 900  # 15 min per tool


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _missing(tool: str) -> Finding:
    return Finding(Head.BACKEND, f"{tool} not installed", Severity.INFO,
                   f"Active tool '{tool}' is not on this runner. Install it on the "
                   "isolated droplet (see deploy/provision.sh) to enable this check.")


def _map_sev(s: str) -> Severity:
    s = (s or "").lower()
    if s.startswith("informational"):
        return Severity.INFO
    return {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL}.get(s, Severity.INFO)


def scan(url: str, auth: AuthRecord, staging: bool = False, log=None) -> list[Finding]:
    """Head 2: active backend attack orchestration (nuclei / ZAP / sqlmap).
    Caller MUST have passed AuthorizationGate first. Refuses production targets
    unless auth.allow_production_active is set."""
    log = log or (lambda *_: None)
    if not staging and not auth.allow_production_active:
        return [Finding(Head.BACKEND, "Active scan withheld", Severity.INFO,
                        "Target is production and allow_production_active is not set. "
                        "Point at a staging clone or explicitly acknowledge prod risk.")]
    out: list[Finding] = []
    _steps.say(log, "arming active toolchain (this bites — can take minutes) …")
    _steps.say(log, "nuclei · templated CVE / misconfig sweep …")
    _steps.step(log, out, "nuclei", lambda: out.extend(_nuclei(url)))
    _steps.say(log, "OWASP ZAP · active injection scan …")
    _steps.step(log, out, "OWASP ZAP", lambda: out.extend(_zap(url)))
    _steps.say(log, "sqlmap · SQL-injection probe …")
    _steps.step(log, out, "sqlmap", lambda: out.extend(_sqlmap(url)))
    return out


def _nuclei(url: str) -> list[Finding]:
    if not _have("nuclei"):
        return [_missing("nuclei")]
    # Scope to the categories that matter for a client audit instead of the full
    # template library (which is too heavy for a 1-vCPU runner against an SPA).
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent",
           "-severity", "low,medium,high,critical",
           "-tags", "misconfig,exposure,cve,default-login,tech",
           "-ni", "-timeout", "5", "-retries", "1", "-rl", "150", "-c", "25"]
    stdout = ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        stdout = p.stdout
    except subprocess.TimeoutExpired as e:
        # Keep whatever nuclei streamed before the cap instead of throwing it away.
        raw = e.stdout
        stdout = (raw.decode() if isinstance(raw, bytes) else raw) or ""
    out: list[Finding] = []
    for line in stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        info = j.get("info", {})
        out.append(Finding(
            Head.BACKEND, f"nuclei: {info.get('name', j.get('template-id', ''))}",
            _map_sev(info.get("severity", "info")),
            (info.get("description") or j.get("template-id", ""))[:400],
            evidence=str(j.get("matched-at", ""))[:120],
            remediation=(info.get("remediation") or "")[:300]))
    return out


def _zap(url: str) -> list[Finding]:
    base = os.environ.get("ZAP_API", "http://localhost:8080")
    key = os.environ.get("ZAP_API_KEY", "")

    def api(path, **params):
        params["apikey"] = key
        q = urllib.parse.urlencode(params)
        with urllib.request.urlopen(f"{base}/JSON/{path}/?{q}", timeout=30) as r:
            return json.load(r)

    try:
        api("core/view/version")
    except Exception:
        return [Finding(Head.BACKEND, "ZAP daemon not reachable", Severity.INFO,
                        f"No ZAP API at {base}. Start ZAP in daemon mode on the runner.")]
    try:
        # Force the URL into ZAP's site tree first, else ascan-by-url 400s with
        # "URL Not Found in the Scan Tree".
        api("core/action/accessUrl", url=url)
        sid = str(api("spider/action/scan", url=url).get("scan", "0"))
        dl = time.time() + 120
        while time.time() < dl:
            if api("spider/view/status", scanId=sid).get("status") == "100":
                break
            time.sleep(3)
        asid = str(api("ascan/action/scan", url=url, recurse="true").get("scan", "0"))
        dl = time.time() + 360
        while time.time() < dl:
            if api("ascan/view/status", scanId=asid).get("status") == "100":
                break
            time.sleep(5)
        alerts = api("core/view/alerts", baseurl=url).get("alerts", [])
    except Exception as e:
        return [Finding(Head.BACKEND, "ZAP scan error", Severity.INFO, str(e)[:200])]
    return [Finding(Head.BACKEND, f"ZAP: {a.get('alert', '')}", _map_sev(a.get("risk", "")),
                    (a.get("description", "") or "")[:400], evidence=str(a.get("url", ""))[:120],
                    remediation=(a.get("solution", "") or "")[:300]) for a in alerts]


def _sqlmap(url: str) -> list[Finding]:
    if not _have("sqlmap"):
        return [_missing("sqlmap")]
    try:
        p = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--smart", "--level=1", "--risk=1",
             "--technique=BEUS", "--flush-session", "--disable-coloring"],
            capture_output=True, text=True, timeout=TOOL_TIMEOUT)
    except subprocess.TimeoutExpired:
        return [Finding(Head.BACKEND, "sqlmap timed out", Severity.INFO, "Exceeded 15m.")]
    txt = (p.stdout or "") + (p.stderr or "")
    if "is vulnerable" in txt or "injectable" in txt.lower():
        return [Finding(Head.BACKEND, "SQL injection detected", Severity.CRITICAL,
                        "sqlmap flagged an injectable parameter (detect-only, no data dumped).",
                        evidence="see sqlmap session log",
                        remediation="Use parameterized queries / prepared statements immediately.")]
    return []
