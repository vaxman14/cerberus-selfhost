from __future__ import annotations
import os
import json
import time
import shutil
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from ..models import Finding, Severity, Head, AuthRecord
from .. import tool_client
from ..cancellation import check, ScanCancelled
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


def scan(url: str, auth: AuthRecord, staging: bool = False, log=None,
         cancel_event=None, run_id: str = "") -> list[Finding]:
    """Head 2: active backend attack orchestration (nuclei / ZAP / sqlmap).
    Caller MUST have passed AuthorizationGate first. Refuses production targets
    unless auth.allow_production_active is set."""
    log = log or (lambda *_: None)
    if not staging and not auth.allow_production_active:
        return [Finding(Head.BACKEND, "Active scan withheld", Severity.INFO,
                        "Target is production and allow_production_active is not set. "
                        "Point at a staging clone or explicitly acknowledge prod risk.")]
    out: list[Finding] = []
    check(cancel_event)
    _steps.say(log, "arming active toolchain (this bites — can take minutes) …")
    _steps.say(log, "nuclei · templated CVE / misconfig sweep …")
    _steps.step(log, out, "nuclei", lambda: out.extend(_nuclei(url, run_id)))
    check(cancel_event)
    _steps.say(log, "OWASP ZAP · active injection scan …")
    _steps.step(log, out, "OWASP ZAP", lambda: out.extend(_zap(url, cancel_event)))
    check(cancel_event)
    _steps.say(log, "sqlmap · SQL-injection probe …")
    _steps.step(log, out, "sqlmap", lambda: out.extend(_sqlmap(url, run_id)))
    check(cancel_event)
    return out


def _nuclei(url: str, run_id: str = "") -> list[Finding]:
    try:
        payload = tool_client.run("nuclei", url, timeout=680, run_id=run_id)
    except tool_client.ToolServiceError as exc:
        raise RuntimeError(f"Nuclei scan did not complete: {str(exc)[:160]}") from exc
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in payload.get("findings", []):
        title = str(item.get("title", "Nuclei finding"))[:200]
        detail = str(item.get("detail", ""))[:400]
        evidence = str(item.get("evidence", ""))[:160]
        identity = (title, detail, evidence)
        if identity in seen:
            continue
        seen.add(identity)
        findings.append(Finding(
            Head.BACKEND, title, _map_sev(str(item.get("severity", "info"))), detail,
            evidence=evidence, remediation=str(item.get("remediation", ""))[:400],
        ))
    return findings


def _zap(url: str, cancel_event=None) -> list[Finding]:
    base = os.environ.get("ZAP_API", "http://localhost:8080")
    key = os.environ.get("ZAP_API_KEY", "")
    key_file = os.environ.get("ZAP_API_KEY_FILE", "")
    if key_file:
        try:
            key = Path(key_file).read_text(encoding="utf-8").strip()
        except OSError:
            return [Finding(Head.BACKEND, "ZAP credential unavailable", Severity.INFO,
                            "The configured ZAP API-key file could not be read.")]

    def api(path, **params):
        params["apikey"] = key
        q = urllib.parse.urlencode(params)
        with urllib.request.urlopen(f"{base}/JSON/{path}/?{q}", timeout=30) as r:
            return json.load(r)

    try:
        api("core/view/version")
    except Exception as exc:
        raise RuntimeError(f"ZAP daemon not reachable at {base}") from exc
    try:
        # ZAP is a long-running sidecar. Its alert store survives between scans,
        # so clear it before this run or fixed issues reappear as stale findings.
        api("core/action/deleteAllAlerts")
        # Force the URL into ZAP's site tree first, else ascan-by-url 400s with
        # "URL Not Found in the Scan Tree".
        api("core/action/accessUrl", url=url)
        sid = str(api("spider/action/scan", url=url).get("scan", "0"))
        dl = time.time() + 120
        while time.time() < dl:
            if cancel_event is not None and cancel_event.is_set():
                api("spider/action/stop", scanId=sid)
                raise ScanCancelled("scan stopped by operator")
            if api("spider/view/status", scanId=sid).get("status") == "100":
                break
            time.sleep(3)
        asid = str(api("ascan/action/scan", url=url, recurse="true").get("scan", "0"))
        dl = time.time() + 360
        while time.time() < dl:
            if cancel_event is not None and cancel_event.is_set():
                api("ascan/action/stop", scanId=asid)
                raise ScanCancelled("scan stopped by operator")
            if api("ascan/view/status", scanId=asid).get("status") == "100":
                break
            time.sleep(5)
        alerts = api("core/view/alerts", baseurl=url).get("alerts", [])
    except ScanCancelled:
        raise
    except Exception as e:
        raise RuntimeError(f"ZAP active scan did not complete: {str(e)[:160]}") from e
    grouped: dict[tuple[str, str, str, str], dict] = {}
    for alert in alerts:
        key = (
            str(alert.get("alert", "")), str(alert.get("risk", "")),
            str(alert.get("description", "")), str(alert.get("solution", "")),
        )
        bucket = grouped.setdefault(key, {"alert": alert, "urls": []})
        affected = str(alert.get("url", ""))
        if affected and affected not in bucket["urls"]:
            bucket["urls"].append(affected)

    findings: list[Finding] = []
    for bucket in grouped.values():
        alert = bucket["alert"]
        urls = bucket["urls"]
        evidence = urls[0][:120] if urls else ""
        if len(urls) > 1:
            evidence = f"{evidence} (+{len(urls) - 1} more URL{'s' if len(urls) != 2 else ''})"
        findings.append(Finding(
            Head.BACKEND, f"ZAP: {alert.get('alert', '')}",
            _map_sev(alert.get("risk", "")),
            (alert.get("description", "") or "")[:400], evidence=evidence,
            remediation=(alert.get("solution", "") or "")[:300],
        ))
    return findings


def _sqlmap(url: str, run_id: str = "") -> list[Finding]:
    try:
        payload = tool_client.run("sqlmap", url, timeout=TOOL_TIMEOUT + 30, run_id=run_id)
    except tool_client.ToolServiceError as exc:
        return [Finding(Head.BACKEND, "sqlmap unavailable", Severity.INFO, str(exc))]
    if payload.get("vulnerable"):
        return [Finding(Head.BACKEND, "SQL injection detected", Severity.CRITICAL,
                        "sqlmap flagged an injectable parameter (detect-only, no data dumped).",
                        evidence="see sqlmap session log",
                        remediation="Use parameterized queries / prepared statements immediately.")]
    return []
