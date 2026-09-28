from __future__ import annotations
import re
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from ..config import EXPOSED_PATHS, SECURITY_HEADERS, SECRET_PATTERNS
from ..models import Finding, Severity, Head
from ..governor import SafetyGovernor
from . import _steps


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def scan(url: str, gov: SafetyGovernor, log=None) -> list[Finding]:
    """Head 1: passive, legal frontend audit. Fetches public content only.
    Logs each individual check to `log` for the live console."""
    log = log or (lambda *_: None)
    out: list[Finding] = []
    _steps.say(log, "connecting to target …")
    try:
        resp = gov.get(url)
    except Exception as e:
        out.append(Finding(Head.FRONTEND, "Target unreachable", Severity.INFO, str(e)))
        log(_steps._fmt("reachability", "FAIL"))
        return out

    _steps.step(log, out, "HTTPS / TLS enforcement", lambda: _check_https(url, out))

    have = {k.lower() for k in resp.headers}
    for h, why in SECURITY_HEADERS.items():
        _steps.step(log, out, f"header · {h}",
                    lambda h=h, why=why: _one_header(have, h, why, out))

    _steps.step(log, out, "cookie security flags", lambda: _check_cookies(resp, out))
    _steps.step(log, out, "exposed secrets / source maps",
                lambda: _scan_js(url, resp, gov, out))

    base = _base(url)
    baseline = _baseline(base, gov)
    for path in EXPOSED_PATHS:
        _steps.step(log, out, f"probe {path}",
                    lambda p=path: _probe_one(base, p, baseline, gov, out))
    return out


def _check_https(url, out):
    p = urlparse(url)
    if p.scheme != "https":
        out.append(Finding(Head.FRONTEND, "No HTTPS", Severity.HIGH,
                           "Site served over plaintext HTTP.",
                           remediation="Force HTTPS and enable HSTS."))
        return
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=p.hostname) as s:
            s.settimeout(10)
            s.connect((p.hostname, 443))
            cert = s.getpeercert()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 15:
            out.append(Finding(Head.FRONTEND, "TLS cert expiring", Severity.MEDIUM,
                               f"Certificate expires in {days} days.",
                               remediation="Renew / verify auto-renewal."))
    except Exception as e:
        out.append(Finding(Head.FRONTEND, "TLS check failed", Severity.LOW, str(e)))


def _one_header(have, h, why, out):
    if h not in have:
        sev = Severity.MEDIUM if h in ("content-security-policy", "strict-transport-security") else Severity.LOW
        out.append(Finding(Head.FRONTEND, f"Missing header: {h}", sev, why,
                           remediation=f"Set the {h} response header."))


def _check_cookies(resp, out):
    for c in resp.cookies:
        flags = []
        if not c.secure:
            flags.append("Secure")
        if not c.has_nonstandard_attr("HttpOnly"):
            flags.append("HttpOnly")
        if flags:
            out.append(Finding(Head.FRONTEND, f"Cookie missing flags: {c.name}", Severity.LOW,
                               f"Cookie '{c.name}' missing: {', '.join(flags)}.",
                               remediation="Set Secure, HttpOnly and SameSite on session cookies."))


def _scan_js(url, resp, gov, out):
    html = resp.text
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    bodies = [("inline HTML", html)]
    for src in scripts[:15]:
        full = urljoin(url, src)
        if not gov.scope.in_scope(full):
            continue
        try:
            bodies.append((full, gov.get(full).text))
        except Exception:
            continue
    for where, body in bodies:
        if "sourceMappingURL" in body:
            out.append(Finding(Head.FRONTEND, "Source map exposed", Severity.LOW,
                               f"sourceMappingURL referenced in {where}. Original source may be downloadable.",
                               remediation="Strip source maps from production builds."))
        for name, pat in SECRET_PATTERNS.items():
            for m in re.findall(pat, body):
                out.append(Finding(Head.FRONTEND, f"Possible leaked secret: {name}", Severity.HIGH,
                                   f"Pattern for {name} found in {where}.",
                                   evidence=str(m)[:12] + "...",
                                   remediation="Rotate the key and move secrets server-side."))


def _baseline(base, gov):
    # A path that should NOT exist. If it returns 200, the server is a catch-all
    # (SPA host like Netlify), so we must compare bodies to avoid false positives.
    try:
        b = gov.get(base + "/cerberus-probe-404-baseline-xyz")
        return (b.status_code == 200, b.text[:2000])
    except Exception:
        return (False, "")


def _probe_one(base, path, baseline, gov, out):
    baseline_200, baseline_body = baseline
    target = base + path
    try:
        r = gov.get(target)
    except Exception:
        return
    if r.status_code != 200 or not r.content:
        return
    ctype = r.headers.get("content-type", "").lower()
    if baseline_200 and r.text[:2000] == baseline_body:
        return
    if "text/html" in ctype:
        return
    out.append(Finding(Head.FRONTEND, f"Exposed file: {path}", Severity.HIGH,
                       f"{target} returned 200 as {ctype or 'unknown type'}.",
                       evidence=r.text[:60].replace("\n", " "),
                       remediation="Block or remove this path."))
