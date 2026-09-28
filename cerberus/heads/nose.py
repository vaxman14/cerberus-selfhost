from __future__ import annotations
import re
import requests
import tldextract
from urllib.parse import urlparse
from ..models import Finding, Severity, Head
from ..governor import SafetyGovernor
from . import _steps

# The Nose: "like The Hunt, but no fangs." Deeper reconnaissance than The Surface,
# but strictly PASSIVE — it sniffs (reads headers, public records, safe GETs). It
# never sends attack payloads, never fuzzes, never tries to exploit anything.

_OLD_HINTS = [
    (r"apache/2\.[0-2]\b", "Apache 2.2 or older"),
    (r"nginx/1\.(?:[0-9]|1[0-2])\b", "an old nginx (<1.13)"),
    (r"php/[45]\b", "PHP 5.x/4.x (end-of-life)"),
    (r"openssl/1\.0", "OpenSSL 1.0.x (end-of-life)"),
    (r"iis/[1-7]\.", "an old IIS (<8)"),
]

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def scan(url: str, gov: SafetyGovernor, log=None) -> list[Finding]:
    log = log or (lambda *_: None)
    out: list[Finding] = []
    _steps.say(log, "sniffing target (passive recon) …")
    try:
        resp = gov.get(url)
    except Exception as e:
        out.append(Finding(Head.NOSE, "Target unreachable", Severity.INFO, str(e)))
        log(_steps._fmt("reachability", "FAIL"))
        return out
    host = urlparse(url).hostname or ""
    _steps.step(log, out, "server / tech fingerprint", lambda: _fingerprint(resp, out))
    _steps.step(log, out, "SPF (email spoofing)", lambda: _spf(host, out))
    _steps.step(log, out, "DMARC policy", lambda: _dmarc(host, out))
    _steps.step(log, out, "security.txt disclosure", lambda: _security_txt(url, gov, out))
    _steps.step(log, out, "directory listing", lambda: _dir_listing(url, gov, out))
    _steps.step(log, out, "WordPress user exposure", lambda: _wp_user_enum(url, resp, gov, out))
    return out


def _fingerprint(resp, out):
    """Read what the server volunteers about its stack. Version disclosure is a
    minor leak; a recognizably ancient version is a real risk (passively noted)."""
    revealed = {}
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Drupal-Cache"):
        v = resp.headers.get(h)
        if v:
            revealed[h] = v
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text or "", re.I)
    if m:
        revealed["meta generator"] = m.group(1)

    for src, val in revealed.items():
        if re.search(r"\d+\.\d+", val):
            out.append(Finding(Head.NOSE, f"Version disclosed via {src}", Severity.LOW,
                               f"The site advertises '{val}'. Broadcasting exact versions helps attackers pick known exploits.",
                               evidence=val[:80],
                               remediation=f"Suppress the {src} version (e.g. ServerTokens Prod, expose_php Off, remove generator meta)."))
        low = val.lower()
        for pat, label in _OLD_HINTS:
            if re.search(pat, low):
                out.append(Finding(Head.NOSE, "Outdated software detected", Severity.MEDIUM,
                                   f"Response headers suggest {label} ('{val}'). Old versions carry publicly known vulnerabilities.",
                                   evidence=val[:80],
                                   remediation="Update to a current, supported version."))


def _doh_txt(name):
    try:
        r = requests.get("https://dns.google/resolve", params={"name": name, "type": "TXT"}, timeout=8)
        data = r.json()
        return [a.get("data", "").strip('"') for a in (data.get("Answer") or []) if a.get("type") == 16]
    except Exception:
        return None


def _mail_domain(host: str) -> str:
    """Return the registrable domain where organizational mail policy lives."""
    extracted = _TLD_EXTRACT(host)
    return extracted.top_domain_under_public_suffix or host


def _spf(host, out):
    if not host or host.replace(".", "").isdigit():
        return
    domain = _mail_domain(host)
    spf = _doh_txt(domain)
    if spf is not None and not any(t.lower().startswith("v=spf1") for t in spf):
        out.append(Finding(Head.NOSE, "No SPF record", Severity.MEDIUM,
                           f"{domain} has no SPF record. Anyone can forge email from this domain.",
                           remediation="Publish an SPF TXT record (e.g. v=spf1 include:... -all)."))


def _dmarc(host, out):
    if not host or host.replace(".", "").isdigit():
        return
    domain = _mail_domain(host)
    dmarc = _doh_txt("_dmarc." + domain)
    if dmarc is not None and not any(t.lower().startswith("v=dmarc1") for t in dmarc):
        out.append(Finding(Head.NOSE, "No DMARC record", Severity.MEDIUM,
                           f"{domain} has no DMARC policy. Spoofed email won't be rejected or reported.",
                           remediation="Publish a _dmarc TXT record (start with p=none, then tighten to quarantine/reject)."))


def _security_txt(url, gov, out):
    try:
        r = gov.get(_base(url) + "/.well-known/security.txt")
        if r.status_code == 200 and "contact" in r.text.lower():
            return  # present — good, no finding
    except Exception:
        return
    out.append(Finding(Head.NOSE, "No security.txt", Severity.INFO,
                       "No /.well-known/security.txt found. It gives security researchers a way to report issues to you responsibly.",
                       remediation="Add a security.txt with a Contact: line."))


def _dir_listing(url, gov, out):
    base = _base(url)
    for path in ("/uploads/", "/images/", "/files/", "/assets/", "/backup/"):
        try:
            r = gov.get(base + path)
        except Exception:
            continue
        if r.status_code == 200 and re.search(r"<title>\s*Index of /|<h1>\s*Index of /", r.text or "", re.I):
            out.append(Finding(Head.NOSE, f"Directory listing enabled: {path}", Severity.MEDIUM,
                               f"{base+path} returns a browsable file index. It can leak files you didn't mean to publish.",
                               remediation="Disable auto-indexing (Options -Indexes / autoindex off)."))


def _wp_user_enum(url, resp, gov, out):
    text = (resp.text or "").lower()
    is_wp = "wp-content" in text or "wp-json" in text or "wordpress" in text
    if not is_wp:
        return
    try:
        r = gov.get(_base(url) + "/wp-json/wp/v2/users")
    except Exception:
        return
    if r.status_code == 200 and r.text.strip().startswith("["):
        try:
            n = len(r.json())
        except Exception:
            n = 0
        if n:
            out.append(Finding(Head.NOSE, "WordPress user enumeration", Severity.MEDIUM,
                               f"The WordPress REST API lists {n} user account(s) publicly, handing attackers valid usernames for brute-force.",
                               remediation="Restrict /wp-json/wp/v2/users (plugin or server rule) and use strong, unique admin names."))
