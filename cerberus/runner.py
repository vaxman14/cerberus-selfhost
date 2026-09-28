from __future__ import annotations
from urllib.parse import urlparse
from .models import AuthRecord, ScanResult, Head
from .scope import ScopeFirewall
from .governor import SafetyGovernor
from .auth_gate import AuthorizationGate, AuthorizationError
from .heads import frontend, speed, backend, nose
from . import persistence


_HEAD_LABEL = {"frontend": "The Surface (exposure)",
               "speed": "The Health (vitality)",
               "nose": "The Nose (sniff)",
               "backend": "The Hunt (intrusion)"}


def run_scan(url: str, client: str = "prospect",
             heads=("frontend", "speed"), auth_ref: str | None = None,
             staging: bool = False, allow_prod: bool = False, log_cb=None,
             admin_override: bool = False):
    """Full pipeline: build auth + scope, run each authorized head through the
    governor, persist (with the full log transcript), and return
    (result, scan_id, skipped_messages). log_cb(line) streams live progress."""
    logs: list[str] = []

    def log(msg: str) -> None:
        logs.append(msg)
        if log_cb:
            try:
                log_cb(msg)
            except Exception:
                pass

    host = urlparse(url).hostname or ""
    log(f"$ cerberus scan {url}")
    log(f"  target host: {host}")
    log(f"  heads: {', '.join(heads)}")
    auth = AuthRecord(client=client, scope_hosts=[host],
                      signed_authorization_ref=auth_ref,
                      allow_production_active=allow_prod,
                      admin_override=admin_override)
    scope = ScopeFirewall(auth.scope_hosts)
    gov = SafetyGovernor(scope)
    gate = AuthorizationGate(auth)
    result = ScanResult(target=url, client=client, heads_run=list(heads))
    skipped: list[str] = []
    log("  authorization ref: " + (auth_ref or "(none)"))
    log("")

    for name in heads:
        head = Head(name)
        label = _HEAD_LABEL.get(name, name)
        log(f">> {label}")
        try:
            gate.authorize(head)
        except AuthorizationError as e:
            skipped.append(str(e))
            log(f"   SKIPPED: {e}")
            log("")
            continue
        before = len(result.findings)
        if head is Head.FRONTEND:
            result.findings += frontend.scan(url, gov, log=log)
        elif head is Head.NOSE:
            result.findings += nose.scan(url, gov, log=log)
        elif head is Head.SPEED:
            result.findings += speed.scan(url, log=log)
        elif head is Head.BACKEND:
            result.findings += backend.scan(url, auth, staging=staging, log=log)
        found = len(result.findings) - before
        log(f"   done — {found} finding(s)")
        log("")

    log(f"== scan complete: {len(result.findings)} finding(s), worst = {result.worst().value}")
    log("   saving to database...")
    scan_id = persistence.save(result, log="\n".join(logs), authorization_id=auth_ref)
    log(f"   saved. scan_id = {scan_id or '(db off)'}")
    return result, scan_id, skipped
