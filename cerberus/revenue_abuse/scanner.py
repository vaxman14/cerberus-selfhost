from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Head, Severity


_TEXT_SUFFIXES = {
    ".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb", ".go", ".java",
    ".kt", ".swift", ".sql", ".json", ".yaml", ".yml", ".toml",
}
_IGNORED_PARTS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".expo",
    "coverage", "Pods", "DerivedData", ".venv", "venv",
}


def _corpus(root: Path) -> tuple[str, list[Path]]:
    chunks: list[str] = []
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        if any(part in _IGNORED_PARTS for part in path.parts):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if len(text) > 2_000_000:
            continue
        files.append(path)
        chunks.append(f"\n// FILE: {path.relative_to(root)}\n{text}")
    return "".join(chunks), files


def _has(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None


def scan_repository(path: str | Path) -> list[Finding]:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository path is not a directory: {root}")
    text, files = _corpus(root)
    findings: list[Finding] = []

    trial = _has(text, r"\btrial(s|_days|Days|_ends?|Ends?|_usage)?\b|free[_ -]?tier")
    if not trial:
        return [Finding(
            Head.REVENUE, "No trial surface detected", Severity.INFO,
            f"Reviewed {len(files)} source/configuration files and found no clear trial or free-tier logic.",
            remediation="No trial-abuse gate is required unless the product introduces a limited trial.",
        )]

    server = _has(text, r"(middleware|route|controller|handler|server|api).{0,100}(trial|entitlement)|(trial|entitlement).{0,100}(middleware|server|api)")
    client_only = _has(text, r"(localStorage|AsyncStorage|UserDefaults|SharedPreferences).{0,120}trial")
    if client_only and not server:
        findings.append(Finding(
            Head.REVENUE, "Trial enforcement appears client-side", Severity.CRITICAL,
            "Trial state is stored in client-controlled storage without a matching server-side gate.",
            remediation="Move admission and usage accounting into an atomic backend transaction; treat client state as display-only.",
        ))

    account = _has(text, r"(user|account|auth).{0,100}(trial|usage)|(trial|usage).{0,100}(user_id|account_id)")
    device = _has(text, r"(device[_ -]?id|installation[_ -]?id|device[_ -]?hash|fingerprint)")
    if account and not device:
        findings.append(Finding(
            Head.REVENUE, "Fresh accounts can likely reset the trial", Severity.HIGH,
            "Trial accounting is tied to an account, but no durable device/installation identity was detected.",
            remediation="Meter both account and privacy-preserving hashed installation identities; neither identity should mint a second trial.",
        ))

    hard_ip = _has(text, r"(deny|block|reject|trial_used).{0,80}(ip_address|client_ip|remote_addr)|(ip_address|client_ip|remote_addr).{0,80}(deny|block|reject)")
    if hard_ip:
        findings.append(Finding(
            Head.REVENUE, "IP address may be used as a hard gate", Severity.HIGH,
            "Hard IP denial can punish unrelated people on shared Wi-Fi and is easy to evade.",
            remediation="Use IP only as a low-weight velocity signal (maximum 15 points), never as sole denial evidence.",
        ))

    fingerprint = _has(text, r"browser.?fingerprint|canvas.?fingerprint|machine.?id|hardware.?id")
    privacy_safe_install = _has(text, r"random(UUID|Bytes)|installation id.{0,100}secure storage|secure storage.{0,100}installation id")
    hashed_device = _has(text, r"(sha256|sha-256|hmac|digest).{0,120}(device|fingerprint)|(device|fingerprint).{0,120}(sha256|hmac|digest)")
    if device and (fingerprint or not privacy_safe_install) and not hashed_device:
        findings.append(Finding(
            Head.REVENUE, "Device identifier may be stored raw", Severity.MEDIUM,
            "Device or fingerprint tracking exists, but hashing/HMAC was not detected near the implementation.",
            remediation="Store a keyed HMAC of a random installation ID; never persist a raw fingerprint or invasive browser fingerprint.",
        ))

    velocity = _has(text, r"velocity|signup.{0,50}(count|rate|window)|rate.?limit.{0,80}(signup|trial)")
    payment = _has(text, r"payment[_ -]?(method|fingerprint).{0,80}(reuse|used|trial)|card[_ -]?fingerprint")
    risk = _has(text, r"risk[_ -]?(score|band)|step[_ -]?up|deny_trial_allow_purchase")
    retention = _has(text, r"retention|expires?_at|delete.{0,80}(fingerprint|trial_signal|risk_event)|ttl")
    audit = _has(text, r"audit[_ -]?(log|event)|risk[_ -]?event|trial[_ -]?decision")

    missing = []
    if not velocity:
        missing.append("signup/trial velocity")
    if not payment:
        missing.append("payment-method reuse")
    if not risk:
        missing.append("combined risk bands and step-up verification")
    if missing:
        findings.append(Finding(
            Head.REVENUE, "No multi-signal trial-abuse policy", Severity.MEDIUM,
            "Missing signals: " + ", ".join(missing) + ".",
            remediation="Combine independent signals conservatively: low=allow, medium=verify email/card, high=deny only the free trial while always allowing purchase.",
        ))
    if not retention:
        findings.append(Finding(
            Head.REVENUE, "No signal retention/deletion policy detected", Severity.MEDIUM,
            "Trial-risk identifiers can become privacy liability when retained indefinitely.",
            remediation="Add explicit expiry and deletion for risk events and hashed identifiers; retain only what is necessary for the abuse window.",
        ))
    if not audit:
        findings.append(Finding(
            Head.REVENUE, "Trial decisions are not auditable", Severity.LOW,
            "No structured trial-decision or risk-event audit trail was detected.",
            remediation="Record decision, score band, rule version, and reason codes without raw personal identifiers.",
        ))

    if not findings:
        findings.append(Finding(
            Head.REVENUE, "Trial-abuse controls detected", Severity.INFO,
            f"Reviewed {len(files)} source/configuration files; server, identity, risk, retention, and audit controls are represented.",
            remediation="Keep abuse-policy tests in CI and review thresholds against false-positive data.",
        ))
    return findings
