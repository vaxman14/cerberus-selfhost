from __future__ import annotations
import html
from datetime import datetime
from .models import ScanResult, Severity

_SEV_COLOR = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825",
              "low": "#2e7d32", "info": "#607d8b"}

CCPA = ("Under California's CCPA, a breach of unencrypted personal information can carry "
        "statutory damages of $100–$750 per consumer, per incident. The weaknesses this scan "
        "looks for are the class that leads there.")

_HEAD_DESC = {
    "frontend": ("The Surface", "HTTPS &amp; TLS, security headers, cookie safety, leaked secrets, and files that shouldn't be public."),
    "nose": ("The Nose", "Software versions, email-spoofing protection (SPF/DMARC), directory listings, and account exposure."),
    "speed": ("The Health", "Load speed and build quality that affect both users and search ranking."),
    "backend": ("The Hunt", "Active penetration testing for exploitable weaknesses."),
    "revenue": ("Revenue Protection", "Trial enforcement, identity reuse, abuse signals, privacy retention, and decision auditing."),
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
BOOK_URL = "https://ctfdesigns.com/book"
SUPPORT_URL = "https://buymeacoffee.com/romanvaxman"


def render_internal(result: ScanResult) -> str:
    rows = []
    for f in result.sorted():
        rows.append(
            f"<tr><td style='color:{_SEV_COLOR[f.severity.value]};font-weight:700'>"
            f"{f.severity.value.upper()}</td><td>{html.escape(f.head.value)}</td>"
            f"<td>{html.escape(f.title)}</td><td>{html.escape(f.detail)}</td>"
            f"<td>{html.escape(f.remediation)}</td></tr>"
        )
    return (f"<h1>Cerberus report — {html.escape(result.target)}</h1>"
            f"<p>Client: {html.escape(result.client)} · Findings: {len(result.findings)} · "
            f"Worst: {result.worst().value.upper()}</p>"
            "<table border=1 cellpadding=6 cellspacing=0>"
            "<tr><th>Severity</th><th>Head</th><th>Finding</th><th>Detail</th><th>Fix</th></tr>"
            + "".join(rows) + "</table>")


# diagnostic/connectivity noise that shouldn't appear on a client-facing report
_NOISE_TITLES = {"Target unreachable", "TLS check failed"}


def _verdict(findings):
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f.severity.value] += 1
    if counts["critical"] or counts["high"]:
        return ("Action needed", "#b00020", counts,
                "We found issues a motivated attacker could use. These should be fixed promptly.")
    if counts["medium"]:
        return ("Room to harden", "#f9a825", counts,
                "No critical exposure, but there are real gaps worth closing before they're found for you.")
    if counts["low"]:
        return ("Looking solid", "#2e7d32", counts,
                "Only minor, low-risk items. A little polish and this is in good shape.")
    return ("Clean bill", "#2e7d32", counts,
            "No security issues surfaced in this scan. Nicely maintained. This is a snapshot, not a guarantee.")


def render_client(result: ScanResult) -> str:
    shown = [f for f in result.findings if f.title not in _NOISE_TITLES]
    label, color, counts, verdict_text = _verdict(shown)
    when = datetime.now().strftime("%B %-d, %Y")
    target = html.escape(result.target)

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}1a;color:{_SEV_COLOR[s]};border:1px solid {_SEV_COLOR[s]}55">'
        f'{counts[s]} {s}</span>'
        for s in _SEV_ORDER if counts[s]
    ) or '<span class="chip" style="background:#2e7d321a;color:#2e7d32;border:1px solid #2e7d3255">0 issues</span>'

    blocks = []
    for s in _SEV_ORDER:
        fs = [f for f in shown if f.severity.value == s]
        if not fs:
            continue
        cards = ""
        for f in fs:
            fix = (f'<div class="fix"><span>How to fix</span> {html.escape(f.remediation)}</div>'
                   if f.remediation else "")
            cards += (
                f'<div class="card" style="border-left:4px solid {_SEV_COLOR[s]}">'
                f'<div class="card-h"><b>{html.escape(f.title)}</b>'
                f'<span class="sev" style="background:{_SEV_COLOR[s]}">{s.upper()}</span></div>'
                f'<p>{html.escape(f.detail)}</p>{fix}</div>'
            )
        blocks.append(cards)
    findings_html = "".join(blocks)
    if not findings_html:
        findings_html = ('<div class="clean">No issues surfaced across the checks we ran. '
                         'A clean result is a good sign — and worth keeping that way with periodic re-scans.</div>')

    scanned = ""
    for h in (result.heads_run or []):
        if h in _HEAD_DESC:
            name, desc = _HEAD_DESC[h]
            scanned += f'<li><b>{name}</b> — {desc}</li>'
    scanned_block = f'<div class="section"><h2>What we scanned</h2><ul class="scanned">{scanned}</ul></div>' if scanned else ""

    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>
  body{{margin:0;background:#f4f5f7;color:#1c2128;font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
  .wrap{{max-width:760px;margin:0 auto;background:#fff}}
  .top{{background:#0b0d10;color:#fff;padding:26px 34px;display:flex;justify-content:space-between;align-items:center}}
  .brand{{font-size:22px;font-weight:800;letter-spacing:.5px}} .brand b{{color:#e5484d}}
  .brand small{{display:block;font-size:11px;font-weight:500;color:#8b97a3;letter-spacing:.04em;margin-top:2px}}
  .top .date{{font-size:12px;color:#8b97a3;text-align:right}}
  .body{{padding:30px 34px 40px}}
  h1{{font-size:22px;margin:0 0 4px}} .target{{color:#57606a;font-size:14px;margin:0 0 22px}}
  .verdict{{border-radius:12px;padding:18px 20px;color:#fff;margin-bottom:18px}}
  .verdict h3{{margin:0 0 4px;font-size:18px}} .verdict p{{margin:0;opacity:.92;font-size:14px}}
  .chips{{margin:0 0 26px}} .chip{{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:5px 11px;margin:0 6px 6px 0}}
  .section{{margin-bottom:26px}} h2{{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:#57606a;border-bottom:1px solid #eaecef;padding-bottom:8px;margin:0 0 14px}}
  .card{{background:#fbfcfd;border:1px solid #eaecef;border-radius:8px;padding:14px 16px;margin-bottom:12px}}
  .card-h{{display:flex;justify-content:space-between;align-items:center;gap:10px}} .card-h b{{font-size:15px}}
  .card p{{margin:6px 0 0;color:#424a53;font-size:14px}}
  .sev{{color:#fff;font-size:10px;font-weight:700;border-radius:5px;padding:3px 7px;letter-spacing:.04em;white-space:nowrap}}
  .fix{{margin-top:10px;font-size:13.5px;color:#1c2128;background:#eef6ff;border-radius:6px;padding:8px 11px}}
  .fix span{{font-weight:700;color:#0969da;margin-right:5px}}
  .clean{{background:#eaf6ec;border:1px solid #cfe8d4;color:#256029;border-radius:8px;padding:16px 18px}}
  ul.scanned{{margin:0;padding-left:18px;color:#424a53;font-size:14px}} ul.scanned li{{margin-bottom:6px}}
  .note{{background:#fff8e6;border:1px solid #f4e0a3;border-radius:8px;padding:13px 16px;font-size:13px;color:#6b5900;margin-bottom:24px}}
  .cta{{background:#0b0d10;border-radius:12px;padding:22px 24px;text-align:center;color:#fff}}
  .cta h3{{margin:0 0 6px;font-size:17px}} .cta p{{margin:0 0 14px;color:#c7cdd4;font-size:14px}}
  .cta a{{display:inline-block;background:#e5484d;color:#fff;text-decoration:none;font-weight:700;border-radius:8px;padding:11px 22px}}
  .cta a.coffee{{background:#ffdd00;color:#111;margin-left:8px}}
  .foot{{text-align:center;color:#8b97a3;font-size:11.5px;padding:18px}}
</style></head><body>
<div class="wrap">
  <div class="top"><div class="brand">Cerber<b>us</b><small>Web-security scan · by CTF Designs</small></div>
    <div class="date">Security Snapshot<br>{when}</div></div>
  <div class="body">
    <h1>Security Snapshot</h1>
    <p class="target">{target}</p>
    <div class="verdict" style="background:{color}"><h3>{label}</h3><p>{verdict_text}</p></div>
    <div class="chips">{chips}</div>
    {scanned_block}
    <div class="section"><h2>Findings</h2>{findings_html}</div>
    <div class="note">{CCPA}</div>
    <div class="cta"><h3>Want these handled?</h3>
      <p>CTF Designs builds and hardens sites for a living. We can fix what's here — or go deeper.</p>
      <a href="{BOOK_URL}">Book a call →</a>
      <a class="coffee" href="{SUPPORT_URL}">☕ Buy me a coffee</a></div>
  </div>
  <div class="foot">Automated scan — a snapshot, not a guarantee of security. &nbsp;·&nbsp; Cerberus by CTF Designs &nbsp;·&nbsp; {when}</div>
</div>
</body></html>"""
