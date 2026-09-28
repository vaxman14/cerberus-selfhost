from __future__ import annotations
import os
import json
import urllib.parse
import urllib.request
from ..models import Finding, Severity, Head
from . import _steps

PSI = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"


def scan(url: str, log=None) -> list[Finding]:
    """Head 3: speed + build quality via PageSpeed Insights (Lighthouse).
    Low scores double as redesign/rebuild leads."""
    log = log or (lambda *_: None)
    _steps.say(log, "requesting Lighthouse report (Google, can take ~20s) …")
    key = os.environ.get("PAGESPEED_API_KEY")
    q = (f"{PSI}?url={urllib.parse.quote(url, safe='')}"
         "&strategy=mobile&category=performance&category=best-practices")
    if key:
        q += f"&key={key}"
    out: list[Finding] = []
    try:
        with urllib.request.urlopen(q, timeout=90) as r:
            data = json.load(r)
        cats = data["lighthouseResult"]["categories"]
    except Exception as e:
        log(_steps._fmt("Lighthouse report", "skip"))
        return [Finding(Head.SPEED, "Speed scan unavailable", Severity.INFO,
                        f"PageSpeed call failed ({e}). Set PAGESPEED_API_KEY for quota.")]

    def _add(cat, label):
        node = cats.get(cat)
        if node and node.get("score") is not None:
            score = int(node["score"] * 100)
            sev = (Severity.INFO if score >= 90
                   else Severity.LOW if score >= 50 else Severity.MEDIUM)
            out.append(Finding(Head.SPEED, f"{label}: {score}/100", sev,
                               f"Lighthouse {label} score is {score}.",
                               remediation=("Rebuild opportunity: CTF redesign lead."
                                            if score < 50 else "")))

    _steps.step(log, out, "Lighthouse · performance", lambda: _add("performance", "Performance"))
    _steps.step(log, out, "Lighthouse · best-practices", lambda: _add("best-practices", "Best Practices"))
    return out
