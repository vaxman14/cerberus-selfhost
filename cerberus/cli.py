from __future__ import annotations
import argparse
import json
from pathlib import Path
from urllib.parse import urlparse
from . import runner, reporting
from .models import ScanResult
from .revenue_abuse import scan_repository


def main():
    ap = argparse.ArgumentParser(prog="cerberus")
    ap.add_argument("cmd", choices=["scan", "audit-trials"])
    ap.add_argument("url", help="URL for scan, or repository path for audit-trials")
    ap.add_argument("--client", default="prospect")
    ap.add_argument("--heads", default="frontend,speed")
    ap.add_argument("--auth-ref", default=None,
                    help="SignWell signed authorization ref (unlocks backend)")
    ap.add_argument("--staging", action="store_true",
                    help="target is a staging clone (enables backend active tests)")
    ap.add_argument("--allow-prod", action="store_true",
                    help="acknowledge active-testing risk on a production target")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    if a.cmd == "audit-trials":
        root = Path(a.url).expanduser().resolve()
        result = ScanResult(target=str(root), client=a.client,
                            findings=scan_repository(root), heads_run=["revenue"])
        for f in result.sorted():
            print(f"[{f.severity.value.upper():8}] {f.title}\n  {f.detail}\n  Fix: {f.remediation}")
        if a.out:
            payload = {"target": str(root), "worst": result.worst().value,
                       "findings": [f.to_dict() for f in result.sorted()]}
            Path(a.out).write_text(json.dumps(payload, indent=2) + "\n")
        return

    heads = tuple(h.strip() for h in a.heads.split(",") if h.strip())
    result, scan_id, skipped = runner.run_scan(
        a.url, client=a.client, heads=heads, auth_ref=a.auth_ref,
        staging=a.staging, allow_prod=a.allow_prod)

    for s in skipped:
        print(f"[skip] {s}")
    tail = f" · saved scan {scan_id}" if scan_id else " · (not persisted)"
    print(f"\n{len(result.findings)} findings, worst = {result.worst().value.upper()}{tail}")
    for f in result.sorted():
        print(f"  [{f.severity.value.upper():8}] {f.head.value:8} {f.title}")

    host = urlparse(a.url).hostname or "target"
    internal = a.out or f"cerberus-report-{host}.html"
    client_out = internal[:-5] + "-client.html" if internal.endswith(".html") else internal + "-client.html"
    with open(internal, "w") as fh:
        fh.write(reporting.render_internal(result))
    with open(client_out, "w") as fh:
        fh.write(reporting.render_client(result))
    print(f"\nInternal report: {internal}\nClient report:   {client_out}")


if __name__ == "__main__":
    main()
