from __future__ import annotations

import json
import os
import sqlite3
import urllib.request
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult


def _supabase_cfg() -> tuple[str | None, str | None]:
    return os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_SERVICE_KEY")


def _sqlite_path() -> Path:
    return Path(os.environ.get("CERBERUS_DB_PATH", "/data/cerberus.db"))


def _db() -> sqlite3.Connection:
    path = _sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          created_at TEXT NOT NULL,
          client TEXT NOT NULL,
          target TEXT NOT NULL,
          worst_severity TEXT NOT NULL,
          finding_count INTEGER NOT NULL,
          log TEXT,
          authorization_id TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          head TEXT NOT NULL,
          title TEXT NOT NULL,
          severity TEXT NOT NULL,
          detail TEXT NOT NULL,
          evidence TEXT NOT NULL DEFAULT '',
          remediation TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        """
    )
    return conn


def _post(path: str, payload) -> list | None:
    url, key = _supabase_cfg()
    if not url or not key:
        return None
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    req = urllib.request.Request(
        f"{url}/rest/v1/{path}", data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except Exception:
        return None


def _get(path: str) -> list | None:
    url, key = _supabase_cfg()
    if not url or not key:
        return None
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}
    req = urllib.request.Request(f"{url}/rest/v1/{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.load(response)
    except Exception:
        return None


def save(result: ScanResult, log: str | None = None,
         authorization_id: str | None = None) -> str | None:
    """Persist a scan to Supabase when configured, otherwise to local SQLite."""
    row = {
        "client": result.client,
        "target": result.target,
        "worst_severity": result.worst().value,
        "finding_count": len(result.findings),
    }
    if log is not None:
        row["log"] = log
    if authorization_id:
        row["authorization_id"] = authorization_id

    url, key = _supabase_cfg()
    if url and key:
        rows = _post("cerberus_scans", row)
        if not rows:
            return None
        scan_id = rows[0]["id"]
        if result.findings:
            _post("cerberus_findings",
                  [{**finding.to_dict(), "scan_id": scan_id}
                   for finding in result.findings])
        return scan_id

    scan_id = uuid.uuid4().hex
    with closing(_db()) as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO scans
                  (id, created_at, client, target, worst_severity, finding_count,
                   log, authorization_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    datetime.now(timezone.utc).isoformat(),
                    result.client,
                    result.target,
                    result.worst().value,
                    len(result.findings),
                    log,
                    authorization_id,
                ),
            )
            conn.executemany(
                """
                INSERT INTO findings
                  (scan_id, head, title, severity, detail, evidence, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        finding.head.value,
                        finding.title,
                        finding.severity.value,
                        finding.detail,
                        finding.evidence,
                        finding.remediation,
                    )
                    for finding in result.findings
                ],
            )
    return scan_id


def list_scans(client: str | None = None, limit: int = 50) -> list:
    """Return past scans newest first, optionally filtered by client."""
    url, key = _supabase_cfg()
    if url and key:
        from urllib.parse import quote
        query = (
            "cerberus_scans?select=id,created_at,client,target,worst_severity,"
            f"finding_count&order=created_at.desc&limit={int(limit)}"
        )
        if client:
            query += f"&client=eq.{quote(client)}"
        return _get(query) or []

    sql = (
        "SELECT id, created_at, client, target, worst_severity, finding_count "
        "FROM scans"
    )
    args: list[object] = []
    if client:
        sql += " WHERE client = ?"
        args.append(client)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    with closing(_db()) as conn:
        return [dict(row) for row in conn.execute(sql, args).fetchall()]


def get_scan(scan_id: str) -> dict | None:
    url, key = _supabase_cfg()
    if url and key:
        rows = _get(f"cerberus_scans?id=eq.{scan_id}&select=*&limit=1")
        return rows[0] if rows else None
    with closing(_db()) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_findings(scan_id: str) -> list:
    url, key = _supabase_cfg()
    if url and key:
        return _get(
            f"cerberus_findings?scan_id=eq.{scan_id}"
            "&select=head,title,severity,detail,evidence,remediation") or []
    with closing(_db()) as conn:
        rows = conn.execute(
            """
            SELECT head, title, severity, detail, evidence, remediation
            FROM findings WHERE scan_id = ? ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def save_agreement(client: str, filename: str, file_b64: str,
                   scope_hosts=None) -> str | None:
    """Store an uploaded authorization when Supabase is configured."""
    rows = _post("cerberus_authorizations", {
        "client": client,
        "scope_hosts": scope_hosts or [],
        "filename": filename,
        "file_b64": file_b64,
    })
    return rows[0]["id"] if rows else None


def agreement_exists(auth_id: str) -> bool:
    """Return whether a Supabase authorization record exists."""
    if not auth_id:
        return False
    rows = _get(f"cerberus_authorizations?id=eq.{auth_id}&select=id")
    return bool(rows)
