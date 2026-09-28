from __future__ import annotations

import json
import hashlib
import os
import secrets
import sqlite3
import urllib.request
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
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
    conn.execute("PRAGMA foreign_keys=ON")
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
        CREATE TABLE IF NOT EXISTS llm_profiles (
          id TEXT PRIMARY KEY,
          label TEXT NOT NULL,
          provider TEXT NOT NULL,
          model TEXT NOT NULL,
          base_url TEXT,
          api_key_enc TEXT,
          external_acknowledged INTEGER NOT NULL DEFAULT 0,
          activated_at TEXT,
          probed_at TEXT,
          capabilities_json TEXT NOT NULL DEFAULT '{}',
          probe_steps_json TEXT NOT NULL DEFAULT '[]',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS llm_bridge_tokens (
          token_hash TEXT PRIMARY KEY,
          profile_id TEXT NOT NULL REFERENCES llm_profiles(id) ON DELETE CASCADE,
          expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_llm_bridge_expiry ON llm_bridge_tokens(expires_at);
        CREATE TABLE IF NOT EXISTS local_users (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'owner',
          created_at TEXT NOT NULL,
          last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS local_sessions (
          token_hash TEXT PRIMARY KEY,
          csrf_hash TEXT NOT NULL,
          user_id TEXT NOT NULL REFERENCES local_users(id) ON DELETE CASCADE,
          expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_local_sessions_expiry
          ON local_sessions(expires_at);
        CREATE TABLE IF NOT EXISTS scan_analyses (
          scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
          profile_id TEXT NOT NULL REFERENCES llm_profiles(id) ON DELETE CASCADE,
          content TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """
    )
    return conn


def local_user_count() -> int:
    with closing(_db()) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM local_users").fetchone()[0])


def create_local_user(username: str, password_hash: str, *, role: str = "owner") -> dict:
    user_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        with conn:
            conn.execute(
                "INSERT INTO local_users(id,username,password_hash,role,created_at) "
                "VALUES (?,?,?,?,?)",
                (user_id, username, password_hash, role, now),
            )
    return {"id": user_id, "username": username, "role": role, "created_at": now}


def get_local_user_by_username(username: str) -> dict | None:
    with closing(_db()) as conn:
        row = conn.execute(
            "SELECT id,username,password_hash,role,created_at,last_login_at "
            "FROM local_users WHERE username=? COLLATE NOCASE",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def create_local_session(user_id: str, token_hash: str, csrf_hash: str, *, hours: int = 24) -> None:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=max(1, min(hours, 168)))
    with closing(_db()) as conn:
        with conn:
            conn.execute("DELETE FROM local_sessions WHERE expires_at<=?", (now.isoformat(),))
            conn.execute(
                "INSERT INTO local_sessions(token_hash,csrf_hash,user_id,expires_at,created_at) "
                "VALUES (?,?,?,?,?)",
                (token_hash, csrf_hash, user_id, expires.isoformat(), now.isoformat()),
            )
            conn.execute(
                "UPDATE local_users SET last_login_at=? WHERE id=?",
                (now.isoformat(), user_id),
            )


def get_local_session(token_hash: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        row = conn.execute(
            """
            SELECT u.id,u.username,u.role,s.csrf_hash,s.expires_at
            FROM local_sessions s JOIN local_users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>?
            """,
            (token_hash, now),
        ).fetchone()
    return dict(row) if row else None


def delete_local_session(token_hash: str) -> None:
    with closing(_db()) as conn:
        with conn:
            conn.execute("DELETE FROM local_sessions WHERE token_hash=?", (token_hash,))


def save_scan_analysis(scan_id: str, profile_id: str, content: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO scan_analyses(scan_id,profile_id,content,created_at)
                VALUES (?,?,?,?)
                ON CONFLICT(scan_id) DO UPDATE SET
                  profile_id=excluded.profile_id,content=excluded.content,
                  created_at=excluded.created_at
                """,
                (scan_id, profile_id, content, now),
            )
    return {"scan_id": scan_id, "profile_id": profile_id,
            "content": content, "created_at": now}


def get_scan_analysis(scan_id: str) -> dict | None:
    with closing(_db()) as conn:
        row = conn.execute(
            "SELECT scan_id,profile_id,content,created_at FROM scan_analyses WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
    return dict(row) if row else None


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


def list_llm_profiles() -> list[dict]:
    """Return redacted local profiles. Ciphertext never crosses the API."""
    with closing(_db()) as conn:
        rows = conn.execute(
            """
            SELECT id, label, provider, model, base_url,
                   api_key_enc IS NOT NULL AS has_api_key,
                   external_acknowledged, activated_at, probed_at,
                   capabilities_json, probe_steps_json, created_at, updated_at
            FROM llm_profiles ORDER BY created_at ASC
            """
        ).fetchall()
    values = []
    for row in rows:
        item = dict(row)
        item["has_api_key"] = bool(item["has_api_key"])
        item["external_acknowledged"] = bool(item["external_acknowledged"])
        item["capabilities"] = json.loads(item.pop("capabilities_json") or "{}")
        item["probe_steps"] = json.loads(item.pop("probe_steps_json") or "[]")
        values.append(item)
    return values


def get_llm_profile(profile_id: str, *, include_ciphertext: bool = False) -> dict | None:
    columns = "*" if include_ciphertext else (
        "id, label, provider, model, base_url, "
        "api_key_enc IS NOT NULL AS has_api_key, external_acknowledged, "
        "activated_at, probed_at, capabilities_json, probe_steps_json, created_at, updated_at"
    )
    with closing(_db()) as conn:
        row = conn.execute(
            f"SELECT {columns} FROM llm_profiles WHERE id = ?", (profile_id,)
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    if "has_api_key" in item:
        item["has_api_key"] = bool(item["has_api_key"])
    item["external_acknowledged"] = bool(item["external_acknowledged"])
    item["capabilities"] = json.loads(item.pop("capabilities_json") or "{}")
    item["probe_steps"] = json.loads(item.pop("probe_steps_json") or "[]")
    return item


def save_llm_profile(
    *, profile_id: str | None, label: str, provider: str, model: str,
    base_url: str | None, api_key_enc: str | None,
    external_acknowledged: bool,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    profile_id = profile_id or uuid.uuid4().hex[:16]
    with closing(_db()) as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO llm_profiles
                  (id, label, provider, model, base_url, api_key_enc,
                   external_acknowledged, activated_at, probed_at,
                   capabilities_json, probe_steps_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, '{}', '[]', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  label=excluded.label, provider=excluded.provider,
                  model=excluded.model, base_url=excluded.base_url,
                  api_key_enc=excluded.api_key_enc,
                  external_acknowledged=excluded.external_acknowledged,
                  activated_at=NULL, probed_at=NULL,
                  capabilities_json='{}', probe_steps_json='[]',
                  updated_at=excluded.updated_at
                """,
                (
                    profile_id, label, provider, model, base_url, api_key_enc,
                    int(external_acknowledged), now, now,
                ),
            )
    return get_llm_profile(profile_id) or {}


def save_llm_probe(profile_id: str, capabilities: dict, steps: list, *, active: bool) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        with conn:
            conn.execute(
                """
                UPDATE llm_profiles
                SET activated_at=?, probed_at=?, capabilities_json=?,
                    probe_steps_json=?, updated_at=?
                WHERE id=?
                """,
                (
                    now if active else None, now,
                    json.dumps(capabilities, separators=(",", ":")),
                    json.dumps(steps, separators=(",", ":")), now, profile_id,
                ),
            )
    return get_llm_profile(profile_id) or {}


def delete_llm_profile(profile_id: str) -> bool:
    with closing(_db()) as conn:
        with conn:
            cursor = conn.execute("DELETE FROM llm_profiles WHERE id = ?", (profile_id,))
    return cursor.rowcount > 0


def issue_llm_bridge_token(profile_id: str, *, ttl_hours: int = 168) -> str:
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=max(1, min(ttl_hours, 168)))
    with closing(_db()) as conn:
        with conn:
            conn.execute("DELETE FROM llm_bridge_tokens WHERE expires_at <= ?", (now.isoformat(),))
            conn.execute(
                "INSERT INTO llm_bridge_tokens(token_hash, profile_id, expires_at, created_at) "
                "VALUES (?, ?, ?, ?)",
                (digest, profile_id, expires.isoformat(), now.isoformat()),
            )
    return token


def profile_for_llm_bridge_token(token: str) -> str | None:
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        row = conn.execute(
            """
            SELECT t.profile_id
            FROM llm_bridge_tokens t
            JOIN llm_profiles p ON p.id=t.profile_id
            WHERE t.token_hash=? AND t.expires_at>? AND p.activated_at IS NOT NULL
            """,
            (digest, now),
        ).fetchone()
    return str(row[0]) if row else None
