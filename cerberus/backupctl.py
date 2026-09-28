from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, persistence, vault

ARCHIVE_FILES = {"cerberus.db", "manifest.json"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro&immutable=1", uri=True)


def _integrity(path: Path) -> None:
    with _read_only(path) as conn:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {result}")


def _safe_read(archive: Path, destination: Path) -> dict:
    with tarfile.open(archive, "r:gz") as tar:
        names = {member.name for member in tar.getmembers() if member.isfile()}
        if names != ARCHIVE_FILES:
            raise RuntimeError("backup contains unexpected or missing files")
        for name in sorted(ARCHIVE_FILES):
            member = tar.getmember(name)
            if member.size > 2 * 1024 * 1024 * 1024:
                raise RuntimeError("backup member is unreasonably large")
            source = tar.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read {name}")
            with (destination / name).open("wb") as output:
                shutil.copyfileobj(source, output)
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    database = destination / "cerberus.db"
    if manifest.get("database_sha256") != _sha256(database):
        raise RuntimeError("database digest does not match backup manifest")
    _integrity(database)
    if int(manifest.get("schema_version", 0)) > persistence.SCHEMA_VERSION:
        raise RuntimeError("backup schema is newer than this Cerberus release")
    return manifest


def export_archive(output) -> dict:
    source = Path(os.environ.get("CERBERUS_DB_PATH", "/data/cerberus.db"))
    if not source.exists():
        raise RuntimeError("Cerberus database does not exist")
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = Path(raw_tmp)
        database = root / "cerberus.db"
        with sqlite3.connect(source) as live, sqlite3.connect(database) as snapshot:
            live.backup(snapshot)
        _integrity(database)
        with sqlite3.connect(database) as conn:
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            schema = int(row[0] or 0)
        manifest = {
            "format": "cerberus-backup-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "cerberus_version": __version__,
            "schema_version": schema,
            "database_sha256": _sha256(database),
        }
        (root / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            for name in sorted(ARCHIVE_FILES):
                tar.add(root / name, arcname=name, recursive=False)
    return manifest


def verify_archive(path: Path) -> dict:
    with tempfile.TemporaryDirectory() as raw_tmp:
        return _safe_read(path, Path(raw_tmp))


def restore_archive(path: Path, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError("restore destination already exists")
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = Path(raw_tmp)
        manifest = _safe_read(path, root)
        temporary = destination.with_suffix(".restore-pending")
        shutil.copy2(root / "cerberus.db", temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    return manifest


def prove_database(database: Path, key_file: Path) -> dict:
    _integrity(database)
    key = vault.load_master_key(str(key_file))
    checked = 0
    with _read_only(database) as conn:
        conn.row_factory = sqlite3.Row
        version = int(conn.execute(
            "SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0])
        for row in conn.execute(
            "SELECT api_key_enc FROM llm_profiles WHERE api_key_enc IS NOT NULL"):
            vault.open_sealed(key, row["api_key_enc"])
            checked += 1
        users = int(conn.execute("SELECT COUNT(*) FROM local_users").fetchone()[0])
        scans = int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
    return {
        "schema_version": version,
        "users": users,
        "scans": scans,
        "sealed_credentials_verified": checked,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create and verify Cerberus backups")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("export")
    verify = sub.add_parser("verify")
    verify.add_argument("archive", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("archive", type=Path)
    restore.add_argument("destination", type=Path)
    prove = sub.add_parser("prove")
    prove.add_argument("database", type=Path)
    prove.add_argument("key_file", type=Path)
    args = parser.parse_args()

    if args.command == "export":
        export_archive(sys.stdout.buffer)
    elif args.command == "verify":
        print(json.dumps(verify_archive(args.archive), sort_keys=True))
    elif args.command == "restore":
        print(json.dumps(restore_archive(args.archive, args.destination), sort_keys=True))
    elif args.command == "prove":
        print(json.dumps(prove_database(args.database, args.key_file), sort_keys=True))


if __name__ == "__main__":
    main()
