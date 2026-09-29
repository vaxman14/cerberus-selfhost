"""Installation-key credential vault, adapted from Josi CE's vault contract."""
from __future__ import annotations

import base64
import json
import os
import re
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_MASTER_KEY_PATH = "/run/secrets/cerberus_master_key"
SEALED_VERSION = "v1"


class VaultError(RuntimeError):
    pass


class MasterKey:
    """A redacting wrapper whose bytes require an explicit reveal()."""

    __slots__ = ("__bytes",)

    def __init__(self, value: bytes):
        if len(value) != 32:
            raise VaultError(f"master key must be 32 bytes, got {len(value)}")
        self.__bytes = value

    def reveal(self) -> bytes:
        return self.__bytes

    def __repr__(self) -> str:
        return "[master key redacted]"

    __str__ = __repr__


def parse_master_key(raw: str) -> bytes:
    value = raw.strip()
    if not value:
        raise VaultError("master key file is empty")
    try:
        decoded = bytes.fromhex(value) if re.fullmatch(r"[0-9a-fA-F]{64}", value) else base64.b64decode(
            value, validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise VaultError("master key must be 32 bytes encoded as base64 or hex") from exc
    if len(decoded) != 32:
        raise VaultError(
            "master key must decode to 32 bytes; generate one with: openssl rand -base64 32"
        )
    return decoded


def load_master_key(path: str | None = None, *, strict_permissions: bool = True) -> MasterKey:
    if os.environ.get("CERBERUS_MASTER_KEY") or os.environ.get("CREDENTIALS_KEY"):
        raise VaultError(
            "the master key must be mounted as a file, never supplied in an environment variable"
        )
    key_path = Path(path or os.environ.get("CERBERUS_MASTER_KEY_FILE", DEFAULT_MASTER_KEY_PATH))
    try:
        raw = key_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise VaultError(f"no master key at {key_path}; create and mount the Docker secret") from exc
    # POSIX mode bits do not represent Windows ACLs. The desktop launcher creates
    # this file below the current user's LocalAppData directory and applies a
    # current-user-only ACL before starting the backend.
    if strict_permissions and os.name != "nt" and not str(key_path).startswith("/run/secrets/"):
        mode = stat.S_IMODE(key_path.stat().st_mode)
        if mode & 0o077:
            raise VaultError(f"master key at {key_path} is readable by other users; chmod 600 it")
    return MasterKey(parse_master_key(raw))


def master_key_available() -> bool:
    try:
        load_master_key()
        return True
    except VaultError:
        return False


def seal(key: MasterKey, payload: dict) -> str:
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    encrypted = AESGCM(key.reveal()).encrypt(nonce, plaintext, SEALED_VERSION.encode())
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    encode = lambda value: base64.b64encode(value).decode("ascii")
    return ".".join((SEALED_VERSION, encode(nonce), encode(tag), encode(ciphertext)))


def open_sealed(key: MasterKey, value: str) -> dict:
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != SEALED_VERSION:
        raise VaultError("unrecognised sealed value")
    try:
        nonce, tag, ciphertext = (base64.b64decode(part, validate=True) for part in parts[1:])
        plaintext = AESGCM(key.reveal()).decrypt(
            nonce, ciphertext + tag, SEALED_VERSION.encode()
        )
        payload = json.loads(plaintext)
    except Exception as exc:  # wrong key and tampering intentionally look identical
        raise VaultError("could not open sealed value") from exc
    if not isinstance(payload, dict):
        raise VaultError("could not open sealed value")
    return payload


def looks_sealed(value: object) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+", value)
    )
