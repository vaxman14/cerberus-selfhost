from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from http.cookies import SimpleCookie
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import persistence


COOKIE_NAME = "cerberus_session"
CSRF_COOKIE_NAME = "cerberus_csrf"
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
PASSWORD_HASHER = PasswordHasher()
DUMMY_HASH = PASSWORD_HASHER.hash("cerberus-invalid-login-placeholder")


class LocalAuthError(RuntimeError):
    def __init__(self, message: str, *, status: int = 400):
        super().__init__(message)
        self.status = status


def setup_required() -> bool:
    return persistence.local_user_count() == 0


def _validate_username(value: str) -> str:
    username = value.strip()
    if not USERNAME.fullmatch(username):
        raise LocalAuthError(
            "username must be 3-64 characters using letters, numbers, dot, dash, or underscore"
        )
    return username


def _validate_password(value: str) -> str:
    if len(value) < 12:
        raise LocalAuthError("password must be at least 12 characters")
    if len(value) > 1024:
        raise LocalAuthError("password is too long")
    return value


def create_owner(username: str, password: str) -> dict:
    if not setup_required():
        raise LocalAuthError("owner setup is already complete", status=409)
    username = _validate_username(username)
    password_hash = PASSWORD_HASHER.hash(_validate_password(password))
    try:
        return persistence.create_local_user(username, password_hash, role="owner")
    except sqlite3.IntegrityError as exc:
        raise LocalAuthError("that username already exists", status=409) from exc


def reset_password(username: str, password: str) -> None:
    username = _validate_username(username)
    password_hash = PASSWORD_HASHER.hash(_validate_password(password))
    if not persistence.reset_local_user_password(username, password_hash):
        raise LocalAuthError("no such local user", status=404)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def login(username: str, password: str) -> tuple[dict, str, str]:
    user = persistence.get_local_user_by_username(username.strip())
    encoded = user.get("password_hash", "") if user else DUMMY_HASH
    try:
        valid = PASSWORD_HASHER.verify(encoded, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        valid = False
    if not user or not valid:
        raise LocalAuthError("invalid username or password", status=401)
    if PASSWORD_HASHER.check_needs_rehash(user["password_hash"]):
        # Rehashing is intentionally deferred until a dedicated password-update
        # transaction exists; authentication never silently risks a partial write.
        pass
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    persistence.create_local_session(user["id"], _digest(token), _digest(csrf))
    return ({"id": user["id"], "username": user["username"], "role": user["role"]},
            token, csrf)


def _cookie_value(cookie_header: str, name: str) -> str:
    try:
        cookies = SimpleCookie()
        cookies.load(cookie_header or "")
        return cookies[name].value if name in cookies else ""
    except Exception:
        return ""


def authenticate(cookie_header: str) -> tuple[dict | None, str]:
    token = _cookie_value(cookie_header, COOKIE_NAME)
    if not token:
        return None, ""
    session = persistence.get_local_session(_digest(token))
    if not session:
        return None, ""
    return ({"id": session["id"], "username": session["username"],
             "role": session["role"], "csrf_hash": session["csrf_hash"]}, token)


def csrf_valid(user: dict, supplied: str) -> bool:
    return bool(supplied) and hmac.compare_digest(
        str(user.get("csrf_hash", "")), _digest(supplied)
    )


def logout(cookie_header: str) -> None:
    token = _cookie_value(cookie_header, COOKIE_NAME)
    if token:
        persistence.delete_local_session(_digest(token))


def cookie_header(token: str, *, secure: bool = False) -> str:
    parts = [f"{COOKIE_NAME}={token}", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=86400"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def csrf_cookie(cookie_header: str) -> str:
    return _cookie_value(cookie_header, CSRF_COOKIE_NAME)


def csrf_cookie_header(token: str, *, secure: bool = False) -> str:
    parts = [f"{CSRF_COOKIE_NAME}={token}", "Path=/", "SameSite=Strict", "Max-Age=86400"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_cookie_header(*, secure: bool = False) -> str:
    parts = [f"{COOKIE_NAME}=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_csrf_cookie_header(*, secure: bool = False) -> str:
    parts = [f"{CSRF_COOKIE_NAME}=", "Path=/", "SameSite=Strict", "Max-Age=0"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def bootstrap_owner_from_env() -> bool:
    if not setup_required():
        return False
    username = os.environ.get("CERBERUS_BOOTSTRAP_USERNAME", "").strip()
    password_file = os.environ.get("CERBERUS_BOOTSTRAP_PASSWORD_FILE", "").strip()
    if not username and not password_file:
        return False
    if not username or not password_file:
        raise LocalAuthError(
            "both CERBERUS_BOOTSTRAP_USERNAME and CERBERUS_BOOTSTRAP_PASSWORD_FILE are required"
        )
    path = Path(password_file)
    try:
        password = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise LocalAuthError("owner bootstrap password file is unavailable") from exc
    create_owner(username, password)
    return True
