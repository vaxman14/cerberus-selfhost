from __future__ import annotations
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


class ScopeFirewall:
    """Blocks any request whose host is not on the authorized allowlist.
    Built once in Phase 0, enforced on every outbound request by the governor."""

    def __init__(self, allowed_hosts: list[str]):
        self.allowed = {self._norm(h) for h in allowed_hosts if h}

    @staticmethod
    def _norm(host: str) -> str:
        host = (host or "").lower().strip()
        return host[4:] if host.startswith("www.") else host

    def _host(self, url: str) -> str:
        return self._norm(urlparse(url).hostname or "")

    def in_scope(self, url: str) -> bool:
        return self._host(url) in self.allowed

    def enforce(self, url: str) -> None:
        if not self.in_scope(url):
            raise ScopeError(f"Out of scope, blocked: {url}")
