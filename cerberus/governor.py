from __future__ import annotations
import time
import requests
from .config import USER_AGENT
from .scope import ScopeFirewall


class CircuitBreakerOpen(Exception):
    pass


class SafetyGovernor:
    """Rate-limits, budgets, and circuit-breaks all outbound requests.
    Every request is scope-checked before it leaves the box."""

    def __init__(self, scope: ScopeFirewall, rate_per_sec: float = 3.0,
                 budget: int = 500, error_threshold: int = 8):
        self.scope = scope
        self.min_interval = 1.0 / rate_per_sec
        self.budget = budget
        self.error_threshold = error_threshold
        self._last = 0.0
        self._count = 0
        self._recent_errors = 0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

    def get(self, url: str, **kw):
        self.scope.enforce(url)
        if self._count >= self.budget:
            raise CircuitBreakerOpen("Request budget exhausted")
        if self._recent_errors >= self.error_threshold:
            raise CircuitBreakerOpen("Circuit breaker tripped: target may be struggling")
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self._count += 1
        try:
            r = self.session.get(url, timeout=15, allow_redirects=True, **kw)
            if r.status_code >= 500:
                self._recent_errors += 1
            else:
                self._recent_errors = max(0, self._recent_errors - 1)
            return r
        except requests.RequestException:
            self._recent_errors += 1
            raise
