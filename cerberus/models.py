from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Head(str, Enum):
    FRONTEND = "frontend"
    BACKEND = "backend"
    SPEED = "speed"
    NOSE = "nose"
    REVENUE = "revenue"


@dataclass
class Finding:
    head: Head
    title: str
    severity: Severity
    detail: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["head"] = self.head.value
        d["severity"] = self.severity.value
        return d


@dataclass
class AuthRecord:
    client: str
    scope_hosts: list[str]
    # Head 2 (active) requires a signed authorization reference; passive heads do not.
    signed_authorization_ref: str | None = None
    allow_production_active: bool = False
    # owner/admin override: the single authorized operator may run active heads.
    admin_override: bool = False


@dataclass
class ScanResult:
    target: str
    client: str
    findings: list[Finding] = field(default_factory=list)
    heads_run: list[str] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)

    def worst(self) -> Severity:
        return max((f.severity for f in self.findings),
                   key=lambda s: s.rank, default=Severity.INFO)
