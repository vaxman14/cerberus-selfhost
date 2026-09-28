from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class RiskBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class RiskSignal:
    """A privacy-bounded signal. Evidence must never contain raw identifiers."""

    name: str
    weight: int
    evidence: str = ""


@dataclass(frozen=True)
class Decision:
    score: int
    band: RiskBand
    action: str
    reasons: tuple[str, ...] = field(default_factory=tuple)


class TrialRiskEngine:
    """Conservative, deterministic policy shared by Cerberus-generated gates.

    IP addresses are deliberately capped as weak evidence. A high-risk denial
    requires at least two independent signals, preventing one shared network
    from blocking a household, office, school, hotel, or university.
    """

    MEDIUM_SCORE = 35
    HIGH_SCORE = 70

    def decide(self, signals: Iterable[RiskSignal]) -> Decision:
        items = list(signals)
        normalized: list[RiskSignal] = []
        for signal in items:
            weight = max(0, min(100, signal.weight))
            if signal.name in {"ip_reuse", "ip_velocity"}:
                weight = min(weight, 15)
            normalized.append(RiskSignal(signal.name, weight, signal.evidence))

        score = min(100, sum(s.weight for s in normalized))
        independent = {s.name for s in normalized if s.weight > 0}
        reasons = tuple(s.name for s in normalized if s.weight > 0)

        if score >= self.HIGH_SCORE and len(independent) >= 2:
            return Decision(score, RiskBand.HIGH, "deny_trial_allow_purchase", reasons)
        if score >= self.MEDIUM_SCORE:
            return Decision(score, RiskBand.MEDIUM, "step_up_verification", reasons)
        return Decision(score, RiskBand.LOW, "allow_trial", reasons)
