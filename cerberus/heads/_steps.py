from __future__ import annotations
import os
import time

# Deliberate per-check delay so the live console reads like a real scan in
# progress (theater for the client demo). Tunable via env; 0 disables.
_DELAY = float(os.environ.get("CERBERUS_STEP_DELAY", "0.18"))
_WIDTH = 46


def _fmt(name: str, status: str) -> str:
    name = name[: _WIDTH - 6]
    dots = "." * max(3, _WIDTH - len(name))
    return f"   {name} {dots} {status}"


def _status(new) -> str:
    if not new:
        return "PASS"
    worst = max(f.severity.rank for f in new)
    if worst >= 3:      # high / critical
        return "FAIL"
    if worst >= 1:      # low / medium
        return "WARN"
    return "note"       # info


def step(log, out, name: str, fn) -> None:
    """Run check fn() (which appends Findings to `out`), then log one result
    line reflecting what it found: PASS clean, WARN low/med, FAIL high/crit."""
    before = len(out)
    try:
        fn()
        st = _status(out[before:])
    except Exception:
        st = "skip"
    if _DELAY:
        time.sleep(_DELAY)
    log(_fmt(name, st))


def say(log, msg: str) -> None:
    """A narration line (no PASS/FAIL), used to announce a phase."""
    if _DELAY:
        time.sleep(_DELAY)
    log("   " + msg)
