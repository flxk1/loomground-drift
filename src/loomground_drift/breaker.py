# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Leases, tripwires and the breaker verdict.

Stopping is the default state; running is what needs a live lease. A lease
lapses on its own: with no renewal the effective grade reads as the floor of
the grade lattice the next time anyone asks. A tripwire trips without a human
in the loop and sends the agent to QUARANTINED, which only a named human clears.

The grade lattice is read from ``loomground_governance.vocabulary("grades")``;
the refusal word a quarantine maps onto is read from ``vocabulary("verdicts")``.
Deterministic: every time-dependent call takes ``now=``.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from loomground_audit_chain.witness_escape import recent_witness_escapes as _recent_witness_escapes
from loomground_governance import vocabulary as _vocabulary

__all__ = [
    "BreakerState", "Lease", "RenewResult", "Tripwire", "default_tripwires",
    "BreakerStatus", "Breaker", "cap_grade", "grade_levels", "floor_grade",
    "WITNESS_ESCAPE_METRIC", "witness_escape_tripwire", "witness_escape_metrics",
    "ensure_witness_escape_armed", "status_after_witness_escape_check",
]


def grade_levels() -> tuple[str, ...]:
    return tuple(_vocabulary("grades")["levels"])


_GRADES = grade_levels()
_GRADE_IDX = {g: i for i, g in enumerate(_GRADES)}


def floor_grade() -> str:
    return _GRADES[0]


def _verdict_word(word: str) -> str:
    alphabet = _vocabulary("verdicts")["alphabet"]
    if word not in alphabet:
        raise LookupError(f"verdict {word!r} absent from the governance alphabet {alphabet!r}")
    return word


#: The verdict a gate returns for a QUARANTINED agent.
REFUSED_VERDICT = _verdict_word("refused")

#: Injectable clock; ``now=`` on any call wins over it.
clock: Callable[[], float] = time.time


def _clock() -> float:
    return clock()


class BreakerState(str, Enum):
    RUNNING = "RUNNING"
    DECAYED = "DECAYED"
    QUARANTINED = "QUARANTINED"


@dataclass
class Lease:
    """A time-boxed grant of autonomy: ``granted_grade`` while live, the floor once
    ``expires_at`` has passed, until a renewal moves ``expires_at`` forward."""
    agent: str
    granted_grade: str
    expires_at: float
    ttl_seconds: float = 60.0
    granted_at: float = field(default_factory=_clock)

    def __post_init__(self) -> None:
        if self.granted_grade not in _GRADE_IDX:
            raise ValueError(f"unknown grade: {self.granted_grade!r}")
        if self.ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be > 0: {self.ttl_seconds!r}")

    def live(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else _clock()) < self.expires_at

    def effective_grade(self, now: Optional[float] = None) -> str:
        return self.granted_grade if self.live(now) else floor_grade()

    def renew(self, *, ok: bool, reason: str = "",
              now: Optional[float] = None,
              ttl_seconds: Optional[float] = None) -> "RenewResult":
        """Conditional renewal: ``ok=False`` keeps the old expiry and lets the lease lapse."""
        now = now if now is not None else _clock()
        if not ok:
            return RenewResult(False, self.effective_grade(now),
                               f"renewal refused: {reason or 'green checks failed'}")
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        self.expires_at = now + ttl
        self.ttl_seconds = ttl
        return RenewResult(True, self.granted_grade, f"renewed for {ttl}s")


@dataclass
class RenewResult:
    renewed: bool
    effective_grade: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Tripwire:
    """``metric`` names the observable, ``limit`` the threshold, ``kind`` the
    comparison: ``"max"`` | ``"min"`` | ``"flag"``. An unmeasured metric (``None``)
    is a gap, never a trip."""
    name: str
    metric: str
    limit: float
    kind: str = "max"

    def trips(self, value: Optional[float | bool]) -> bool:
        if value is None:
            return False
        if self.kind == "flag":
            return bool(value)
        if self.kind == "min":
            return float(value) < self.limit
        return float(value) > self.limit

    def evaluate(self, value: Optional[float | bool]) -> Optional[str]:
        if self.trips(value):
            return (f"tripwire {self.name!r}: {self.metric}={value} "
                    f"{'is set' if self.kind == 'flag' else self.kind + ' ' + str(self.limit)}")
        return None


def default_tripwires() -> list[Tripwire]:
    return [
        Tripwire("budget", "usd_spent_iteration", 0.0, "max"),
        Tripwire("error_rate", "error_rate", 0.25, "max"),
        Tripwire("attestation", "attestation_failed", 0.0, "flag"),
        Tripwire("chain_integrity", "chain_invalid", 0.0, "flag"),
    ]


@dataclass
class BreakerStatus:
    agent: str
    state: BreakerState
    effective_grade: str
    reasons: list[str] = field(default_factory=list)
    tripped: list[str] = field(default_factory=list)
    #: ``REFUSED_VERDICT`` when QUARANTINED; ``""`` otherwise (the gate decides
    #: from ``effective_grade``).
    verdict: str = ""

    @property
    def running(self) -> bool:
        return self.state is BreakerState.RUNNING

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d


class Breaker:
    """One lease plus tripwires, one verdict per agent. A trip is sticky on the
    instance until :meth:`clear`; a renewal alone cannot lift it."""

    def __init__(self, lease: Lease,
                 tripwires: Optional[Iterable[Tripwire]] = None) -> None:
        self.lease = lease
        self.tripwires = list(tripwires if tripwires is not None else default_tripwires())
        self._quarantined_reason: Optional[str] = None

    def trip_check(self, metrics: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for tw in self.tripwires:
            msg = tw.evaluate(metrics.get(tw.metric))
            if msg:
                out.append(msg)
        return out

    def status(self, *, metrics: Optional[dict[str, Any]] = None,
               now: Optional[float] = None) -> BreakerStatus:
        metrics = metrics or {}
        tripped = self.trip_check(metrics)
        if self._quarantined_reason:
            tripped = [self._quarantined_reason] + tripped
        if tripped:
            self._quarantined_reason = tripped[0]
            return BreakerStatus(
                self.lease.agent, BreakerState.QUARANTINED, floor_grade(),
                reasons=["quarantined — frozen until a human clears"],
                tripped=tripped, verdict=REFUSED_VERDICT)
        if not self.lease.live(now):
            return BreakerStatus(
                self.lease.agent, BreakerState.DECAYED, floor_grade(),
                reasons=[f"lease lapsed — autonomy decayed to {floor_grade()}; renew to restore"])
        return BreakerStatus(
            self.lease.agent, BreakerState.RUNNING, self.lease.effective_grade(now),
            reasons=[f"lease live; grade {self.lease.granted_grade}"])

    def renew(self, *, ok: bool, reason: str = "",
              now: Optional[float] = None,
              ttl_seconds: Optional[float] = None) -> RenewResult:
        if self._quarantined_reason:
            return RenewResult(False, floor_grade(),
                               "agent is quarantined — renewal cannot lift a "
                               "tripped breaker; a human must clear it")
        return self.lease.renew(ok=ok, reason=reason, now=now, ttl_seconds=ttl_seconds)

    def clear(self, *, by: str, rationale: str) -> dict[str, Any]:
        """A named human clears the quarantine with a rationale; the lease is left as is."""
        if not (by or "").strip():
            return {"error": "a human actor must be named to clear a quarantine"}
        if not (rationale or "").strip():
            return {"error": "clearing a quarantine requires a rationale"}
        prev = self._quarantined_reason
        self._quarantined_reason = None
        return {"cleared": True, "by": by.strip(),
                "rationale": rationale.strip(), "previous_reason": prev}

    def effective_grade(self, *, metrics: Optional[dict[str, Any]] = None,
                        now: Optional[float] = None) -> str:
        return self.status(metrics=metrics, now=now).effective_grade


def cap_grade(requested: str, ceiling: str) -> str:
    """Lattice meet of a requested grade with a ceiling. An empty ceiling leaves
    the request; an unknown token on either side reads as the floor."""
    ri = _GRADE_IDX.get(requested, 0)
    if not ceiling:
        return _GRADES[ri]
    ci = _GRADE_IDX.get(ceiling, 0)
    return _GRADES[min(ri, ci)]


# Witness escape as a tripwire input: the audit chain records the escape, this
# reads it back as one more flag metric for the same ``Breaker.status`` path.

WITNESS_ESCAPE_METRIC = "witness_escape_detected"


def witness_escape_tripwire(name: str = "witness_escape") -> Tripwire:
    return Tripwire(name, WITNESS_ESCAPE_METRIC, 0.0, "flag")


def witness_escape_metrics(
    folder_context: str | Path, actor: str, *,
    since: Optional[float] = None,
    log_root: str | Path | None = None,
) -> dict[str, Any]:
    """``True`` iff a witness-escape event for this actor is on this folder's
    chain at or after ``since`` (``None`` = any time)."""
    hits = _recent_witness_escapes(folder_context, actor, since=since, log_root=log_root)
    return {WITNESS_ESCAPE_METRIC: bool(hits)}


def ensure_witness_escape_armed(breaker: Breaker) -> Breaker:
    if any(t.metric == WITNESS_ESCAPE_METRIC for t in breaker.tripwires):
        return breaker
    breaker.tripwires.append(witness_escape_tripwire())
    return breaker


def status_after_witness_escape_check(
    breaker: Breaker,
    folder_context: str | Path,
    actor: str,
    *,
    since: Optional[float] = None,
    log_root: str | Path | None = None,
    extra_metrics: Optional[dict[str, Any]] = None,
    now: Optional[float] = None,
) -> BreakerStatus:
    """Arm the witness-escape tripwire and evaluate ``breaker.status`` with the
    recorded-escape metric folded in; ``since`` defaults to the lease's ``granted_at``."""
    ensure_witness_escape_armed(breaker)
    window_since = since if since is not None else breaker.lease.granted_at
    metrics = dict(extra_metrics or {})
    metrics.update(witness_escape_metrics(folder_context, actor, since=window_since, log_root=log_root))
    return breaker.status(metrics=metrics, now=now)
