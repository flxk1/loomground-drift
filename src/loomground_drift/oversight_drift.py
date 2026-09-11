# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Drift report → breaker metrics and an oversight floor.

Structural drift arms the breaker (``drift_structural`` flag → QUARANTINED
until re-baselined). Behavioural drift raises the recommended oversight floor
instead of freezing. ``no_baseline``, ``too_thin`` and ``structural_unmeasured``
are gaps: they ask for a re-baseline and never trip.

The oversight ladder is the host's: ``levels`` (ascending strictness) is a
required parameter; this module names no level.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from .breaker import Tripwire
from .drift_monitor import DriftReport

__all__ = ["DriftSignal", "drift_tripwire", "evaluate", "raise_floor"]

DRIFT_STRUCTURAL_METRIC = "drift_structural"


@dataclass
class DriftSignal:
    structural: bool = False
    recommend_floor: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    needs_rebaseline: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"structural": self.structural,
                "recommend_floor": self.recommend_floor,
                "metrics": self.metrics, "findings": self.findings,
                "needs_rebaseline": self.needs_rebaseline, "reason": self.reason}


def drift_tripwire() -> Tripwire:
    return Tripwire("drift", DRIFT_STRUCTURAL_METRIC, 0.0, "flag")


def _level_order(levels: Sequence[str]) -> dict[str, int]:
    if not levels:
        raise ValueError("levels must name at least one oversight level")
    order = {lvl: i for i, lvl in enumerate(levels)}
    if len(order) != len(levels):
        raise ValueError(f"levels must be distinct: {tuple(levels)!r}")
    return order


def _check_level(name: str, order: dict[str, int], what: str) -> None:
    if name not in order:
        raise ValueError(f"{what} {name!r} is outside the ladder {tuple(order)!r}")


def evaluate(report: DriftReport, *, levels: Sequence[str],
             behavioural_floor: str) -> DriftSignal:
    """``behavioural_floor`` is the floor recommended on behavioural drift alone;
    it must be a member of ``levels``."""
    order = _level_order(levels)
    _check_level(behavioural_floor, order, "behavioural_floor")
    if report.no_baseline:
        return DriftSignal(needs_rebaseline=True,
                           reason="no baseline — establish one before judging drift")
    if report.structural_unmeasured:
        return DriftSignal(needs_rebaseline=True,
                           reason="structural state unmeasured on one side — gap, "
                                  "not breach; re-baseline with the structural port bound")
    if report.too_thin:
        return DriftSignal(needs_rebaseline=True,
                           reason=f"window too thin ({report.window_n} events) "
                                  "— gap, not breach; re-baseline or wait")

    structural = bool(report.structural)
    behavioural = bool(report.behavioural)
    sig = DriftSignal(structural=structural,
                      metrics={DRIFT_STRUCTURAL_METRIC: structural},
                      findings=report.findings)
    if structural:
        sig.reason = (f"structural drift ({len(report.structural)} change(s)) — "
                      "regulator model stale; breaker armed for quarantine")
    elif behavioural:
        sig.recommend_floor = behavioural_floor
        sig.reason = (f"behavioural drift ({len(report.behavioural)} share-shift(s)) "
                      f"— oversight floor raised to {behavioural_floor}")
    else:
        sig.reason = "no drift"
    return sig


def raise_floor(current: str, recommended: str, *, levels: Sequence[str]) -> str:
    """Join of two floors on ``levels``: the stricter (later) wins; ``""`` is absent."""
    order = _level_order(levels)
    if not recommended:
        return current
    if not current:
        _check_level(recommended, order, "recommended")
        return recommended
    _check_level(current, order, "current")
    _check_level(recommended, order, "recommended")
    return recommended if order[recommended] > order[current] else current
