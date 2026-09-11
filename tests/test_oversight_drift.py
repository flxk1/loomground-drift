# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""DriftReport → DriftSignal with the oversight ladder injected."""

from __future__ import annotations

import functools

import pytest

from loomground_drift.breaker import Breaker, BreakerState, Lease, grade_levels
from loomground_drift.drift_monitor import DriftReport
from loomground_drift.oversight_drift import (
    DRIFT_STRUCTURAL_METRIC, drift_tripwire, evaluate, raise_floor)

LADDER = ("NOTIFY", "REVIEW", "APPROVE")
G = grade_levels()
ev = functools.partial(evaluate, levels=LADDER, behavioural_floor="REVIEW")


def _report(**kw) -> DriftReport:
    base = dict(folder="/x", as_of=0.0)
    base.update(kw)
    return DriftReport(**base)


def test_no_baseline_asks_for_rebaseline_never_trips():
    sig = ev(_report(no_baseline=True))
    assert sig.needs_rebaseline is True
    assert sig.structural is False
    assert sig.recommend_floor == ""


def test_thin_window_asks_for_rebaseline_never_trips():
    sig = ev(_report(too_thin=True, window_n=3))
    assert sig.needs_rebaseline is True and sig.structural is False
    assert "3 events" in sig.reason


def test_structural_unmeasured_asks_for_rebaseline_never_trips():
    sig = ev(_report(structural_unmeasured=True))
    assert sig.needs_rebaseline is True and sig.structural is False
    assert sig.metrics == {}
    assert drift_tripwire().trips(sig.metrics.get(DRIFT_STRUCTURAL_METRIC)) is False


def test_structural_drift_arms_the_breaker():
    sig = ev(_report(structural=[{"change": "tool added"}]))
    assert sig.structural is True
    assert sig.metrics == {DRIFT_STRUCTURAL_METRIC: True}
    assert "quarantine" in sig.reason and "stale" in sig.reason
    assert drift_tripwire().trips(sig.metrics[DRIFT_STRUCTURAL_METRIC]) is True


def test_behavioural_drift_raises_floor_not_freeze():
    sig = ev(_report(behavioural=[{"shift": 0.4}]))
    assert sig.structural is False
    assert sig.recommend_floor == "REVIEW"
    assert sig.metrics[DRIFT_STRUCTURAL_METRIC] is False


def test_behavioural_floor_is_the_callers():
    sig = evaluate(_report(behavioural=[{"shift": 0.4}]), levels=LADDER, behavioural_floor="APPROVE")
    assert sig.recommend_floor == "APPROVE"


def test_structural_beats_behavioural():
    sig = ev(_report(structural=[{"c": 1}], behavioural=[{"s": 1}]))
    assert sig.structural is True and sig.recommend_floor == ""


def test_clean_report_no_drift():
    sig = ev(_report())
    assert sig.structural is False and sig.recommend_floor == ""
    assert sig.reason == "no drift"
    assert sig.to_dict()["needs_rebaseline"] is False


def test_drift_tripwire_does_not_trip_on_false():
    assert drift_tripwire().trips(False) is False


def test_levels_is_required_and_floor_must_be_on_the_ladder():
    with pytest.raises(TypeError):
        evaluate(_report())  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        evaluate(_report(), levels=LADDER, behavioural_floor="PANIC")
    with pytest.raises(ValueError):
        evaluate(_report(), levels=(), behavioural_floor="REVIEW")
    with pytest.raises(ValueError):
        evaluate(_report(), levels=("A", "A"), behavioural_floor="A")


# ── raise_floor: stricter (later on the ladder) wins ─────────────────────────

def test_raise_floor_takes_the_stricter():
    assert raise_floor("NOTIFY", "REVIEW", levels=LADDER) == "REVIEW"
    assert raise_floor("APPROVE", "REVIEW", levels=LADDER) == "APPROVE"
    assert raise_floor("", "REVIEW", levels=LADDER) == "REVIEW"
    assert raise_floor("APPROVE", "", levels=LADDER) == "APPROVE"


def test_raise_floor_orders_an_injected_three_level_ladder():
    ladder = ("low", "mid", "high")
    assert raise_floor("low", "mid", levels=ladder) == "mid"
    assert raise_floor("mid", "low", levels=ladder) == "mid"
    assert raise_floor("high", "mid", levels=ladder) == "high"
    assert raise_floor("low", "high", levels=ladder) == "high"
    reversed_ladder = ("high", "mid", "low")
    assert raise_floor("low", "mid", levels=reversed_ladder) == "low"


def test_raise_floor_rejects_names_off_the_ladder():
    with pytest.raises(ValueError):
        raise_floor("NOTIFY", "PANIC", levels=LADDER)
    with pytest.raises(ValueError):
        raise_floor("PANIC", "REVIEW", levels=LADDER)


# ── the wire: signal metrics → breaker tripwire → quarantine ──────────────────

def test_structural_signal_quarantines_breaker():
    b = Breaker(Lease("bot", G[3], expires_at=1000.0), tripwires=[drift_tripwire()])
    sig = ev(_report(structural=[{"metric": "policy"}]))
    s = b.status(metrics=sig.metrics, now=990.0)
    assert s.state is BreakerState.QUARANTINED
    assert s.effective_grade == G[0]


def test_clean_drift_does_not_quarantine():
    b = Breaker(Lease("bot", G[3], expires_at=1000.0), tripwires=[drift_tripwire()])
    s = b.status(metrics=ev(_report()).metrics, now=990.0)
    assert s.state is BreakerState.RUNNING


def test_gap_signal_does_not_quarantine():
    b = Breaker(Lease("bot", G[3], expires_at=1000.0), tripwires=[drift_tripwire()])
    s = b.status(metrics=ev(_report(structural_unmeasured=True)).metrics, now=990.0)
    assert s.state is BreakerState.RUNNING
