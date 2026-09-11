# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Baseline, deterministic tick, findings, surface — with the structural
inputs injected through the ``structural_state`` port or ``structural=``."""

import time

import pytest
from loomground_audit_chain.mutation_log import LogEvent, MutationLog

from loomground_drift import drift_monitor as dm
from loomground_drift.drift_monitor import DriftReport, DriftThresholds

THIN = DriftThresholds(share_shift=0.15, min_events=5)
STRUCT_A = {"policy:oversight_default_level": "review", "policy:lock_is_active": True,
            "pinned_skills": ["nd-a", "nd-x"]}


@pytest.fixture
def structural_port(monkeypatch):
    """Bind the host port to a mutable dict so tests change 'configuration'."""
    state = dict(STRUCT_A)
    monkeypatch.setattr(dm, "structural_state", lambda folder: dict(state))
    return state


def _seed(folder, log_root, *, n_user=10, n_agent=0, skill="nd-x"):
    log = MutationLog(folder, log_root=log_root)
    for i in range(n_user):
        log.append(LogEvent(event="ingest", folder_path=str(folder),
                            pair_id=f"p{i}", channel="document", actor="user"))
    for i in range(n_agent):
        log.append(LogEvent(event="system", folder_path=str(folder),
                            pair_id="workflow-event", channel="system",
                            actor=f"agent:{skill}",
                            extra={"kind": "workflow-event", "skill_id": skill,
                                   "state": "done", "run_id": "r", "workflow": "w",
                                   "step_index": i}))
    return log


# ── baseline ──────────────────────────────────────────────────────────────────

def test_baseline_writes_signed_event_and_state(folder, log_root, structural_port):
    _seed(folder, log_root)
    rec = dm.baseline(folder, log_root=log_root, catalogue_fingerprint="cat-1")
    assert rec["audit_id"]
    st = rec["state"]
    assert st["catalogue_fingerprint"] == "cat-1"
    assert st["behaviour"]["n"] == 10
    assert st["structural"] == STRUCT_A
    assert MutationLog(folder, log_root=log_root).verify_chain().ok


def test_explicit_structural_overrides_port(folder, log_root, structural_port):
    rec = dm.baseline(folder, log_root=log_root, structural={"k": 1})
    assert rec["state"]["structural"] == {"k": 1}


def test_tick_without_baseline_says_so(folder, log_root, structural_port):
    _seed(folder, log_root)
    rep = dm.drift_tick(folder, log_root=log_root)
    assert rep.no_baseline and rep.needs_rebaseline and not rep.ok


# ── no structural port: honest gap, never a guessed empty baseline ────────────

def test_absent_port_baseline_records_structural_none(folder, log_root):
    assert dm.structural_state is None
    rec = dm.baseline(folder, log_root=log_root)
    assert rec["state"]["structural"] is None


def test_absent_port_tick_is_unmeasured_and_fires_no_finding(folder, log_root):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root, catalogue_fingerprint="a")
    _seed(folder, log_root, n_user=0, n_agent=20)
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, catalogue_fingerprint="b")
    assert rep.structural_unmeasured is True
    assert rep.needs_rebaseline is True
    assert rep.findings == []
    assert rep.ok is False
    assert rep.window_n == 20
    assert rep.to_dict()["structural_unmeasured"] is True


def test_baseline_without_port_then_tick_with_port_is_unmeasured(folder, log_root, monkeypatch):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    monkeypatch.setattr(dm, "structural_state", lambda folder: dict(STRUCT_A))
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    assert rep.structural_unmeasured and not rep.findings


def test_baseline_with_port_then_tick_without_port_is_unmeasured(folder, log_root, structural_port, monkeypatch):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    monkeypatch.setattr(dm, "structural_state", None)
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    assert rep.structural_unmeasured and not rep.findings
    rep2 = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, structural=STRUCT_A)
    assert not rep2.structural_unmeasured


# ── determinism ───────────────────────────────────────────────────────────────

def test_tick_is_deterministic(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    _seed(folder, log_root, n_user=2, n_agent=6)
    as_of = time.time() + 1
    r1 = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, as_of=as_of)
    r2 = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, as_of=as_of)
    assert r1.to_dict() == r2.to_dict()


def test_no_change_is_ok(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    _seed(folder, log_root, n_user=10)
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    assert rep.ok and not rep.findings and not rep.too_thin and not rep.needs_rebaseline


def test_thin_window_is_surfaced_not_compared(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    _seed(folder, log_root, n_user=2)
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=DriftThresholds(min_events=20))
    assert rep.too_thin and rep.needs_rebaseline and not rep.findings


def test_as_of_bounds_the_window(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, as_of=0.0)
    assert rep.window_n == 0 and rep.too_thin


# ── structural drift ──────────────────────────────────────────────────────────

def test_scalar_structural_change_is_finding(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    structural_port["policy:oversight_default_level"] = "autonomous"
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    f = [f for f in rep.structural if f["metric"] == "policy:oversight_default_level"]
    assert f == [{"metric": "policy:oversight_default_level", "baseline": "review", "current": "autonomous"}]
    assert not rep.ok


def test_set_like_structural_change_reports_added_removed(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    structural_port["pinned_skills"] = ["nd-a", "nd-new"]
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    pin = [f for f in rep.structural if f["metric"] == "pinned_skills"]
    assert pin == [{"metric": "pinned_skills", "added": ["nd-new"], "removed": ["nd-x"]}]


def test_new_and_dropped_structural_keys_are_findings(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    del structural_port["policy:lock_is_active"]
    structural_port["policy:new_flag"] = 1
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    assert {f["metric"] for f in rep.structural} == {"policy:lock_is_active", "policy:new_flag"}


def test_catalogue_fingerprint_change_is_structural_finding(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root, catalogue_fingerprint="cat-1")
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, catalogue_fingerprint="cat-2")
    assert any(f["metric"] == "catalogue_fingerprint" for f in rep.structural)


def test_structural_finding_survives_thin_window(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root, catalogue_fingerprint="a")
    rep = dm.drift_tick(folder, log_root=log_root, catalogue_fingerprint="b")
    assert rep.too_thin and rep.structural and not rep.behavioural


# ── behavioural drift ─────────────────────────────────────────────────────────

def test_actor_mix_shift_fires_behavioural_finding(folder, log_root, structural_port):
    _seed(folder, log_root, n_user=20)
    dm.baseline(folder, log_root=log_root)
    _seed(folder, log_root, n_user=0, n_agent=20)
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    assert "by_actor_kind:agent" in [f["metric"] for f in rep.behavioural]
    assert not rep.ok


def test_new_dominant_skill_fires_finding(folder, log_root, structural_port):
    _seed(folder, log_root, n_agent=10, skill="nd-a")
    dm.baseline(folder, log_root=log_root)
    _seed(folder, log_root, n_user=0, n_agent=10, skill="nd-b")
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN)
    assert any(m["metric"] == "by_skill:nd-b" for m in rep.behavioural)


def test_behaviour_mix_counts_escalations_and_actor_kinds():
    events = [
        LogEvent(event="system", folder_path="f", pair_id="x", channel="system",
                 actor="system", extra={"kind": "residual-decision"}),
        LogEvent(event="ingest", folder_path="f", pair_id="y", channel="document", actor="user"),
        LogEvent(event="system", folder_path="f", pair_id="z", channel="system",
                 actor="agent:s", extra={"kind": "skill-dispatch", "skill_id": "s"}),
    ]
    mix = dm._behaviour_mix(events)
    assert mix["n"] == 3 and mix["escalations"] == 1
    assert mix["by_actor_kind"] == {"system": 1, "user": 1, "agent": 1}
    assert mix["by_skill"] == {"s": 1}


def test_share_drift_only_past_threshold():
    out = dm._share_drift("by_event", {"a": 5, "b": 5}, {"a": 6, "b": 4}, 0.15)
    assert out == []
    out = dm._share_drift("by_event", {"a": 5, "b": 5}, {"a": 10}, 0.15)
    assert {o["metric"] for o in out} == {"by_event:a", "by_event:b"}


# ── recording: idempotent, replayable ────────────────────────────────────────

def test_record_findings_is_idempotent(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root, catalogue_fingerprint="cat-1")
    rep = dm.drift_tick(folder, log_root=log_root, thresholds=THIN, catalogue_fingerprint="cat-2")
    first = dm.record_findings(rep, log_root=log_root)
    assert len(first) == len(rep.findings) >= 1
    assert dm.record_findings(rep, log_root=log_root) == []
    assert MutationLog(folder, log_root=log_root).verify_chain().ok


def test_record_findings_on_clean_report_writes_nothing(folder, log_root, structural_port):
    _seed(folder, log_root)
    dm.baseline(folder, log_root=log_root)
    assert dm.record_findings(dm.drift_tick(folder, log_root=log_root), log_root=log_root) == []


# ── the surface ───────────────────────────────────────────────────────────────

def _report_with_finding():
    return DriftReport(folder="/f", as_of=1.0, baseline_audit_id="b1",
                       structural=[{"metric": "catalogue_fingerprint", "baseline": "a", "current": "b"}])


def test_finding_surface_spec_offers_three_options_none_recommended():
    assert dm.build_surface is None
    spec = dm.finding_surface(_report_with_finding())
    assert [c["id"] for c in spec["candidates"]] == list(dm.FINDING_OPTIONS)
    assert all("recommended" not in c for c in spec["candidates"])
    assert "catalogue_fingerprint" in spec["esc_reason"]


def test_finding_surface_routes_through_bound_port(monkeypatch):
    seen = {}
    monkeypatch.setattr(dm, "build_surface", lambda **kw: seen.update(kw) or "surface")
    assert dm.finding_surface(_report_with_finding()) == "surface"
    assert set(seen) == {"query", "candidates", "esc_reason", "context"}


def test_finding_surface_refuses_clean_report():
    with pytest.raises(ValueError):
        dm.finding_surface(DriftReport(folder="/f", as_of=1.0))
