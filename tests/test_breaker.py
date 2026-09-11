# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Leases, tripwires, quarantine: stopping is default, running needs a live lease."""

import pytest
from loomground_governance import vocabulary

from loomground_drift import breaker as br
from loomground_drift.breaker import (
    REFUSED_VERDICT, Breaker, BreakerState, Lease, Tripwire, cap_grade,
    default_tripwires, floor_grade, grade_levels)

G = grade_levels()
FLOOR = G[0]


def _lease(grade=G[3], expires=1000.0, ttl=60.0, granted=940.0):
    return Lease(agent="bot", granted_grade=grade, expires_at=expires,
                 ttl_seconds=ttl, granted_at=granted)


# ── grounding: the lattice is governance's, the refusal word is governance's ──

def test_grade_lattice_is_governance_vocabulary():
    assert list(G) == vocabulary("grades")["levels"]
    assert floor_grade() == vocabulary("grades")["levels"][0]


def test_refused_verdict_is_in_governance_alphabet():
    assert REFUSED_VERDICT in vocabulary("verdicts")["alphabet"]


def test_unknown_verdict_word_is_refused_at_import_time():
    with pytest.raises(LookupError):
        br._verdict_word("not-a-verdict")


# ── Lease decay ───────────────────────────────────────────────────────────────

def test_live_lease_grants_its_grade():
    assert _lease().effective_grade(now=990.0) == G[3]


def test_lapsed_lease_decays_to_floor_no_action():
    assert _lease(expires=1000.0).effective_grade(now=1001.0) == FLOOR


def test_refused_renewal_does_not_extend():
    lease = _lease(expires=1000.0)
    r = lease.renew(ok=False, reason="budget exceeded", now=990.0)
    assert r.renewed is False
    assert lease.expires_at == 1000.0
    assert lease.effective_grade(now=1001.0) == FLOOR


def test_successful_renewal_extends():
    lease = _lease(expires=1000.0, ttl=60.0)
    r = lease.renew(ok=True, now=990.0)
    assert r.renewed is True
    assert lease.expires_at == 1050.0
    assert lease.effective_grade(now=1040.0) == G[3]


def test_bad_grade_and_ttl_rejected_at_write():
    with pytest.raises(ValueError):
        Lease("bot", "L99", 1.0)
    with pytest.raises(ValueError):
        Lease("bot", G[3], 1.0, ttl_seconds=0)


def test_injectable_clock_is_the_default_now(monkeypatch):
    monkeypatch.setattr(br, "clock", lambda: 995.0)
    lease = _lease(expires=1000.0)
    assert lease.live() is True
    monkeypatch.setattr(br, "clock", lambda: 1005.0)
    assert lease.live() is False
    assert Lease("bot", G[1], 2000.0).granted_at == 1005.0


# ── Tripwires ─────────────────────────────────────────────────────────────────

def test_tripwire_max_min_flag():
    assert Tripwire("e", "error_rate", 0.2, "max").trips(0.3)
    assert not Tripwire("e", "error_rate", 0.2, "max").trips(0.1)
    assert Tripwire("h", "queue_health", 0.5, "min").trips(0.4)
    assert Tripwire("a", "attestation_failed", 0.0, "flag").trips(True)


def test_unmeasured_metric_does_not_trip():
    assert Tripwire("e", "error_rate", 0.2, "max").trips(None) is False
    assert Tripwire("e", "error_rate", 0.2, "max").evaluate(None) is None


# ── Breaker composition ───────────────────────────────────────────────────────

def test_running_when_lease_live_and_clean():
    s = Breaker(_lease(), tripwires=[]).status(now=990.0)
    assert s.state is BreakerState.RUNNING
    assert s.effective_grade == G[3]
    assert s.running
    assert s.verdict == ""


def test_decayed_when_lease_lapsed():
    s = Breaker(_lease(expires=1000.0), tripwires=[]).status(now=1001.0)
    assert s.state is BreakerState.DECAYED
    assert s.effective_grade == FLOOR
    assert s.verdict == ""


def test_tripwire_quarantines_even_with_live_lease():
    b = Breaker(_lease(), tripwires=[Tripwire("error_rate", "error_rate", 0.25, "max")])
    s = b.status(metrics={"error_rate": 0.4}, now=990.0)
    assert s.state is BreakerState.QUARANTINED
    assert s.effective_grade == FLOOR
    assert s.tripped
    assert s.verdict == REFUSED_VERDICT
    assert s.to_dict()["state"] == "QUARANTINED"
    assert s.to_dict()["verdict"] == REFUSED_VERDICT


def test_quarantine_is_sticky_until_cleared():
    b = Breaker(_lease(), tripwires=[Tripwire("attestation", "attestation_failed", 0.0, "flag")])
    b.status(metrics={"attestation_failed": True}, now=990.0)
    s2 = b.status(metrics={"attestation_failed": False}, now=991.0)
    assert s2.state is BreakerState.QUARANTINED


def test_renewal_cannot_lift_quarantine():
    b = Breaker(_lease(), tripwires=[Tripwire("chain", "chain_invalid", 0.0, "flag")])
    b.status(metrics={"chain_invalid": True}, now=990.0)
    r = b.renew(ok=True, now=991.0)
    assert r.renewed is False
    assert r.effective_grade == FLOOR
    assert "quarantine" in r.reason.lower()


def test_clear_requires_actor_and_rationale():
    b = Breaker(_lease(), tripwires=[Tripwire("chain", "chain_invalid", 0.0, "flag")])
    b.status(metrics={"chain_invalid": True}, now=990.0)
    assert "error" in b.clear(by="", rationale="x")
    assert "error" in b.clear(by="alice", rationale="")
    ok = b.clear(by="alice", rationale="root cause fixed, hash rebuilt")
    assert ok["cleared"] is True and ok["previous_reason"]
    b.renew(ok=True, now=991.0)
    assert b.status(metrics={"chain_invalid": False}, now=992.0).state is BreakerState.RUNNING


def test_effective_grade_is_the_gate_coupling():
    b = Breaker(_lease(grade=G[4], expires=1000.0), tripwires=[])
    assert b.effective_grade(now=990.0) == G[4]
    assert b.effective_grade(now=1001.0) == FLOOR


def test_dead_mans_switch_sequence():
    b = Breaker(_lease(grade=G[3], expires=1000.0, ttl=60.0), tripwires=[])
    assert b.status(now=990.0).effective_grade == G[3]
    assert b.status(now=1001.0).effective_grade == FLOOR
    b.renew(ok=True, now=1001.0)
    assert b.status(now=1010.0).effective_grade == G[3]


def test_default_tripwires_are_armed_when_none_given():
    b = Breaker(_lease())
    assert [t.metric for t in b.tripwires] == [t.metric for t in default_tripwires()]


# ── grade lattice meet ────────────────────────────────────────────────────────

def test_cap_grade_meets_lower():
    assert cap_grade(G[4], G[2]) == G[2]
    assert cap_grade(G[1], G[3]) == G[1]
    assert cap_grade(G[3], G[3]) == G[3]


def test_cap_grade_no_ceiling_and_unknown_ceiling():
    assert cap_grade(G[4], "") == G[4]
    assert cap_grade(G[4], "bogus") == FLOOR
    assert cap_grade("bogus", G[4]) == FLOOR


def test_default_tripwires_cover_integrity():
    metrics = {tw.metric for tw in default_tripwires()}
    assert {"attestation_failed", "chain_invalid"} <= metrics
