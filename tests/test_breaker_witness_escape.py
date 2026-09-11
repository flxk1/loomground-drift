# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""A witness escape recorded on the audit chain trips the same flag mechanism
as every other integrity check: QUARANTINED, floor grade, scoped by folder and
actor, sticky until a named human clears it."""
from __future__ import annotations

import pytest
from loomground_audit_chain.witness_escape import record_witness_escape

from loomground_drift.breaker import (
    REFUSED_VERDICT, WITNESS_ESCAPE_METRIC, Breaker, BreakerState, Lease,
    ensure_witness_escape_armed, grade_levels, status_after_witness_escape_check,
    witness_escape_metrics, witness_escape_tripwire)

G = grade_levels()


@pytest.fixture
def other_folder(tmp_path):
    f = tmp_path / "ws-b"
    f.mkdir()
    return f


def _lease(agent, grade=G[3], expires=100000.0, granted_at=0.0):
    return Lease(agent=agent, granted_grade=grade, expires_at=expires,
                 ttl_seconds=60.0, granted_at=granted_at)


def test_witness_escape_tripwire_is_a_flag_tripwire():
    tw = witness_escape_tripwire()
    assert tw.kind == "flag" and tw.metric == WITNESS_ESCAPE_METRIC
    assert tw.trips(True) is True
    assert tw.trips(False) is False
    assert tw.trips(None) is False


def test_ensure_witness_escape_armed_is_idempotent():
    b = Breaker(_lease("bot7"), tripwires=[])
    ensure_witness_escape_armed(b)
    ensure_witness_escape_armed(b)
    assert len([t for t in b.tripwires if t.metric == WITNESS_ESCAPE_METRIC]) == 1


def test_recorded_escape_quarantines_the_actor_to_floor(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    b = Breaker(_lease("bot7"), tripwires=[])
    status = status_after_witness_escape_check(b, folder, "bot7", now=50.0)
    assert status.state is BreakerState.QUARANTINED
    assert status.effective_grade == G[0]
    assert status.verdict == REFUSED_VERDICT
    assert b.effective_grade(metrics={}, now=50.0) == G[0]


def test_witness_escape_metrics_reads_true_only_when_recorded(folder):
    assert witness_escape_metrics(folder, "bot7") == {WITNESS_ESCAPE_METRIC: False}
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    assert witness_escape_metrics(folder, "bot7") == {WITNESS_ESCAPE_METRIC: True}


def test_witness_escape_metrics_honours_explicit_log_root(folder, log_root):
    record_witness_escape(folder, ["/etc/passwd"], "bot7", log_root=log_root)
    assert witness_escape_metrics(folder, "bot7") == {WITNESS_ESCAPE_METRIC: False}
    assert witness_escape_metrics(folder, "bot7", log_root=log_root) == {WITNESS_ESCAPE_METRIC: True}


def test_since_window_scopes_the_read(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    assert witness_escape_metrics(folder, "bot7", since=1_000_000_000_000.0) == {WITNESS_ESCAPE_METRIC: False}


def test_escape_does_not_quarantine_an_unrelated_actor_in_the_same_folder(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    innocent = Breaker(_lease("bot-innocent"), tripwires=[])
    status = status_after_witness_escape_check(innocent, folder, "bot-innocent", now=50.0)
    assert status.state is BreakerState.RUNNING
    assert status.effective_grade == G[3]


def test_escape_in_folder_a_does_not_quarantine_the_same_actor_in_folder_b(folder, other_folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    elsewhere = Breaker(_lease("bot7"), tripwires=[])
    status = status_after_witness_escape_check(elsewhere, other_folder, "bot7", now=50.0)
    assert status.state is BreakerState.RUNNING
    assert status.effective_grade == G[3]


def test_no_witness_escape_event_leaves_status_unchanged(folder):
    plain = Breaker(_lease("bot7"), tripwires=[])
    checked = Breaker(_lease("bot7"), tripwires=[])
    plain_status = plain.status(now=50.0)
    checked_status = status_after_witness_escape_check(checked, folder, "bot7", now=50.0)
    assert checked_status.state == plain_status.state == BreakerState.RUNNING
    assert checked_status.effective_grade == plain_status.effective_grade == G[3]


def test_extra_metrics_are_folded_in(folder):
    from loomground_drift.breaker import Tripwire
    b = Breaker(_lease("bot7"), tripwires=[Tripwire("e", "error_rate", 0.25, "max")])
    s = status_after_witness_escape_check(b, folder, "bot7", extra_metrics={"error_rate": 0.9}, now=50.0)
    assert s.state is BreakerState.QUARANTINED
    assert any("error_rate" in t for t in s.tripped)


def test_quarantine_is_sticky_and_clears_only_via_named_human(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    b = Breaker(_lease("bot7"), tripwires=[])
    assert status_after_witness_escape_check(b, folder, "bot7", now=50.0).state is BreakerState.QUARANTINED
    assert b.renew(ok=True, now=60.0).renewed is False
    s2 = status_after_witness_escape_check(b, folder, "bot7", since=1_000_000_000_000.0, now=70.0)
    assert s2.state is BreakerState.QUARANTINED
    assert "error" in b.clear(by="", rationale="root cause fixed")
    assert "error" in b.clear(by="alice", rationale="")
    assert b.clear(by="alice", rationale="reviewed escape, false positive on a symlink")["cleared"] is True
    b.renew(ok=True, now=71.0)
    assert b.status(now=72.0).state is BreakerState.RUNNING


def test_self_renewal_never_clears_a_witness_escape_quarantine(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    b = Breaker(_lease("bot7"), tripwires=[])
    status_after_witness_escape_check(b, folder, "bot7", now=50.0)
    for _ in range(3):
        r = b.renew(ok=True, now=60.0)
        assert r.renewed is False
        assert "quarantine" in r.reason.lower()
    assert b.status(now=61.0).state is BreakerState.QUARANTINED
