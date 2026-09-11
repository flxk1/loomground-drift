# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The preserved seam surface: names, call shapes, and grounding."""

import inspect
import json
import pathlib

import pytest
from loomground_governance import vocabulary

import loomground_drift
from loomground_drift import breaker, drift_monitor, oversight_drift

SEAM = {
    "breaker": ["Breaker", "BreakerState", "Lease", "Tripwire", "WITNESS_ESCAPE_METRIC",
                "cap_grade", "default_tripwires", "ensure_witness_escape_armed",
                "status_after_witness_escape_check", "witness_escape_metrics",
                "witness_escape_tripwire"],
    "drift_monitor": ["DriftReport", "DriftThresholds", "drift_tick"],
    "oversight_drift": ["DriftSignal", "drift_tripwire", "evaluate", "raise_floor"],
}
ALSO = {
    "breaker": ["RenewResult", "BreakerStatus", "REFUSED_VERDICT", "grade_levels", "floor_grade", "clock"],
    "drift_monitor": ["DEFAULT_THRESHOLDS", "baseline", "record_findings", "finding_surface",
                      "structural_state", "build_surface", "_behaviour_mix", "_share_drift"],
    "oversight_drift": ["DRIFT_STRUCTURAL_METRIC"],
}


@pytest.mark.parametrize("module,name", [(m, n) for m, ns in SEAM.items() for n in ns])
def test_seam_surface_name_is_importable(module, name):
    mod = getattr(loomground_drift, module)
    assert hasattr(mod, name)
    if not name.startswith("_") and name not in ("clock",):
        assert hasattr(loomground_drift, name)


@pytest.mark.parametrize("module,name", [(m, n) for m, ns in ALSO.items() for n in ns])
def test_kept_name_is_present(module, name):
    assert hasattr(getattr(loomground_drift, module), name)


def _params(fn):
    return inspect.signature(fn).parameters


def test_breaker_status_shape():
    p = _params(breaker.Breaker.status)
    assert list(p) == ["self", "metrics", "now"]
    assert p["metrics"].kind is p["metrics"].KEYWORD_ONLY


def test_drift_tick_shape_is_host_compatible_plus_port():
    p = _params(drift_monitor.drift_tick)
    assert list(p) == ["folder", "log_root", "catalogue_fingerprint", "thresholds", "as_of", "structural"]
    assert p["folder"].kind is p["folder"].POSITIONAL_OR_KEYWORD
    assert all(p[k].kind is p[k].KEYWORD_ONLY for k in list(p)[1:])
    assert p["structural"].default is None


def test_baseline_shape_is_host_compatible_plus_port():
    p = _params(drift_monitor.baseline)
    assert list(p) == ["folder", "log_root", "catalogue_fingerprint", "actor", "note", "structural"]
    assert p["actor"].default == "user"


def test_evaluate_shape_is_host_compatible_plus_levels():
    p = _params(oversight_drift.evaluate)
    assert list(p) == ["report", "levels", "behavioural_floor"]
    assert p["levels"].kind is p["levels"].KEYWORD_ONLY
    assert p["levels"].default is p["levels"].empty
    assert p["behavioural_floor"].default is p["behavioural_floor"].empty


def test_raise_floor_shape():
    p = _params(oversight_drift.raise_floor)
    assert list(p) == ["current", "recommended", "levels"]
    assert p["levels"].kind is p["levels"].KEYWORD_ONLY


def test_grade_lattice_equals_governance_vocabulary():
    assert list(breaker.grade_levels()) == vocabulary("grades")["levels"]
    assert list(breaker._GRADES) == vocabulary("grades")["levels"]


def test_source_declares_no_grade_sequence_literal():
    src = pathlib.Path(breaker.__file__).parent
    for path in src.glob("*.py"):
        text = path.read_text()
        assert '"L0"' not in text, path.name
        assert "'L0'" not in text, path.name


def test_events_go_through_the_audit_chain():
    from loomground_audit_chain.mutation_log import LogEvent, MutationLog
    assert drift_monitor.MutationLog is MutationLog
    assert drift_monitor.LogEvent is LogEvent


def test_version_is_a_string():
    assert isinstance(loomground_drift.__version__, str)
    json.dumps(loomground_drift.__version__)
