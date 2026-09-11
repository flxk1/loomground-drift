# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""loomground-drift — leased autonomy, tripwires, drift against a baseline.

Modules: :mod:`.breaker` (leases, tripwires, the breaker verdict),
:mod:`.drift_monitor` (baselines and the deterministic tick),
:mod:`.oversight_drift` (a drift report as breaker metrics and an oversight floor).
"""
from __future__ import annotations

from . import breaker, drift_monitor, oversight_drift
from ._version import __version__
from .breaker import (
    REFUSED_VERDICT,
    WITNESS_ESCAPE_METRIC,
    Breaker,
    BreakerState,
    BreakerStatus,
    Lease,
    RenewResult,
    Tripwire,
    cap_grade,
    default_tripwires,
    ensure_witness_escape_armed,
    floor_grade,
    grade_levels,
    status_after_witness_escape_check,
    witness_escape_metrics,
    witness_escape_tripwire,
)
from .drift_monitor import (
    DEFAULT_THRESHOLDS,
    DriftReport,
    DriftThresholds,
    baseline,
    drift_tick,
    finding_surface,
    record_findings,
)
from .oversight_drift import DriftSignal, drift_tripwire, evaluate, raise_floor

__all__ = [
    "__version__",
    "breaker", "drift_monitor", "oversight_drift",
    "REFUSED_VERDICT", "WITNESS_ESCAPE_METRIC", "Breaker", "BreakerState",
    "BreakerStatus", "Lease", "RenewResult", "Tripwire", "cap_grade",
    "default_tripwires", "ensure_witness_escape_armed", "floor_grade",
    "grade_levels", "status_after_witness_escape_check",
    "witness_escape_metrics", "witness_escape_tripwire",
    "DEFAULT_THRESHOLDS", "DriftReport", "DriftThresholds", "baseline",
    "drift_tick", "finding_surface", "record_findings",
    "DriftSignal", "drift_tripwire", "evaluate", "raise_floor",
]
