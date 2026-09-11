<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Seam: RVND → loomground-drift

Source: RVND commit `bac579b`, `server/src/rvnd/`. Behaviour, constants and
metric names preserved; the host's structural loaders and oversight ladder
become injected ports; grade and verdict words come from governance vocabulary.

## Module map

| RVND module (bac579b) | Package module |
|---|---|
| `rvnd/breaker.py` | `loomground_drift/breaker.py` |
| `rvnd/drift_monitor.py` | `loomground_drift/drift_monitor.py` |
| `rvnd/oversight_drift.py` | `loomground_drift/oversight_drift.py` |

## Preserved names

From `seam-surface.json` (names RVND callers import):

- `breaker`: `Breaker`, `BreakerState`, `Lease`, `Tripwire`, `WITNESS_ESCAPE_METRIC`,
  `cap_grade`, `default_tripwires`, `ensure_witness_escape_armed`,
  `status_after_witness_escape_check`, `witness_escape_metrics`, `witness_escape_tripwire`.
  Also kept: `RenewResult`, `BreakerStatus`. New: `grade_levels()`, `floor_grade()`,
  `REFUSED_VERDICT`, `clock`, `BreakerStatus.verdict`.
- `drift_monitor`: `DriftReport`, `DriftThresholds`, `drift_tick`. Also kept:
  `DEFAULT_THRESHOLDS`, `baseline`, `record_findings`, `finding_surface`,
  `_behaviour_mix`, `_share_drift`. New: `DriftReport.structural_unmeasured`,
  `DriftReport.needs_rebaseline`, `FINDING_OPTIONS`, the two ports below.
- `oversight_drift`: `DriftSignal`, `drift_tripwire`, `evaluate`, `raise_floor`.
  New: `DRIFT_STRUCTURAL_METRIC`.

Call shapes kept: `Breaker.status(*, metrics=, now=)`;
`baseline(folder, *, log_root=, catalogue_fingerprint=, actor=, note=, structural=)`;
`drift_tick(folder, *, log_root=, catalogue_fingerprint=, thresholds=, as_of=, structural=)`;
`evaluate(report, *, levels, behavioural_floor)`; `raise_floor(current, recommended, *, levels)`.

## Ports

| Port | Kind | Default | RVND binding |
|---|---|---|---|
| `drift_monitor.structural_state(folder) -> Mapping[str, Any]` | module global, or `structural=` per call | `None` → `structural_unmeasured` | `policy.load_policy` bindings (`policy:<field>` keys) + `pinned_skills.load_pinned_skills` (`pinned_skills` sorted ids) |
| `drift_monitor.build_surface(query=, candidates=, esc_reason=, context=)` | module global | `None` → spec dict returned | `decisions.surface.build_surface` |
| `oversight_drift.evaluate(..., levels=)` / `raise_floor(..., levels=)` | required keyword | — | `oversight_extractor.OVERSIGHT_LEVELS` |
| `oversight_drift.evaluate(..., behavioural_floor=)` | required keyword | — | `"REVIEW"` |
| `breaker.clock` | module global | `time.time` | — |

Structural state is a flat `{name: json_value}` mapping. On a tick every differing
key is one finding named by the key: set-like values report `added`/`removed`,
scalars report `baseline`/`current`. A port raising propagates; nothing is guessed.

Absent structural half (port unbound at baseline or at tick): the tick returns
`structural_unmeasured=True`, `findings == []`, `ok is False`, `needs_rebaseline is True`;
`oversight_drift.evaluate` maps it to `needs_rebaseline`, never a trip.

## Grounding

- Grade lattice: `loomground_governance.vocabulary("grades")["levels"]`, read at
  import into `_GRADES`/`_GRADE_IDX`; the floor is `levels[0]`. No level name is
  written in `src/`.
- Verdicts: QUARANTINED → the gate refuses, `BreakerStatus.verdict == "refused"`
  (checked against `vocabulary("verdicts")["alphabet"]` at import); DECAYED → the
  floor grade, verdict left to the gate's grade comparison.
- Events: `loomground_audit_chain.mutation_log.{MutationLog, LogEvent}` for
  baselines (`pair_id="drift-baseline"`) and findings (`pair_id="drift-finding"`);
  `loomground_audit_chain.witness_escape.recent_witness_escapes` for the
  witness-escape metric.

## Stays in RVND

- `rvnd/policy.py`, `rvnd/pinned_skills.py` — the structural loaders, reached through
  the `structural_state` port.
- `rvnd/oversight_extractor.OVERSIGHT_LEVELS` — the ladder, passed as `levels`.
- `rvnd/decisions/surface.py` — the decision surface, reached through `build_surface`.
- `rvnd/parties.py`, `rvnd/governance.decide_action`, `rvnd/oversight_dispatch.py` —
  the party register, the gate and the dispatch writer; their tests stay with RVND.

## How RVND shims

One `rvnd/adapters/drift.py` binds the ports; each `rvnd/<module>.py` re-exports.

```python
# rvnd/adapters/drift.py
import functools
import loomground_drift.drift_monitor as _dm
import loomground_drift.oversight_drift as _od
from loomground_drift.breaker import *          # rvnd.breaker: import-only
from .. import policy, pinned_skills
from ..oversight_extractor import OVERSIGHT_LEVELS

def _structural(folder, log_root=None):
    p = policy.load_policy(folder)
    out = {f"policy:{k}": getattr(p, k) for k in (
        "privacy_lock_enabled", "lock_is_active", "lock_mode", "oversight_enabled",
        "oversight_is_active", "oversight_default_level")}
    out["policy:acknowledgements"] = sorted(p.acknowledgements)
    try:
        out["pinned_skills"] = sorted(s.id for s in pinned_skills.load_pinned_skills(folder, log_root=log_root).skills)
    except Exception:
        out["pinned_skills"] = ["<pinned-skills-store-unreadable>"]
    return out

def _build_surface(**kw):
    from ..decisions.surface import build_surface
    return build_surface(**kw)

_dm.structural_state = _structural
_dm.build_surface = _build_surface

def baseline(folder, *, log_root=None, **kw):                  # rvnd.drift_monitor
    return _dm.baseline(folder, log_root=log_root, structural=_structural(folder, log_root), **kw)

def drift_tick(folder, *, log_root=None, **kw):
    return _dm.drift_tick(folder, log_root=log_root, structural=_structural(folder, log_root), **kw)

evaluate = functools.partial(_od.evaluate, levels=OVERSIGHT_LEVELS, behavioural_floor="REVIEW")
raise_floor = functools.partial(_od.raise_floor, levels=OVERSIGHT_LEVELS)   # rvnd.oversight_drift
```

`rvnd.breaker` needs zero definitions. `rvnd.drift_monitor` and
`rvnd.oversight_drift` are port-binding wrappers: the structural mapping keys
above reproduce RVND's finding metric names (`policy:<field>`, `pinned_skills`);
`functools.partial` keeps `evaluate(report, behavioural_floor=...)` callable as before.
