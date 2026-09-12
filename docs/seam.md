<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Host seam

`loomground-drift` owns its breaker, drift-monitor, and oversight-drift
semantics. A consuming host supplies structural state, a decision-surface
builder, and its oversight ladder through explicit ports; no host package is
imported.

## Public modules

| Module | Public surface |
|---|---|
| `loomground_drift.breaker` | `Breaker`, `BreakerState`, `Lease`, `Tripwire`, `cap_grade`, witness-escape helpers |
| `loomground_drift.drift_monitor` | `DriftReport`, `DriftThresholds`, `baseline`, `drift_tick`, findings helpers |
| `loomground_drift.oversight_drift` | `DriftSignal`, `drift_tripwire`, `evaluate`, `raise_floor` |

Call shapes are stable: `Breaker.status(*, metrics=, now=)`;
`baseline(folder, *, log_root=, catalogue_fingerprint=, actor=, note=,
structural=)`; `drift_tick(folder, *, log_root=, catalogue_fingerprint=,
thresholds=, as_of=, structural=)`; `evaluate(report, *, levels,
behavioural_floor)`; and `raise_floor(current, recommended, *, levels)`.

## Ports

| Port | Default | Host responsibility |
|---|---|---|
| `drift_monitor.structural_state(folder)` or per-call `structural=` | absent | Return a flat JSON-compatible mapping of policy-relevant state. |
| `drift_monitor.build_surface(**spec)` | absent | Convert a finding spec into the host's decision surface. |
| `evaluate(..., levels=)` / `raise_floor(..., levels=)` | required | Supply the ordered oversight ladder. |
| `evaluate(..., behavioural_floor=)` | required | Supply a value on that ladder. |
| `breaker.clock` | `time.time` | Optionally inject a deterministic clock. |

Structural state is a flat `{name: json_value}` mapping. Every changed key is
one finding; set-like values report `added` and `removed`, while scalars report
`baseline` and `current`. If the structural port is absent at baseline or tick,
the report sets `structural_unmeasured=True`, has no structural findings, is not
OK, and requires rebaselining. Port errors propagate rather than being guessed
away.

## Grounding

- The grade lattice comes from
  `loomground_governance.vocabulary("grades")["levels"]`; source code contains
  no hard-coded level names.
- A quarantined breaker uses the `refused` verdict from the governance
  vocabulary. A decayed breaker falls to the first grade.
- Baselines and findings use
  `loomground_audit_chain.mutation_log.{MutationLog, LogEvent}`; witness-escape
  metrics use `loomground_audit_chain.witness_escape`.

## Host adapter sketch

```python
import functools
import loomground_drift.drift_monitor as drift
import loomground_drift.oversight_drift as oversight

def structural_state(folder):
    return {"policy:version": load_policy(folder).version}

drift.structural_state = structural_state
drift.build_surface = build_decision_surface
evaluate = functools.partial(
    oversight.evaluate,
    levels=OVERSIGHT_LEVELS,
    behavioural_floor="REVIEW",
)
```

The adapter belongs to the consumer. The package has no dependency on it.
