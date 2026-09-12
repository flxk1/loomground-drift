<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 flxk1 -->
# loomground-drift

Leased autonomy that decays unless renewed, tripwires that quarantine, drift measured against a baseline.

## Problem

A human stops a fast agent too late; drift from baseline goes unseen. Leased autonomy that decays unless renewed, tripwires that quarantine, drift measured against a baseline.

## Install

```
pip install loomground-drift
```

Requires `loomground-governance` 0.11 and `loomground-audit-chain` 0.1. Python 3.10+.

## Usage

```python
from loomground_drift import Breaker, Lease, drift_tripwire, drift_tick, evaluate
b = Breaker(Lease("bot", "L3", expires_at=1000.0), tripwires=[drift_tripwire()])
b.status(now=990.0).effective_grade
report = drift_tick("ws", log_root="logs", structural={"pinned_skills": ["x"]})
sig = evaluate(report, levels=("NOTIFY", "REVIEW", "APPROVE"), behavioural_floor="REVIEW")
b.status(metrics=sig.metrics, now=1002.0).verdict
```

## Example

```
in : lease L3 until t=1000, drift tripwire armed; status at 990, at 1001, then a structural finding at 1002 and a renewal
out: RUNNING L3 ''
     DECAYED L0 ''
     QUARANTINED L0 'refused' False
```

## Interface

- `Lease(agent, granted_grade, expires_at, ttl_seconds, granted_at)`: `live(now)`, `effective_grade(now)`, `renew(ok=, now=)`
- `Tripwire(name, metric, limit, kind)` with `kind` in `max` | `min` | `flag`; `None` is a gap, never a trip
- `Breaker(lease, tripwires)`: `status(metrics=, now=) → BreakerStatus(state, effective_grade, verdict)`, `renew`, `clear(by=, rationale=)`; `cap_grade(requested, ceiling)`
- states: RUNNING → the lease's grade; DECAYED → floor grade `levels[0]`; QUARANTINED → floor grade and the `refused` verdict, sticky until a named human clears
- `baseline(folder, log_root=, structural=)`, `drift_tick(folder, log_root=, thresholds=, as_of=, structural=) → DriftReport`, `record_findings`, `finding_surface`
- `evaluate(report, levels=, behavioural_floor=) → DriftSignal`, `drift_tripwire()`, `raise_floor(current, recommended, levels=)`
- ports: `drift_monitor.structural_state(folder) → dict` (absent → `structural_unmeasured`, zero findings), `drift_monitor.build_surface`, `levels` (the host's oversight ladder), `breaker.clock`; details in [docs/seam.md](docs/seam.md)

## Family

Runtime controls. Consumes `loomground-governance` (`vocabulary("grades")`, `vocabulary("verdicts")`) and `loomground-audit-chain` (`mutation_log`, `witness_escape`). Hosts consume it through the documented ports; it is optional for every consumer. Catalogue: [loomground/CATALOGUE.md](https://github.com/flxk1/loomground/blob/main/CATALOGUE.md).

## Status

0.1.0 · 118 tests · Python >=3.10 · governance 0.11 · audit-chain 0.1

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` (code) · CC-BY-4.0 `LICENSES/CC-BY-4.0.txt` (README) · `NOTICE`
