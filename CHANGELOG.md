<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## [0.2.0](https://github.com/flxk1/loomground-drift/compare/loomground-drift-v0.1.0...loomground-drift-v0.2.0) (2026-09-11)


### Features

* breaker, drift monitor, oversight drift with injected ports ([c1dafdb](https://github.com/flxk1/loomground-drift/commit/c1dafdb1db9c00e5584bf2b08a1d0da8c0b4703d))


### Documentation

* seam map, RVND shim guidance, llms.txt ([5bdd6d7](https://github.com/flxk1/loomground-drift/commit/5bdd6d74a69d741fc713980bf9ed94c2fd9ec665))

## 0.1.0

Initial extraction. Provenance: RVND commit `bac579b`, `server/src/rvnd/breaker.py`,
`server/src/rvnd/drift_monitor.py`, `server/src/rvnd/oversight_drift.py`, relicensed
from AGPL-3.0-only to Apache-2.0 (code) / CC-BY-4.0 (README) on the
loomground-workspace extraction precedent, copyright holder unchanged (flxk1).

* `breaker`: `Lease`, `Tripwire`, `Breaker`, `cap_grade`, the witness-escape
  tripwire input. Grade lattice read from `loomground_governance.vocabulary("grades")`;
  the floor grade is `levels[0]`; a QUARANTINED status carries the `refused` verdict
  word read from `vocabulary("verdicts")`. Witness-escape events read through
  `loomground_audit_chain.witness_escape.recent_witness_escapes`.
* `drift_monitor`: `baseline`, `drift_tick`, `record_findings`, `finding_surface`.
  Structural inputs injected: the `structural_state(folder) -> dict` port or an
  explicit `structural=` argument replaces the host's policy and pinned-skill
  loaders; with neither, a baseline records `structural: None` and a tick reports
  `structural_unmeasured` (a gap, no finding, `ok=False`). `finding_surface`
  hands its spec to the `build_surface` port or returns it as a dict. Events go
  through `loomground_audit_chain.mutation_log`.
* `oversight_drift`: `DriftSignal`, `evaluate`, `drift_tripwire`, `raise_floor`.
  The oversight ladder is injected: `levels` is a required keyword on `evaluate`
  and `raise_floor`; `behavioural_floor` has no default and must be on the ladder.
* Tests ported from RVND's breaker, witness-escape, drift-monitor and
  oversight-drift suites and adapted to the injected ports; the party-register,
  `decide_action` and dispatch-record halves stay with RVND.
