# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Versioned operational-state baselines and a deterministic drift tick.

``baseline(folder)`` snapshots the folder's operational state — the host's
structural state (through the ``structural_state`` port or an explicit
``structural=``), a catalogue fingerprint, and the behavioural mix projected
from the folder's audit chain — as a signed ``drift-baseline`` event.
``drift_tick(folder)`` diffs the current state against the latest baseline;
same chain and same ``as_of`` give the same report. Threshold crossings are
findings for a human; the monitor records and surfaces, it decides nothing.

Honest gaps: a thin window is ``too_thin``; a structural half missing on either
side is ``structural_unmeasured``. Both are surfaced, neither is compared, and
neither fires a finding.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from loomground_audit_chain.mutation_log import LogEvent, MutationLog

__all__ = ["DriftThresholds", "DriftReport", "baseline", "drift_tick",
           "record_findings", "finding_surface", "DEFAULT_THRESHOLDS",
           "structural_state", "build_surface"]

#: Host port: ``structural_state(folder) -> {name: json_value}``, the host's
#: configuration bindings for the folder. ``None`` = structural drift unmeasured.
structural_state: Optional[Callable[[Any], Mapping[str, Any]]] = None

#: Host port: ``build_surface(query=, candidates=, esc_reason=, context=)``
#: routes findings to the host's decision surface. ``None`` = the spec is returned.
build_surface: Optional[Callable[..., Any]] = None


@dataclass(frozen=True)
class DriftThresholds:
    """``share_shift``: a behavioural category whose share of traffic moves by
    more than this against the baseline is a finding. ``min_events``: fewer
    events since the baseline than this is ``too_thin``."""
    share_shift: float = 0.15
    min_events: int = 20


DEFAULT_THRESHOLDS = DriftThresholds()

_BASELINE_KIND = "drift-baseline"
_FINDING_KIND = "drift-finding"
_SKILL_EVENT_KINDS = ("workflow-event", "skill-dispatch")
_ESCALATION_KIND = "residual-decision"
_AGENT_PREFIX = "agent:"
_USER_ACTOR = "user"


def _resolve_structural(folder: Any, structural: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    if structural is not None:
        return dict(structural)
    port = globals()["structural_state"]
    if port is None:
        return None
    return dict(port(folder))


def _behaviour_mix(events: Iterable[LogEvent]) -> dict[str, Any]:
    n = 0
    by_event: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    by_actor_kind: dict[str, int] = {}
    by_skill: dict[str, int] = {}
    escalations = 0
    for e in events:
        n += 1
        by_event[e.event] = by_event.get(e.event, 0) + 1
        by_channel[e.channel] = by_channel.get(e.channel, 0) + 1
        kind = "agent" if str(e.actor).startswith(_AGENT_PREFIX) else (
            "user" if e.actor == _USER_ACTOR else "system")
        by_actor_kind[kind] = by_actor_kind.get(kind, 0) + 1
        x = e.extra or {}
        if x.get("kind") in _SKILL_EVENT_KINDS and x.get("skill_id"):
            by_skill[str(x["skill_id"])] = by_skill.get(str(x["skill_id"]), 0) + 1
        if x.get("kind") == _ESCALATION_KIND:
            escalations += 1
    return {"n": n, "by_event": by_event, "by_channel": by_channel,
            "by_actor_kind": by_actor_kind, "by_skill": by_skill,
            "escalations": escalations}


def _operational_state(structural: Optional[dict[str, Any]], *,
                       catalogue_fingerprint: str,
                       events: Iterable[LogEvent]) -> dict[str, Any]:
    return {"structural": structural,
            "catalogue_fingerprint": catalogue_fingerprint,
            "behaviour": _behaviour_mix(events)}


def baseline(folder: str | Path, *, log_root: str | Path | None = None,
             catalogue_fingerprint: str = "", actor: str = "user",
             note: str = "",
             structural: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    """Snapshot the folder's operational state as a signed baseline event.
    ``structural=`` overrides the ``structural_state`` port; with neither, the
    baseline records ``structural: None`` and says so."""
    log = MutationLog(folder, log_root=log_root)
    state = _operational_state(_resolve_structural(folder, structural),
                               catalogue_fingerprint=catalogue_fingerprint,
                               events=log.replay())
    audit_id = log.append(LogEvent(
        event="system", folder_path=str(folder), pair_id=_BASELINE_KIND,
        channel="system", actor=actor,
        extra={"kind": _BASELINE_KIND, "state": state, "note": note}))
    return {"audit_id": audit_id, "state": state}


def _latest_baseline(log: MutationLog) -> Optional[tuple[LogEvent, dict]]:
    found = None
    for e in log.replay():
        if e.pair_id == _BASELINE_KIND and (e.extra or {}).get("kind") == _BASELINE_KIND:
            found = (e, (e.extra or {}).get("state") or {})
    return found


@dataclass
class DriftReport:
    folder: str
    as_of: float
    baseline_audit_id: str = ""
    baseline_ts: float = 0.0
    structural: list[dict] = field(default_factory=list)
    behavioural: list[dict] = field(default_factory=list)
    too_thin: bool = False
    window_n: int = 0
    no_baseline: bool = False
    structural_unmeasured: bool = False

    @property
    def findings(self) -> list[dict]:
        return self.structural + self.behavioural

    @property
    def needs_rebaseline(self) -> bool:
        return self.no_baseline or self.too_thin or self.structural_unmeasured

    @property
    def ok(self) -> bool:
        return not self.no_baseline and not self.structural_unmeasured and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {"folder": self.folder, "as_of": self.as_of,
                "baseline_audit_id": self.baseline_audit_id,
                "baseline_ts": self.baseline_ts,
                "structural": self.structural, "behavioural": self.behavioural,
                "too_thin": self.too_thin, "window_n": self.window_n,
                "no_baseline": self.no_baseline,
                "structural_unmeasured": self.structural_unmeasured,
                "needs_rebaseline": self.needs_rebaseline, "ok": self.ok}


def _shares(hist: dict[str, int]) -> dict[str, float]:
    total = sum(hist.values()) or 1
    return {k: v / total for k, v in hist.items()}


def _share_drift(name: str, base_hist: dict[str, int], now_hist: dict[str, int],
                 limit: float) -> list[dict]:
    base_s, now_s = _shares(base_hist or {}), _shares(now_hist or {})
    out = []
    for key in sorted(set(base_s) | set(now_s)):
        delta = abs(now_s.get(key, 0.0) - base_s.get(key, 0.0))
        if delta > limit:
            out.append({"metric": f"{name}:{key}",
                        "baseline_share": round(base_s.get(key, 0.0), 4),
                        "current_share": round(now_s.get(key, 0.0), 4),
                        "delta": round(delta, 4), "threshold": limit})
    return out


def _is_set_like(value: Any) -> bool:
    return isinstance(value, (list, tuple, set, frozenset))


def _structural_drift(base: Mapping[str, Any], now: Mapping[str, Any]) -> list[dict]:
    """Every configuration change is a finding; there is no threshold on config.
    Set-like values report ``added``/``removed``; scalars report both sides."""
    out = []
    for k in sorted(set(base) | set(now)):
        b, n = base.get(k), now.get(k)
        if b == n:
            continue
        if _is_set_like(b) and _is_set_like(n):
            out.append({"metric": k,
                        "added": sorted(set(n) - set(b)),
                        "removed": sorted(set(b) - set(n))})
        else:
            out.append({"metric": k, "baseline": b, "current": n})
    return out


def drift_tick(folder: str | Path, *, log_root: str | Path | None = None,
               catalogue_fingerprint: str = "",
               thresholds: DriftThresholds = DEFAULT_THRESHOLDS,
               as_of: Optional[float] = None,
               structural: Optional[Mapping[str, Any]] = None) -> DriftReport:
    """Diff the current operational state against the latest baseline. Pure
    read; see :func:`record_findings`. ``structural=`` overrides the port."""
    log = MutationLog(folder, log_root=log_root)
    as_of = as_of if as_of is not None else time.time()
    report = DriftReport(folder=str(folder), as_of=as_of)

    found = _latest_baseline(log)
    if found is None:
        report.no_baseline = True
        return report
    base_event, base_state = found
    report.baseline_audit_id = base_event.audit_id
    report.baseline_ts = base_event.ts

    window = [e for e in log.replay()
              if e.ts > base_event.ts and e.ts <= as_of
              and e.pair_id not in (_BASELINE_KIND, _FINDING_KIND)]
    mix_now = _behaviour_mix(window)
    report.window_n = mix_now["n"]

    now_struct = _resolve_structural(folder, structural)
    base_struct = base_state.get("structural")
    if now_struct is None or base_struct is None:
        report.structural_unmeasured = True
        return report

    report.structural.extend(_structural_drift(base_struct, now_struct))
    b_cat = base_state.get("catalogue_fingerprint", "")
    if catalogue_fingerprint != b_cat:
        report.structural.append(
            {"metric": "catalogue_fingerprint",
             "baseline": b_cat, "current": catalogue_fingerprint})

    if mix_now["n"] < thresholds.min_events:
        report.too_thin = True
        return report
    mix_base = base_state.get("behaviour", {})
    for name in ("by_event", "by_channel", "by_actor_kind", "by_skill"):
        report.behavioural.extend(_share_drift(
            name, mix_base.get(name, {}), mix_now.get(name, {}),
            thresholds.share_shift))
    return report


def record_findings(report: DriftReport, *, log_root: str | Path | None = None,
                    actor: str = "system") -> list[str]:
    """One ``drift-finding`` event per finding, keyed by
    ``(baseline_audit_id, metric)`` and written at most once."""
    if not report.findings:
        return []
    log = MutationLog(report.folder, log_root=log_root)
    seen = set()
    for e in log.replay():
        x = e.extra or {}
        if x.get("kind") == _FINDING_KIND:
            seen.add((x.get("baseline_audit_id"), x.get("metric")))
    out = []
    for f in report.findings:
        key = (report.baseline_audit_id, f["metric"])
        if key in seen:
            continue
        out.append(log.append(LogEvent(
            event="system", folder_path=report.folder, pair_id=_FINDING_KIND,
            channel="system", actor=actor,
            extra={"kind": _FINDING_KIND,
                   "baseline_audit_id": report.baseline_audit_id,
                   "metric": f["metric"], "finding": f})))
    return out


FINDING_OPTIONS = ("within-envelope", "reassess", "halt")


def finding_surface(report: DriftReport):
    """Route the findings to a human as a residual choice among three options,
    none recommended. Through the ``build_surface`` port when bound; otherwise
    the surface spec is returned as a dict."""
    if not report.findings:
        raise ValueError("no findings — nothing to decide")
    detail = "; ".join(f["metric"] for f in report.findings)
    spec = dict(
        query=(f"Operational drift detected against baseline "
               f"{report.baseline_audit_id} in folder {report.folder}"),
        candidates=[
            {"id": "within-envelope",
             "label": "Within the assessed envelope — re-baseline",
             "conclusion": "The change is anticipated adaptive behaviour; "
                           "record why and set a new baseline.",
             "consequences": ["a new drift-baseline event is written",
                              "the rationale becomes part of the audit chain"]},
            {"id": "reassess",
             "label": "Outside the envelope — reassess before continuing",
             "conclusion": "The change may affect the assessed risk profile; "
                           "rerun the risk assessment for this folder.",
             "consequences": ["folder stays operational",
                              "reassessment is tracked as an open obligation"]},
            {"id": "halt",
             "label": "Halt the folder pending review",
             "conclusion": "Suspend autonomous operation in this folder until "
                           "a human review completes.",
             "consequences": ["agentic dispatch should be refused by the host",
                              "interactive use may continue"]},
        ],
        esc_reason=f"drift findings: {detail}",
        context="The choice and its recorded rationale are the documented "
                "determination procedure.")
    port = globals()["build_surface"]
    if port is None:
        return spec
    return port(**spec)
