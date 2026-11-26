"""The detector: one entry point, one deterministic ordering, one report.

Pipeline for a whole log in one call:

1. **ingest** -- strict parse, quarantine and count everything malformed;
2. **timeline** -- correct per-source clocks, put events in corrected order inside a
   bounded reorder buffer, and remember the per-source uncertainty;
3. **context** -- load approvals;
4. **baseline** -- build each identity's service graph from the earliest fraction;
5. **rules** -- goal 6 (privilege + approval context) and goal 7 (graph novelty),
   both consulting goal 8's timeline before claiming any sequence;
6. **dedupe + sort** -- by event time, rule, id, so two runs are byte-identical.

Everything the caller needs to audit the run is in the returned report: counts of
what was refused and why, the supported timing range, every source's applied offset
and residual uncertainty, and the alerts themselves.

Bounded by construction
-----------------------
``max_events`` caps the log, the reorder buffer caps memory, the sample lists cap
the report, and each identity's baseline stores sets of edges rather than events.
Feeding a 100 GB file therefore fails at the size check instead of at the OOM killer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import context as ctx
from . import fields as F
from .alerts import dedupe
from .config import DetectorConfig
from .ingest import parse_csv
from .lateral import LateralDetector
from .privilege import PrivilegeDetector
from .timing import Timeline

#: Report shape version. Bumped when the report's meaning changes, so a stored
#: report can never be silently re-read under new semantics.
REPORT_VERSION = 1


@dataclass
class DetectionReport:
    alerts: list = field(default_factory=list)
    ingest: dict = field(default_factory=dict)
    timing: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    baseline: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "report_version": REPORT_VERSION,
            "alerts": [a.to_dict() for a in self.alerts],
            "counts": self.counts,
            "ingest": self.ingest,
            "timing": self.timing,
            "context": self.context,
            "baseline": self.baseline,
        }


def run(
    log_text: str,
    *,
    approvals=None,
    config: DetectorConfig | None = None,
) -> DetectionReport:
    """Run the whole detector over one log. Pure function of its arguments.

    ``approvals`` may be a JSON string, a parsed dict, or a
    :class:`context.Context`. With ``None`` the detector still works: every
    privilege change is then unapproved by definition, which is the correct reading
    of "no change control supplied" rather than a crash or a blanket pass.
    """
    cfg = (config or DetectorConfig()).validate()

    ingest = parse_csv(log_text, config=cfg)
    timeline = Timeline(config=cfg.timing)
    ordered, deferred = timeline.reorder(ingest.events)
    # Deferred events are NOT discarded. Dropping them would be the worst possible
    # answer: their order is unknown, so a sequence rule must not be confident about
    # them -- but the events themselves still happened, and an identity that only
    # appears among stragglers would otherwise be invisible. They are analysed in
    # receipt order after everything that could be sequenced, and every rule that
    # asks about order gets "uncertain" from the timeline rather than a guess.
    analysis_order = ordered + list(deferred)

    context = _load_context(approvals)

    privilege = PrivilegeDetector(cfg, timeline, context)
    lateral = LateralDetector(cfg, timeline, context)
    lateral.build_baseline(analysis_order)

    alerts: list = []
    alerts.extend(privilege.evaluate(analysis_order))
    alerts.extend(lateral.evaluate(analysis_order))
    alerts = dedupe(alerts)

    report = DetectionReport(alerts=alerts)
    report.ingest = {
        "events_accepted": len(ingest.events),
        "events_rejected": ingest.rejected_total,
        "rejected_by_reason": dict(sorted(ingest.rejected.items())),
        "rejected_samples": [list(s) for s in ingest.rejected_samples],
        "header": list(ingest.header),
        "truncated": ingest.truncated,
        "total_lines_seen": ingest.total_lines_seen,
        "events_deferred_by_reorder": len(deferred),
    }
    report.timing = timeline.report()
    report.context = context.report()
    report.baseline = _baseline_report(lateral)
    report.counts = _counts(alerts, lateral, ingest)
    return report


def run_bytes(data: bytes, *, approvals=None, config: DetectorConfig | None = None):
    """Byte input. A non-UTF-8 log is one counted refusal, not an exception."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        report = DetectionReport()
        report.ingest = {
            "events_accepted": 0,
            "events_rejected": 1,
            "rejected_by_reason": {F.Reason.BAD_ENCODING: 1},
            "rejected_samples": [[0, F.Reason.BAD_ENCODING]],
            "header": [],
            "truncated": False,
            "total_lines_seen": 0,
            "events_deferred_by_reorder": 0,
        }
        report.timing = Timeline(config=(config or DetectorConfig()).timing).report()
        report.context = {"approvals": 0, "rejected": {}}
        report.baseline = {"identities": 0, "cold_start": 0, "established": 0}
        report.counts = {"alerts": 0, "by_rule": {}, "by_severity": {}, "by_goal": {}}
        return report
    return run(text, approvals=approvals, config=config)


def _load_context(approvals) -> ctx.Context:
    """Load the approvals, distinguishing "none" from "unreadable".

    Both end up with an empty context -- detection must still run -- but the second
    is reported as ``document_error`` so an operator is not left wondering why every
    privilege change is suddenly unapproved.
    """
    if approvals is None:
        return ctx.Context()
    if isinstance(approvals, ctx.Context):
        return approvals

    def failed(reason: str) -> ctx.Context:
        return ctx.Context(document_error=reason)

    if isinstance(approvals, dict):
        try:
            return ctx.Context.from_obj(approvals)
        except ctx.ApprovalError as exc:
            return failed(exc.reason)
    if isinstance(approvals, (str, bytes)):
        try:
            text = approvals.decode("utf-8") if isinstance(approvals, bytes) else approvals
        except UnicodeDecodeError:
            return failed("approvals_not_utf8")
        try:
            return ctx.Context.from_json(text)
        except ctx.ApprovalError as exc:
            return failed(exc.reason)
    return failed("approvals_wrong_type")


def _baseline_report(lateral: LateralDetector) -> dict:
    cold = 0
    established = 0
    for graph in lateral.graphs.values():
        if graph.events < lateral.config.lateral.min_baseline_events:
            cold += 1
        else:
            established += 1
    graphs = {
        identity: {
            "events": graph.events,
            "edges": [list(edge) for edge in sorted(graph.edges)],
            "targets": sorted(graph.targets),
        }
        for identity, graph in lateral.graphs.items()
    }
    return {
        "identities": len(lateral.graphs),
        "established": established,
        "cold_start": cold,
        "baseline_cutoff_ms": lateral.baseline_cutoff_ms,
        "min_baseline_events": lateral.config.lateral.min_baseline_events,
        "baseline_fraction_percent": lateral.config.lateral.baseline_fraction_percent,
        #: Per-identity summary, used by ``detect_append`` to persist a baseline
        #: across processes. Counts and membership only: no raw log text is stored,
        #: so a persisted baseline cannot smuggle a hostile string back in.
        "graphs": graphs,
    }


def _counts(alerts, lateral: LateralDetector, ingest) -> dict:
    by_rule: dict = {}
    by_severity: dict = {}
    by_goal: dict = {}
    for alert in alerts:
        by_rule[alert.rule] = by_rule.get(alert.rule, 0) + 1
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        key = f"goal_{alert.goal}"
        by_goal[key] = by_goal.get(key, 0) + 1
    return {
        "alerts": len(alerts),
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_goal": dict(sorted(by_goal.items())),
        "events_accepted": len(ingest.events),
        "events_rejected": ingest.rejected_total,
    }


__all__ = ["DetectionReport", "REPORT_VERSION", "run", "run_bytes"]
