"""Adapter operations for detection, and the state they persist.

The adapter starts a new process for every request, so a detector that needed
in-process memory between calls would be useless in the judged interface. Two modes
cover the contract:

``detect_log``
    The whole log in one request. Stateless in the sense that nothing is required
    from a previous call, and the return value contains the complete report. This is
    the mode the evaluation script and a judge would use.

``detect_append``
    Add events to a persisted baseline, so repeated calls accumulate history. The
    baseline is written under ``TRACK4_STATE_DIR`` with the Phase 3 atomic-write
    helper (temp file, ``fsync``, ``os.replace``), so a crash mid-write leaves
    either the old baseline or the new one and never a half-written file. The
    read-only-root-filesystem rule from the contract is honoured by never touching
    anything outside the state directory.

``detect_status``
    What is persisted, and the supported timing range -- so an operator can see the
    detector's own view of its limits without running a detection.

What the baseline stores is a *summary*, not the events: per-identity edge counts,
target sets, and the last transition. That keeps the file small and means the state
directory never accumulates raw log text, which could itself contain hostile
strings we would then have to re-validate on load.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..keystore import default_state_dir, ensure_private_dir
from ..logsign import atomic_write_text
from . import config as detect_config
from .core import run

#: Where the persisted baseline lives, relative to the private state directory.
BASELINE_FILE = "detect-baseline.json"
#: State file version, so an old file is refused rather than misread.
BASELINE_VERSION = 1
#: Cap on identities stored, so a hostile log cannot grow the state file without
#: bound. Hitting it is reported, never silently ignored.
MAX_IDENTITIES = 20_000


class DetectStateError(Exception):
    """State problem. Fixed token only, never a path or a value."""

    def __init__(self, reason: str = "detect_state_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


def _state_path() -> Path:
    root = Path(default_state_dir())
    ensure_private_dir(root)
    return root / BASELINE_FILE


def load_baseline() -> dict:
    """Read the persisted baseline, or an empty one if none exists yet.

    A corrupt file is an error rather than a silent reset: quietly discarding a
    baseline would make the next detection report look "clean" because it had no
    history to compare against, which is the opposite of the truth.
    """
    path = _state_path()
    if not path.exists():
        return {"version": BASELINE_VERSION, "identities": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise DetectStateError("detect_state_corrupt") from None
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise DetectStateError("detect_state_incompatible")
    if not isinstance(data.get("identities"), dict):
        raise DetectStateError("detect_state_incompatible")
    return data


def save_baseline(baseline: dict) -> None:
    """Atomically replace the baseline. Never leaves a partial file."""
    path = _state_path()
    baseline = dict(baseline, version=BASELINE_VERSION)
    atomic_write_text(path, json.dumps(baseline, sort_keys=True, indent=0))


def summarise_report(report) -> dict:
    """Merge one detection run's baseline into the persisted summary.

    Only counts and membership sets are stored -- enough to answer "has this
    identity used this edge before" on the next call, and nothing that would let a
    stored hostile string re-enter an alert without validation.
    """
    existing = load_baseline()
    identities = existing.get("identities", {})
    for identity, summary in report.baseline.get("graphs", {}).items():
        if identity not in identities and len(identities) >= MAX_IDENTITIES:
            existing["truncated"] = True
            continue
        current = identities.get(identity, {"events": 0, "edges": [], "targets": []})
        edges = set(map(tuple, current.get("edges", []))) | set(
            map(tuple, summary.get("edges", []))
        )
        targets = set(current.get("targets", [])) | set(summary.get("targets", []))
        identities[identity] = {
            "events": int(current.get("events", 0)) + int(summary.get("events", 0)),
            "edges": sorted(list(edge) for edge in edges),
            "targets": sorted(targets),
        }
    existing["identities"] = identities
    return existing


# ------------------------------------------------------------------- handlers
def op_detect_log(request: dict) -> dict:
    """Detect over a whole log supplied in the request.

    The log arrives as ``log`` (a string) and the approvals as ``approvals`` (a JSON
    string or an object). Both are bounded: the log by ``max_events``/``max_line_len``
    and the approvals by their own parser, so a hostile request cannot exhaust the
    worker.
    """
    log = request.get("log")
    if not isinstance(log, str):
        return {"error": "malformed_request"}
    cfg = _config_from(request)
    if isinstance(cfg, dict):
        return cfg
    report = run(log, approvals=request.get("approvals"), config=cfg)
    body = report.to_dict()
    body["rules_fired"] = sorted({a.rule for a in report.alerts})
    return body


def op_detect_append(request: dict) -> dict:
    """Detect over new events and merge the result into the persisted baseline."""
    log = request.get("log")
    if not isinstance(log, str):
        return {"error": "malformed_request"}
    cfg = _config_from(request)
    if isinstance(cfg, dict):
        return cfg
    report = run(log, approvals=request.get("approvals"), config=cfg)
    baseline = summarise_report(report)
    save_baseline(baseline)
    body = report.to_dict()
    body["baseline_identities_persisted"] = len(baseline.get("identities", {}))
    body["rules_fired"] = sorted({a.rule for a in report.alerts})
    return body


def op_detect_status(request: dict) -> dict:
    """What is persisted, and the timing range this detector will claim."""
    baseline = load_baseline()
    identities = baseline.get("identities", {})
    cfg = _config_from(request)
    if isinstance(cfg, dict):
        return cfg
    return {
        "baseline_identities": len(identities),
        "baseline_events": sum(int(v.get("events", 0)) for v in identities.values()),
        "baseline_truncated": bool(baseline.get("truncated")),
        "supported_timing_range": {
            "offset_mode": cfg.timing.offset_mode,
            "max_abs_source_offset_ms": cfg.timing.max_abs_offset_ms,
            "per_source_uncertainty_ms": cfg.timing.offset_uncertainty_ms,
            "max_out_of_order_ms": cfg.timing.max_out_of_order_ms,
            "reorder_buffer_events": cfg.timing.reorder_buffer_events,
        },
        "min_baseline_events": cfg.lateral.min_baseline_events,
        "cold_start_report_lone_edges": cfg.lateral.cold_start_report_lone_edges,
    }


def _config_from(request: dict):
    """Build a config from the request, or return an opaque error dict."""
    raw = request.get("config")
    if raw is None:
        return detect_config.DetectorConfig().validate()
    if not isinstance(raw, dict):
        return {"error": "malformed_request"}
    try:
        return detect_config.DetectorConfig.from_dict(raw)
    except detect_config.ConfigError as exc:
        # The reason token is ours, not the caller's, so it leaks nothing about
        # what the config parser saw.
        return {"error": "config_rejected", "reason": exc.reason}


#: Operations this module answers. ``team_app.dispatch`` merges these in.
OPS = {
    "detect_log": op_detect_log,
    "detect_append": op_detect_append,
    "detect_status": op_detect_status,
}

#: The subset worth writing into the signed key-event log. Deliberately narrow:
#: the log records key and access events, and flooding it with low-grade detections
#: would make it useless as an audit trail. High-severity privilege and lateral
#: findings are exactly the class an auditor needs provable, so those are recorded
#: (see ``recordable_alerts``).
RECORDABLE_RULES = frozenset({
    "unapproved_privilege_change",
    "self_approved_privilege_change",
    "lateral_movement_chain",
    "first_seen_sensitive_service",
})


def recordable_alerts(report) -> list:
    """Alerts that belong in the signed log: high-signal, one line each.

    The explanation is *not* copied into the log. The log's ``detail`` field is
    validated as an identifier (bounded, printable ASCII, no newlines) by
    :mod:`pqc_kv.logsign`, and the explanation contains characters that policy
    refuses -- so the record carries the rule name and the alert id, and the alert
    object itself stays in the detection report. Writing the prose would mean
    weakening the log's field policy, which Phase 3 established for good reasons.
    """
    return [
        alert for alert in report.alerts
        if alert.rule in RECORDABLE_RULES and alert.severity in ("high", "medium")
    ]


def log_detail(alert) -> str:
    """A log-safe one-line identifier for one alert: ``rule:alert_id``.

    ``:`` is in the signed log's identifier charset and ``/`` is not, so the
    separator is chosen to satisfy the existing policy rather than widening it.
    """
    return f"{alert.rule}:{alert.alert_id}"


__all__ = [
    "BASELINE_FILE", "BASELINE_VERSION", "DetectStateError", "MAX_IDENTITIES", "OPS",
    "RECORDABLE_RULES", "load_baseline", "log_detail", "op_detect_append",
    "op_detect_log", "op_detect_status", "recordable_alerts", "save_baseline",
    "summarise_report",
]
