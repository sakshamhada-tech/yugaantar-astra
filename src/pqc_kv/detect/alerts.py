"""The alert object, and why its shape is a security control.

An alert is the one place log text re-enters the world as prose. If
``actor="user-a\\n[ALERT] root login"`` reached an explanation verbatim, the
operator's terminal would show two alerts -- one forged. So:

* every value in an alert was validated at ingest by :mod:`fields` (bounded,
  printable ASCII, no newlines or quotes);
* the *structure* of an alert is a fixed set of keys defined here, never derived
  from input;
* explanations are assembled from those validated values by f-strings in rule
  code, with no format string ever taken from input;
* :meth:`Alert.to_dict` re-asserts the key policy before emitting.

Ids are content-derived, so the same log always yields the same alert ids in the
same order. That makes "same input gives identical output" testable by comparing
bytes, and it means a re-run cannot be mistaken for new activity.
"""

from __future__ import annotations

import hashlib
import json

from . import fields as F

#: Severity vocabulary. Ordering is used for thresholds and reporting.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

#: Every field an alert may carry. A future rule that wants a new field adds it
#: here deliberately, which is the point: the schema is closed.
ALERT_KEYS = (
    "alert_id", "rule", "severity", "identity", "services", "event_ids",
    "event_time", "explanation", "order", "facts", "goal", "path",
)


class Alert:
    """One explainable detection. Immutable after construction."""

    __slots__ = (
        "alert_id", "rule", "severity", "identity", "services", "event_ids",
        "event_ms", "explanation", "order", "facts", "goal", "path",
    )

    def __init__(
        self,
        *,
        rule: str,
        severity: str,
        identity: str,
        services,
        event_ids,
        event_ms: int,
        explanation: str,
        order: str,
        facts: dict,
        goal: int,
        path=(),
    ) -> None:
        F.safe_key(rule)
        if severity not in SEVERITY_ORDER:
            raise F.FieldError(F.Reason.BAD_FIELD)
        self.rule = rule
        self.severity = severity
        self.identity = identity
        self.services = tuple(services)
        self.event_ids = tuple(event_ids)
        self.event_ms = event_ms
        self.explanation = explanation
        self.order = order
        self.facts = dict(facts)
        self.goal = int(goal)
        self.path = tuple(path)
        self.alert_id = self._derive_id()

    def _derive_id(self) -> str:
        """Content-derived id: same detection, same id, every run."""
        payload = {
            "rule": self.rule,
            "identity": self.identity,
            "events": list(self.event_ids),
            "services": list(self.services),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "al-" + hashlib.sha256(blob.encode("ascii")).hexdigest()[:16]

    # ------------------------------------------------------------------ output
    def to_dict(self) -> dict:
        out = {
            "alert_id": self.alert_id,
            "rule": self.rule,
            "severity": self.severity,
            "identity": self.identity,
            "services": list(self.services),
            "event_ids": list(self.event_ids),
            "event_time": F.format_timestamp(self.event_ms),
            "explanation": self.explanation,
            "order": self.order,
            "facts": self.facts,
            "goal": self.goal,
            "path": list(self.path),
        }
        for key in out:
            F.safe_key(key)
        return out

    def sort_key(self):
        """Deterministic ordering: event time, then rule, then id.

        Event time first so a report reads as a timeline. Rule and id break ties so
        two alerts at the same millisecond never swap places between runs.
        """
        return (self.event_ms, self.rule, self.alert_id)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Alert {self.rule} {self.alert_id} events={list(self.event_ids)}>"


def dedupe(alerts) -> list:
    """Drop duplicate ids, keep first occurrence, then sort."""
    seen = {}
    for alert in alerts:
        if alert.alert_id not in seen:
            seen[alert.alert_id] = alert
    return sorted(seen.values(), key=lambda a: a.sort_key())


__all__ = ["ALERT_KEYS", "Alert", "SEVERITY_ORDER", "dedupe"]
