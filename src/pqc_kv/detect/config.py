"""Detector configuration: every threshold lives here, none in the rule code.

The rule modules read this object and nothing else. That is what makes the claim
"the detector is not tuned to the practice data" checkable: you can change every
value below and the rules still run, and :mod:`tests.test_phase4_config` proves it
by running the whole pipeline against a config that shares no numbers with the
default.

Two deliberate choices:

* **No identity or service names in the defaults.** The lists that would hold them
  start empty. An operator supplies their own; the practice vocabulary never
  reaches the detector's source.
* **Structural signals beat vocabulary.** The most important privilege signal is
  ``role_before != role_after`` -- a property of the data, not of a name. The
  action lists exist only for the cases the schema cannot express that way (a
  revocation where the actor's own role does not change).

Config is data, so it is validated like data: every value is range-checked and
every string validated with the same policy as a log field. A config file is often
written by the same operator who later reads the alerts, and a typo silently
widening a window is a detection failure that looks like a quiet week.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from .fields import FieldError, MAX_OFFSET_MS, validate_ident


class ConfigError(Exception):
    """Bad configuration. The reason is a fixed token, never the offending value."""

    def __init__(self, reason: str = "config_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


def _int(value, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"config_{name}_invalid")
    if not (low <= value <= high):
        raise ConfigError(f"config_{name}_out_of_range")
    return value


def _bool(value, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"config_{name}_invalid")
    return value


def _idents(value, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 512:
        raise ConfigError(f"config_{name}_invalid")
    out = []
    for item in value:
        try:
            out.append(validate_ident(item))
        except FieldError:
            raise ConfigError(f"config_{name}_invalid") from None
    # Sorted and de-duplicated so two runs over the same config never differ in
    # iteration order -- determinism starts before the first event is read.
    return tuple(sorted(set(out)))


@dataclass(frozen=True)
class TimingConfig:
    """Goal 8: what order we are willing to claim.

    ``offset_mode`` decides where the per-source clock correction comes from:

    ``declared``
        Trust ``source_clock_offset_ms`` from the log (the practice format's
        meaning: known offset relative to the collector). Residual uncertainty is
        ``offset_uncertainty_ms`` per source.
    ``estimated``
        Ignore the column and estimate the offset per source from delivery delay
        using a minimum filter (the NTP idea: true delay is never negative, so the
        smallest observed delay bounds the error). Uncertainty grows with the
        observed spread, capped by ``max_offset_uncertainty_ms``.
    ``none``
        No correction at all. Every cross-source comparison is flagged uncertain;
        only same-source ordering is claimed. This is the honest fallback when a
        log has no offset column.
    """

    #: Residual per-source uncertainty under ``declared`` mode. Two events are
    #: claimed ordered only if they differ by more than the *sum* of the two
    #: sources' uncertainties; otherwise the alert carries UNCERTAIN_ORDER.
    offset_uncertainty_ms: int = 250
    #: Upper bound on the uncertainty we will tolerate in ``estimated`` mode before
    #: we stop claiming order for that source at all.
    max_offset_uncertainty_ms: int = 60_000
    #: Largest per-source offset the estimator will accept (matches ingest bound).
    max_abs_offset_ms: int = MAX_OFFSET_MS
    offset_mode: str = "declared"
    #: Reorder buffer: an event is not "final" until a receipt has advanced beyond
    #: its corrected event time by this much, or the buffer holds this many events.
    max_out_of_order_ms: int = 600_000
    reorder_buffer_events: int = 4096
    #: Largest delivery delay we assume possible when bounding a clock estimate.
    max_delivery_delay_ms: int = 300_000

    def validate(self) -> "TimingConfig":
        _int(self.offset_uncertainty_ms, "offset_uncertainty_ms", 0, 3_600_000)
        _int(self.max_offset_uncertainty_ms, "max_offset_uncertainty_ms", 0, 3_600_000)
        _int(self.max_abs_offset_ms, "max_abs_offset_ms", 0, MAX_OFFSET_MS)
        _int(self.max_out_of_order_ms, "max_out_of_order_ms", 0, 86_400_000)
        _int(self.reorder_buffer_events, "reorder_buffer_events", 1, 1_000_000)
        _int(self.max_delivery_delay_ms, "max_delivery_delay_ms", 0, 86_400_000)
        if self.offset_mode not in ("declared", "estimated", "none"):
            raise ConfigError("config_offset_mode_invalid")
        return self


@dataclass(frozen=True)
class PrivilegeConfig:
    """Goal 6: which events count as a privilege change, and how approval matches."""

    #: Structural signal is ``role_before != role_after``; these are the actions
    #: that change privilege *without* the schema showing it (a revocation where
    #: the operator's own role is unchanged). Override for your vocabulary.
    privileged_actions: tuple[str, ...] = (
        "role_change", "grant_role", "revoke_role", "approve_role_change",
        "policy_change", "enrol", "unenrol", "disable_identity",
    )
    #: Actions that carry an approval decision. An approval that merely *authorises*
    #: is context; it is not itself a privilege change.
    authorising_actions: tuple[str, ...] = ("approve_role_change", "approve_change",)
    #: Map a log ``action`` to an approval ``operation``. Empty means "do not check
    #: the operation name" -- better than inventing a mapping for a vocabulary you
    #: have not seen.
    operation_for_action: dict = field(default_factory=dict)
    #: An approval's ``valid_from_utc`` may be slightly *after* the action in event
    #: time and still count as covering it (paperwork filed a little late). Zero
    #: means strict: the approval window must already be open.
    approval_slack_before_ms: int = 0
    #: After ``valid_until_utc`` nothing is covered. Kept at 0 because the practice
    #: README says the bound is exclusive; widening it would silently approve late
    #: actions, which is the failure mode this rule exists to catch.
    approval_slack_after_ms: int = 0
    #: If true, a role name that does not equal the approval's role does not match,
    #: even when subject and time do. Turning this off is a deliberate downgrade.
    require_role_match: bool = True
    #: When an unexplained privilege change is followed by data access in the same
    #: session within this window, raise a follow-on alert.
    follow_on_window_ms: int = 900_000
    #: Emit the follow-on alert at all. It is the rule most likely to be noisy in a
    #: real deployment, so it is switchable rather than clever.
    follow_on_alerts: bool = True

    def validate(self) -> "PrivilegeConfig":
        for name, value in (
            ("privileged_actions", list(self.privileged_actions)),
            ("authorising_actions", list(self.authorising_actions)),
        ):
            _idents(value, name)
        _int(self.approval_slack_before_ms, "approval_slack_before_ms", 0, 86_400_000)
        _int(self.approval_slack_after_ms, "approval_slack_after_ms", 0, 86_400_000)
        _int(self.follow_on_window_ms, "follow_on_window_ms", 0, 86_400_000)
        _bool(self.require_role_match, "require_role_match")
        _bool(self.follow_on_alerts, "follow_on_alerts")
        if not isinstance(self.operation_for_action, dict):
            raise ConfigError("config_operation_for_action_invalid")
        for key, value in self.operation_for_action.items():
            try:
                validate_ident(key)
                validate_ident(value)
            except FieldError:
                raise ConfigError("config_operation_for_action_invalid") from None
        object.__setattr__(
            self, "operation_for_action", dict(sorted(self.operation_for_action.items()))
        )
        object.__setattr__(self, "privileged_actions", tuple(sorted(self.privileged_actions)))
        object.__setattr__(self, "authorising_actions", tuple(sorted(self.authorising_actions)))
        return self


@dataclass(frozen=True)
class LateralConfig:
    """Goal 7: how much history makes an identity's graph trustworthy."""

    #: Fraction of the *tuning* window used to build each identity's baseline graph.
    #: Expressed as a fraction rather than a count so it travels between datasets.
    baseline_fraction_percent: int = 40
    #: An identity with fewer baseline events than this has "insufficient" baseline.
    #: Cold start is a stated state, not a guess: see ``cold_start_*`` below.
    #:
    #: Why 12 and not 5: the number was measured, not chosen. On the synthetic log,
    #: a threshold of 5 produced 25 false alerts from identities with 5-8 baseline
    #: events -- enough events to pass the "established" test and far too few for
    #: novelty to mean anything. Every one was an ordinary read into a service the
    #: identity simply had not needed yet, and ``metrics -> metrics`` was flagged
    #: because even *that* ordered pair had not appeared in eight events. Raising it
    #: to 12 took false alerts to zero on both the tuning and held-out identity
    #: halves without losing a single true positive (14 alerts, 14 true positives,
    #: 0 false), and it left the practice log unchanged at 3 alerts / 3 hits.
    #:
    #: The honest reading: this is the smallest baseline at which "first-seen" was a
    #: meaningful word on the data available. A deployment whose identities are all
    #: new should raise it further and expect one alert per genuinely unusual hop
    #: until the baseline fills.
    min_baseline_events: int = 12
    #: A novel out-of-scope edge needs company before we call it movement. One denial
    #: is one denial; the practice labels say so explicitly.
    min_novel_edges: int = 2
    #: Cold-start identities need more evidence before an alert, because we have no
    #: idea what is normal for them. Deliberately higher than ``min_novel_edges``.
    cold_start_min_novel_edges: int = 3
    #: Emit a LOW-severity notice when a cold-start identity makes a single
    #: successful first-seen edge.
    #:
    #: **Off by default, and that is a measured decision the operator can reverse.**
    #: It is the honest alternative to the two dishonest options (blanket-alarm on
    #: every new principal, or silently trust one), and it is implemented and tested.
    #: But on the synthetic log it produced 20 false alerts against 3 true positives,
    #: because an identity with four baseline events has no "normal" to depart from
    #: and the notice fires on its first ordinary read. Silence is not the same as
    #: trust here: such an identity is marked ``cold_start`` in the run report, and
    #: the run reports ``cold_start`` counts so an operator can see how much of their
    #: estate is unbaselined. Turn this on when you would rather see the noise.
    cold_start_report_lone_edges: bool = False
    #: Novel edges count as one sequence only if they fall within this span (event
    #: time). Keeps a month of sporadic one-off denials from becoming "movement".
    burst_window_ms: int = 900_000
    #: A --source-> target transition is "new" if the ordered pair was never seen
    #: for that identity in the baseline, even when both ends are familiar.
    transition_window_ms: int = 300_000
    #: Operator-supplied high-value targets. Empty by default: the detector must not
    #: know that ``billing`` is interesting. Populate with your own.
    sensitive_services: tuple[str, ...] = ()
    #: Targets covered by an approval scope count as authorised even on first sight:
    #: novelty alone is not evidence of abuse.
    approval_scope_grants_authorisation: bool = True
    #: A single *successful* novel out-of-scope edge may alert on its own, because
    #: valid credentials reaching a new service is exactly the scenario goal 7
    #: names. A single *denied* edge never does: one denial is not movement.
    alert_on_allowed_novel_edges: bool = True
    #: Ordering between two already-familiar services. This is the lowest-value rule
    #: (it needs a baseline of transitions, and in a small log almost everything is
    #: "new"), so it is OFF by default. Turn it on for a mature deployment with a
    #: long baseline; the rule is implemented and tested either way.
    emit_novel_transitions: bool = False

    def validate(self) -> "LateralConfig":
        _int(self.baseline_fraction_percent, "baseline_fraction_percent", 1, 99)
        _int(self.min_baseline_events, "min_baseline_events", 1, 100_000)
        _int(self.min_novel_edges, "min_novel_edges", 1, 1_000)
        _int(self.cold_start_min_novel_edges, "cold_start_min_novel_edges", 1, 1_000)
        _bool(self.cold_start_report_lone_edges, "cold_start_report_lone_edges")
        _int(self.burst_window_ms, "burst_window_ms", 1, 86_400_000)
        _int(self.transition_window_ms, "transition_window_ms", 1, 86_400_000)
        _bool(self.approval_scope_grants_authorisation, "approval_scope_grants_authorisation")
        _bool(self.alert_on_allowed_novel_edges, "alert_on_allowed_novel_edges")
        _bool(self.emit_novel_transitions, "emit_novel_transitions")
        _idents(list(self.sensitive_services), "sensitive_services")
        object.__setattr__(self, "sensitive_services", tuple(sorted(self.sensitive_services)))
        return self


@dataclass(frozen=True)
class IngestConfig:
    """Bounds on hostile input. Not tuning knobs -- changing these changes safety."""

    max_events: int = 1_000_000
    max_line_len: int = 65_536
    #: Event ids are evidence. Duplicates mean two different records claim one id,
    #: which is unambiguous tampering or a broken collector, so they are quarantined
    #: rather than merged.
    reject_duplicate_event_ids: bool = True

    def validate(self) -> "IngestConfig":
        _int(self.max_events, "max_events", 1, 10_000_000)
        _int(self.max_line_len, "max_line_len", 256, 16_777_216)
        _bool(self.reject_duplicate_event_ids, "reject_duplicate_event_ids")
        return self


@dataclass(frozen=True)
class DetectorConfig:
    timing: TimingConfig = field(default_factory=TimingConfig)
    privilege: PrivilegeConfig = field(default_factory=PrivilegeConfig)
    lateral: LateralConfig = field(default_factory=LateralConfig)
    ingest: IngestConfig = field(default_factory=IngestConfig)
    #: Columns expected in the log header. Overriding this is a different schema,
    #: not a tweak.
    columns: tuple[str, ...] = (
        "event_id", "event_time_utc", "received_time_utc", "source_clock_offset_ms",
        "actor", "source_service", "target_service", "action", "role_before",
        "role_after", "outcome", "approval_id", "session_id", "correlation_id",
    )
    #: Alert severities are assigned by rule, and this map is what an operator sees.
    severity_floor: str = "low"

    def validate(self) -> "DetectorConfig":
        self.timing.validate()
        self.privilege.validate()
        self.lateral.validate()
        self.ingest.validate()
        _idents(list(self.columns), "columns")
        if self.severity_floor not in ("low", "medium", "high"):
            raise ConfigError("config_severity_floor_invalid")
        object.__setattr__(self, "columns", tuple(sorted(self.columns)))
        return self

    # ------------------------------------------------------------- serialise
    def to_dict(self) -> dict:
        return {
            "columns": sorted(self.columns),
            "severity_floor": self.severity_floor,
            "ingest": {
                "max_events": self.ingest.max_events,
                "max_line_len": self.ingest.max_line_len,
                "reject_duplicate_event_ids": self.ingest.reject_duplicate_event_ids,
            },
            "timing": {
                "offset_mode": self.timing.offset_mode,
                "offset_uncertainty_ms": self.timing.offset_uncertainty_ms,
                "max_offset_uncertainty_ms": self.timing.max_offset_uncertainty_ms,
                "max_abs_offset_ms": self.timing.max_abs_offset_ms,
                "max_out_of_order_ms": self.timing.max_out_of_order_ms,
                "reorder_buffer_events": self.timing.reorder_buffer_events,
                "max_delivery_delay_ms": self.timing.max_delivery_delay_ms,
            },
            "privilege": {
                "privileged_actions": list(self.privilege.privileged_actions),
                "authorising_actions": list(self.privilege.authorising_actions),
                "operation_for_action": dict(self.privilege.operation_for_action),
                "approval_slack_before_ms": self.privilege.approval_slack_before_ms,
                "approval_slack_after_ms": self.privilege.approval_slack_after_ms,
                "require_role_match": self.privilege.require_role_match,
                "follow_on_window_ms": self.privilege.follow_on_window_ms,
                "follow_on_alerts": self.privilege.follow_on_alerts,
            },
            "lateral": {
                "baseline_fraction_percent": self.lateral.baseline_fraction_percent,
                "min_baseline_events": self.lateral.min_baseline_events,
                "min_novel_edges": self.lateral.min_novel_edges,
                "cold_start_min_novel_edges": self.lateral.cold_start_min_novel_edges,
                "cold_start_report_lone_edges": self.lateral.cold_start_report_lone_edges,
                "burst_window_ms": self.lateral.burst_window_ms,
                "transition_window_ms": self.lateral.transition_window_ms,
                "sensitive_services": list(self.lateral.sensitive_services),
                "approval_scope_grants_authorisation":
                    self.lateral.approval_scope_grants_authorisation,
                "alert_on_allowed_novel_edges": self.lateral.alert_on_allowed_novel_edges,
                "emit_novel_transitions": self.lateral.emit_novel_transitions,
            },
        }

    # ------------------------------------------------------------ construct
    @classmethod
    def from_dict(cls, data: dict) -> "DetectorConfig":
        """Build from a plain dict. Unknown keys are refused, not ignored.

        Ignoring an unknown key is how a typo becomes a silently unapplied
        threshold: the operator thinks they raised ``min_novel_edges`` and did not.
        """
        if not isinstance(data, dict):
            raise ConfigError("config_invalid")
        known = {"columns", "severity_floor", "ingest", "timing", "privilege", "lateral"}
        unknown = set(data) - known
        if unknown:
            raise ConfigError("config_unknown_key")

        def section(name, klass, default):
            raw = data.get(name)
            if raw is None:
                return default()
            if not isinstance(raw, dict):
                raise ConfigError(f"config_{name}_invalid")
            allowed = {f for f in klass.__dataclass_fields__}
            if set(raw) - allowed:
                raise ConfigError(f"config_{name}_invalid")
            base = default()
            fields = {k: raw[k] for k in raw}
            if "privileged_actions" in fields:
                fields["privileged_actions"] = tuple(fields["privileged_actions"])
            if "authorising_actions" in fields:
                fields["authorising_actions"] = tuple(fields["authorising_actions"])
            if "sensitive_services" in fields:
                fields["sensitive_services"] = tuple(fields["sensitive_services"])
            try:
                return replace(base, **fields)
            except TypeError:
                raise ConfigError(f"config_{name}_invalid") from None

        config = cls(
            timing=section("timing", TimingConfig, TimingConfig),
            privilege=section("privilege", PrivilegeConfig, PrivilegeConfig),
            lateral=section("lateral", LateralConfig, LateralConfig),
            ingest=section("ingest", IngestConfig, IngestConfig),
        )
        if "columns" in data:
            config = replace(config, columns=tuple(data["columns"]))
        if "severity_floor" in data:
            config = replace(config, severity_floor=data["severity_floor"])
        return config.validate()

    @classmethod
    def from_file(cls, path) -> "DetectorConfig":
        raw = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except ValueError:
            raise ConfigError("config_not_json") from None
        return cls.from_dict(data)


def load(path=None) -> DetectorConfig:
    """Default config, or one loaded from ``path``. Never silently falls back."""
    if path is None:
        return DetectorConfig().validate()
    return DetectorConfig.from_file(path)


__all__ = [
    "ConfigError", "DetectorConfig", "IngestConfig", "LateralConfig",
    "PrivilegeConfig", "TimingConfig", "load",
]
