"""Goal 7: lateral movement with valid credentials.

The hard part of this rule is *restraint*: most first-seen edges are benign. So the
negative tests here matter more than the positive ones, and the cold-start tests
pin a policy that could otherwise be quietly changed into either "trust everything
new" or "alert on every new identity".
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from pqc_kv.detect import context as ctx
from pqc_kv.detect.config import DetectorConfig, LateralConfig
from pqc_kv.detect.ingest import parse_csv
from pqc_kv.detect.lateral import (
    BASELINE_COLD, BASELINE_KNOWN, LateralDetector, R_LATERAL_CHAIN, R_NOVEL_EDGE,
    R_NOVEL_TRANSITION, R_SENSITIVE_EDGE,
)
from pqc_kv.detect.timing import Timeline

HEADER = (
    "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
    "source_service,target_service,action,role_before,role_after,outcome,"
    "approval_id,session_id,correlation_id"
)

APPROVALS = """{"changes": [
  {"approval_id": "chg-1", "approved_by": "ops-1", "subject": "alice",
   "operation": "grant_role", "role": "analyst", "scope": ["warehouse"],
   "valid_from_utc": "2026-01-15T08:00:00Z", "valid_until_utc": "2026-01-15T12:00:00Z"},
  {"approval_id": "chg-expired", "approved_by": "ops-1", "subject": "bob",
   "operation": "grant_role", "role": "analyst", "scope": ["vault"],
   "valid_from_utc": "2026-01-14T08:00:00Z", "valid_until_utc": "2026-01-14T12:00:00Z"}
]}"""


def row(event_id, minute, actor, source, target, *, outcome="allow", session="s1",
        action="read", role="reader", approval=""):
    """A row at ``minute`` past 09:00 on 2026-01-15."""
    hour = 9 + minute // 60
    mins = minute % 60
    at = f"2026-01-15T{hour:02d}:{mins:02d}:00.000Z"
    received = at.replace(".000Z", ".100Z")
    return (f"{event_id},{at},{received},0,{actor},{source},{target},{action},"
            f"{role},{role},{outcome},{approval},{session},c-{event_id}")


def baseline_rows(actor, source, target, count, *, start=0, session="base"):
    return [row(f"b-{actor}-{start + i}", start + i, actor, source, target,
                session=session) for i in range(count)]


def run(rows, *, approvals=APPROVALS, **lateral_overrides):
    config = DetectorConfig(
        lateral=LateralConfig(**lateral_overrides).validate()
    ).validate()
    log = HEADER + "\n" + "\n".join(rows) + "\n"
    parsed = parse_csv(log, config=config)
    timeline = Timeline(config=config.timing)
    ordered, deferred = timeline.reorder(parsed.events)
    context = ctx.Context.from_json(approvals) if approvals else ctx.Context()
    detector = LateralDetector(config, timeline, context)
    everything = ordered + list(deferred)
    detector.build_baseline(everything)
    return detector.evaluate(everything)


def established(actor="worker", source="gateway", target="index", count=60):
    """Enough history that the identity is established, not cold-started.

    The baseline is the earliest ``baseline_fraction_percent`` (40%) of events by
    time, so 30 baseline rows against one evaluation row gives roughly a dozen
    baseline events for this identity -- comfortably above ``min_baseline_events``.
    Using only a handful here made every test take the cold-start path, which is a
    different policy. The count has to be generous because the baseline is only the
    earliest 40% of the log: 60 baseline rows against 1-3 evaluation rows yields
    roughly 24 baseline events, comfortably above ``min_baseline_events`` (12).
    """
    return baseline_rows(actor, source, target, count)


# ------------------------------------------------------------------ positive
def test_a_first_seen_edge_alerts():
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    alerts = run(rows)
    assert R_NOVEL_EDGE in {a.rule for a in alerts}


def test_an_established_identity_is_reported_as_such():
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    alert = next(a for a in run(rows) if a.rule == R_NOVEL_EDGE)
    assert alert.facts["baseline_state"] == BASELINE_KNOWN
    assert alert.facts["baseline_events_for_identity"] >= 10


def test_the_alert_carries_the_identity_services_and_event_ids():
    """Goal 7 requires each alert to name all three."""
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    alert = next(a for a in run(rows) if a.rule == R_NOVEL_EDGE)
    assert alert.identity == "worker"
    assert "vault" in alert.services
    assert alert.event_ids == ("x-1",)


def test_the_alert_states_how_many_baseline_events_used_the_edge():
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    alert = next(a for a in run(rows) if a.rule == R_NOVEL_EDGE)
    assert alert.facts["baseline_edge_uses"] == 0
    assert "0 of" in alert.explanation


def test_a_chained_walk_alerts_as_one_alert_not_three():
    rows = established() + [
        row("x-1", 100, "worker", "gateway", "vault"),
        row("x-2", 101, "worker", "vault", "warehouse"),
        row("x-3", 102, "worker", "warehouse", "directory"),
    ]
    alerts = [a for a in run(rows) if a.rule == R_LATERAL_CHAIN]
    assert len(alerts) == 1
    assert set(alerts[0].event_ids) == {"x-1", "x-2", "x-3"}
    assert list(alerts[0].path) == ["gateway", "vault", "warehouse", "directory"]


def test_a_chain_alert_reports_the_hops_that_used_a_fresh_foothold():
    rows = established() + [
        row("x-1", 100, "worker", "gateway", "vault"),
        row("x-2", 101, "worker", "vault", "warehouse"),
    ]
    alert = next(a for a in run(rows) if a.rule == R_LATERAL_CHAIN)
    assert alert.facts["chained_hops"] >= 1


def test_a_denied_chain_is_reported_as_attempts_not_compromise():
    """The practice data's own caution: denials do not prove access happened."""
    rows = established() + [
        row("x-1", 100, "worker", "gateway", "vault", outcome="deny"),
        row("x-2", 101, "worker", "vault", "warehouse", outcome="deny"),
    ]
    alert = next(a for a in run(rows) if a.rule == R_LATERAL_CHAIN)
    assert alert.facts["outcomes"] == ["deny"]
    assert "compromise" not in alert.explanation.lower()


def test_a_sensitive_service_target_alerts_on_first_sight():
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    alert = next(a for a in run(rows, sensitive_services=("vault",))
                 if a.rule == R_SENSITIVE_EDGE)
    assert alert.facts["sensitive_target"] == "vault"


# ------------------------------------------------------------------ negative
def test_a_known_edge_does_not_alert():
    rows = established() + [row("x-1", 100, "worker", "gateway", "index")]
    assert run(rows) == []


def test_a_single_denied_new_edge_is_not_movement():
    """The practice README says so explicitly about an isolated denial."""
    rows = established() + [
        row("x-1", 100, "worker", "gateway", "vault", outcome="deny"),
    ]
    assert [a for a in run(rows) if a.rule == R_LATERAL_CHAIN] == []


def test_two_parallel_denials_from_one_place_are_not_a_chain():
    """Two new targets, both reached directly from the same origin: no foothold used."""
    rows = established() + [
        row("x-1", 100, "worker", "gateway", "vault", outcome="deny"),
        row("x-2", 101, "worker", "gateway", "warehouse", outcome="deny"),
    ]
    assert [a for a in run(rows) if a.rule == R_LATERAL_CHAIN] == []


def test_one_successful_new_edge_alerts_once_not_twice():
    """A lone allowed novel edge is worth one alert; duplicates train operators to ignore."""
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    alerts = run(rows)
    assert len(alerts) == 1


def test_new_edges_spread_far_apart_in_time_are_not_one_sequence():
    rows = established() + [
        row("x-1", 100, "worker", "gateway", "vault"),
        row("x-2", 100 + 60, "worker", "vault", "warehouse"),
    ]
    # burst_window_ms default is 15 min; this pair is an hour apart
    assert [a for a in run(rows) if a.rule == R_LATERAL_CHAIN] == []


def test_a_new_edge_covered_by_an_in_force_approval_is_authorised():
    rows = baseline_rows("alice", "gateway", "index", 60) + [
        row("x-1", 100, "alice", "gateway", "warehouse")
    ]
    assert [a for a in run(rows) if a.rule in (R_NOVEL_EDGE, R_LATERAL_CHAIN)] == []


def test_an_expired_approval_does_not_cover_a_new_edge():
    """The difference between an approved rollout and a kept-old-ticket."""
    rows = baseline_rows("bob", "gateway", "index", 60) + [
        row("x-1", 100, "bob", "gateway", "vault")
    ]
    assert R_NOVEL_EDGE in {a.rule for a in run(rows)}


def test_without_approvals_the_detector_still_works():
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    assert R_NOVEL_EDGE in {a.rule for a in run(rows, approvals=None)}


# --------------------------------------------------------------- cold start
def test_a_cold_identity_is_never_reported_as_established():
    """Policy: an unbaselined identity is marked, and any alert says so.

    With the default configuration a lone first-seen edge from a cold identity is
    not emitted -- it is noise, measured at 20 false alerts against 3 true
    positives. What must hold either way: nothing about a cold identity is ever
    presented as if its baseline were known.
    """
    rows = [
        row("c-1", 0, "newbie", "gateway", "index"),
        row("x-1", 10, "newbie", "gateway", "vault"),
    ]
    for alert in run(rows):
        assert alert.facts.get("baseline_state") != BASELINE_KNOWN


def test_a_cold_identity_notice_can_be_switched_on_and_is_low_severity():
    """The option exists, is off by default, and is quiet when enabled."""
    rows = [
        row("c-1", 0, "newbie", "gateway", "index"),
        row("x-1", 10, "newbie", "gateway", "vault"),
    ]
    alerts = run(rows, cold_start_report_lone_edges=True)
    notices = [
        a for a in alerts
        if a.facts.get("notice_reason") == "insufficient_baseline"
    ]
    assert notices, "the cold-start notice must be available when enabled"
    assert all(a.severity == "low" for a in notices)


def test_a_cold_identity_with_a_full_chain_still_alerts():
    """Insufficient baseline raises the bar; it does not grant immunity."""
    rows = [
        row("c-1", 100, "fresh", "gateway", "index"),
        row("c-2", 101, "fresh", "gateway", "vault"),
        row("c-3", 102, "fresh", "vault", "warehouse"),
        row("c-4", 103, "fresh", "warehouse", "ledger"),
    ]
    alerts = [a for a in run(rows) if a.rule == R_LATERAL_CHAIN]
    assert alerts
    assert alerts[0].facts["baseline_state"] == BASELINE_COLD


def test_a_cold_identity_needs_more_evidence_than_an_established_one():
    """Same trace, two identities: only the established one alerts on two hops."""
    established_rows = established("known", "gateway", "index", 60) + [
        row("k-1", 100, "known", "gateway", "vault"),
        row("k-2", 101, "known", "vault", "warehouse"),
    ]
    cold_rows = [
        row("c-1", 100, "fresh", "gateway", "index"),
        row("c-2", 101, "fresh", "gateway", "vault"),
        row("c-3", 102, "fresh", "vault", "warehouse"),
    ]
    known = {a.rule for a in run(established_rows)}
    cold = {a.rule for a in run(cold_rows)}
    assert R_LATERAL_CHAIN in known
    assert R_LATERAL_CHAIN not in cold


def test_the_cold_start_policy_is_configurable_and_the_number_changes():
    rows = [
        row("c-1", 100, "fresh", "gateway", "index"),
        row("c-2", 101, "fresh", "gateway", "vault"),
        row("c-3", 102, "fresh", "vault", "warehouse"),
        row("c-4", 103, "fresh", "warehouse", "ledger"),
    ]
    strict = {a.rule for a in run(rows, cold_start_min_novel_edges=5)}
    loose = {a.rule for a in run(rows, cold_start_min_novel_edges=2)}
    assert R_LATERAL_CHAIN not in strict
    assert R_LATERAL_CHAIN in loose


# ------------------------------------------------------------------ boundary
def test_a_novel_transition_is_off_by_default():
    rows = established("worker", "gateway", "index", 60) + [
        row("t-1", 100, "worker", "gateway", "reports"),
        row("t-2", 101, "worker", "reports", "metrics"),
    ]
    assert R_NOVEL_TRANSITION not in {a.rule for a in run(rows)}


def test_a_novel_transition_can_be_switched_on():
    """Both targets familiar, the *ordering* new.

    The baseline holds both services, reached on separate occasions so the baseline
    never saw ``reports -> metrics``. Inside the evaluation window they occur in that
    sequence, which the rule reports when the operator has enabled it.
    """
    rows = (
        # interleaved so the baseline contains both targets and both orderings
        baseline_rows("worker", "gateway", "reports", 15, session="b1")
        + baseline_rows("worker", "gateway", "metrics", 15, start=40, session="b2")
        + baseline_rows("worker", "gateway", "reports", 15, start=80, session="b3")
        + [
            row("t-1", 200, "worker", "gateway", "reports"),
            row("t-2", 201, "worker", "gateway", "metrics"),
        ]
    )
    alerts = run(rows, emit_novel_transitions=True)
    assert R_NOVEL_TRANSITION in {a.rule for a in alerts}


def test_the_transition_rule_needs_a_baseline_of_transitions():
    """With a thin baseline almost every pair looks new, which is why it is off."""
    rows = [
        row("t-1", 0, "worker", "gateway", "reports"),
        row("t-2", 1, "worker", "reports", "metrics"),
        row("t-3", 2, "worker", "gateway", "metrics"),
    ]
    alerts = run(rows, emit_novel_transitions=True)
    transitions = [a for a in alerts if a.rule == R_NOVEL_TRANSITION]
    # Any transition emitted must at least describe a real pair it saw.
    for alert in transitions:
        assert len(alert.facts["transition"]) == 2


def test_the_baseline_fraction_moves_the_cutoff():
    rows = established("worker", "gateway", "index", 60)
    config = DetectorConfig(lateral=replace(DetectorConfig().lateral,
                                            baseline_fraction_percent=10)).validate()
    log = HEADER + "\n" + "\n".join(rows) + "\n"
    parsed = parse_csv(log, config=config)
    timeline = Timeline(config=config.timing)
    ordered, _ = timeline.reorder(parsed.events)
    detector = LateralDetector(config, timeline, None)
    detector.build_baseline(ordered)
    # 60 rows at 10% of the log is at most a handful of baseline events.
    assert len(detector.baseline_event_ids) <= 7


def test_min_baseline_events_is_respected():
    """Raising the bar past this identity's baseline demotes it to cold start.

    A lone edge is then no longer a finding, because a cold identity needs stricter
    evidence. The effect is visible as the absence of a high-severity alert plus a
    cold-start notice when that option is enabled.
    """
    rows = established("worker", "gateway", "index", 60) + [
        row("x-1", 100, "worker", "gateway", "vault")
    ]
    assert any(a.rule == R_NOVEL_EDGE for a in run(rows))

    strict = run(rows, min_baseline_events=5_000, cold_start_report_lone_edges=True)
    notices = [a for a in strict if a.facts.get("baseline_state") == BASELINE_COLD]
    assert notices, "demoting to cold start must change the report"
    assert all(a.severity == "low" for a in notices)


# ------------------------------------------------------------ hostile input
def test_an_identity_name_cannot_forge_a_second_alert():
    """The injection case: a newline in an actor must never reach an alert."""
    rows = established() + [row("x-1", 100, "evil\nALERT forged", "gateway", "vault")]
    alerts = run(rows)
    for alert in alerts:
        body = alert.to_dict()
        assert "\n" not in body["identity"]
        assert "\n" not in body["explanation"]


def test_alert_ids_are_content_derived():
    rows = established() + [row("x-1", 100, "worker", "gateway", "vault")]
    first = run(rows)[0].alert_id
    second = run(rows)[0].alert_id
    assert first == second
    assert first.startswith("al-")
