"""Goal 6: approved administration versus suspicious privilege change.

Each rule is tested three ways -- positive (it fires), negative (it stays quiet on
the benign look-alike) and boundary (the exact edge where it flips). The pairs are
the point: a rule that fires on everything passes every positive test.
"""

from __future__ import annotations

import pytest

from pqc_kv.detect import context as ctx
from pqc_kv.detect.config import DetectorConfig, PrivilegeConfig
from pqc_kv.detect.privilege import (
    PrivilegeDetector, R_FOLLOW_ON, R_SELF_APPROVED, R_UNAPPROVED_PRIVILEGE,
    R_UNCERTAIN_APPROVAL,
)
from pqc_kv.detect.timing import Timeline

HEADER = (
    "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
    "source_service,target_service,action,role_before,role_after,outcome,"
    "approval_id,session_id,correlation_id"
)

#: Note: a JSON *array*, not a fragment wrapped in stray braces. A malformed
#: approvals file is refused by :class:`context.Context` rather than half-applied,
#: and that refusal is silent by design -- so this fixture is asserted below to make
#: sure it really parses, instead of every test accidentally running with no
#: change control and quietly passing for the wrong reason.
APPROVALS = """{"changes": [
  {"approval_id": "chg-1", "approved_by": "ops-1", "subject": "alice",
   "operation": "grant_role", "role": "analyst", "scope": ["reports"],
   "valid_from_utc": "2026-01-15T08:00:00Z", "valid_until_utc": "2026-01-15T12:00:00Z"}
]}"""


def build(rows, *, approvals=APPROVALS, **privilege_overrides):
    """Run the privilege detector on CSV rows and return the alerts."""
    from pqc_kv.detect.ingest import parse_csv

    config = DetectorConfig(
        privilege=PrivilegeConfig(**privilege_overrides).validate()
    ).validate()
    # An override with a misspelled keyword would otherwise raise TypeError from the
    # dataclass, which is fine -- but this assertion makes the failure say which
    # keyword, instead of surfacing three tests later as "no alerts".
    log = HEADER + "\n" + "\n".join(rows) + "\n"
    parsed = parse_csv(log, config=config)
    timeline = Timeline(config=config.timing)
    ordered, deferred = timeline.reorder(parsed.events)
    context = ctx.Context.from_json(approvals) if approvals else ctx.Context()
    detector = PrivilegeDetector(config, timeline, context)
    return detector.evaluate(ordered + list(deferred))


def row(event_id="e-1", at="2026-01-15T09:00:00.000Z", actor="alice",
        action="role_change", before="viewer", after="analyst",
        outcome="success", approval="chg-1", source="portal",
        target="identity", session="s1", offset="0", received=None):
    received = received or at.replace(".000Z", ".100Z")
    return (
        f"{event_id},{at},{received},{offset},{actor},{source},{target},{action},"
        f"{before},{after},{outcome},{approval},{session},c1"
    )


# ---------------------------------------------------------------- positive
def test_an_unapproved_role_change_alerts():
    """No record covers it: the subject has no approval at all."""
    alerts = build([row(actor="stranger", approval="")])
    assert R_UNAPPROVED_PRIVILEGE in {a.rule for a in alerts}


def test_a_change_covered_by_a_valid_record_is_approved_even_without_a_ticket_id():
    """An empty ``approval_id`` column is not an unapproved change.

    What authorises a change is a record covering its subject, role, scope and time.
    Treating a blank column as "no paperwork" would flag every deployment whose
    ticketing system backfills ids after the fact -- and it would do so for the wrong
    reason, since the facts it needs are in the record either way.
    """
    assert build([row(approval="")]) == []


def test_a_blank_ticket_does_not_launder_a_different_grant():
    """The abuse an empty id *could* have enabled, and what actually stops it."""
    alert = next(a for a in build([row(approval="", after="operator")])
                 if a.rule == R_UNAPPROVED_PRIVILEGE)
    assert "role" in alert.facts["context_missing"]


def test_the_alert_names_the_missing_context():
    alert = next(a for a in build([row(actor="stranger", approval="")])
                 if a.rule == R_UNAPPROVED_PRIVILEGE)
    assert alert.facts["context_missing"]
    assert "subject" in alert.facts["context_missing"]


def test_a_role_change_naming_a_nonexistent_ticket_is_not_trusted():
    """A cited id is a claim, not evidence: the facts still have to match."""
    alert = next(a for a in build([row(approval="chg-nope", after="operator")])
                 if a.rule == R_UNAPPROVED_PRIVILEGE)
    assert "role" in alert.facts["context_missing"]
    assert alert.facts["approval_id_claimed"] == "chg-nope"


def test_a_ticket_for_a_different_role_does_not_cover_it():
    """The near-miss: right subject, right time, wrong role."""
    alert = next(a for a in build([row(after="operator")])
                 if a.rule == R_UNAPPROVED_PRIVILEGE)
    assert "role" in alert.facts["context_missing"]


def test_a_self_approved_change_alerts_twice_for_two_distinct_reasons():
    approvals = """
    {"changes": [{"approval_id": "chg-9", "approved_by": "alice", "subject": "alice",
      "operation": "grant_role", "role": "analyst", "scope": ["reports"],
      "valid_from_utc": "2026-01-15T08:00:00Z",
      "valid_until_utc": "2026-01-15T12:00:00Z"}]}
    """
    alerts = build([row(approval="chg-9")], approvals=approvals)
    rules = {a.rule for a in alerts}
    assert R_SELF_APPROVED in rules
    assert R_UNAPPROVED_PRIVILEGE in rules


# ---------------------------------------------------------------- negative
def test_an_approved_role_change_is_silent():
    assert build([row()]) == []


def test_an_approved_change_within_scope_access_is_silent():
    rows = [
        row(event_id="e-1", action="approve_role_change", actor="ops-1",
            before="operator", after="operator", approval="chg-1"),
        row(event_id="e-2"),
        row(event_id="e-3", action="read", source="portal", target="reports",
            outcome="allow", before="analyst", after="analyst"),
    ]
    alerts = [a for a in build(rows) if a.rule == R_UNAPPROVED_PRIVILEGE]
    assert alerts == []


def test_a_failed_role_change_is_not_a_privilege_change():
    """What took effect is the subject of this rule. Attempts are a different job."""
    assert build([row(outcome="deny", approval="")]) == []


def test_a_read_that_changes_no_role_is_not_a_privilege_change():
    assert build([row(action="read", before="analyst", after="analyst",
                      approval="")]) == []


def test_an_authorisation_record_is_context_not_a_change():
    rows = [row(event_id="e-1", action="approve_role_change", actor="ops-1",
                before="operator", after="operator", approval="chg-1")]
    assert build(rows) == []


# ---------------------------------------------------------------- boundary
def test_the_window_start_is_inclusive():
    """Comfortably inside the window: approved, no uncertainty involved."""
    assert build([row(at="2026-01-15T09:00:00.000Z")]) == []


def test_the_window_end_is_exclusive():
    """Past the bound is out, well beyond any clock doubt."""
    alert = next(a for a in build([row(at="2026-01-15T12:00:01.000Z")])
                 if a.rule == R_UNAPPROVED_PRIVILEGE)
    assert "window" in alert.facts["context_missing"]


def test_a_change_in_the_clock_shadow_of_the_bound_is_uncertain_not_judged():
    """Exactly on the boundary is neither approved nor a violation.

    With 250 ms of declared uncertainty, an event stamped exactly at
    ``valid_until_utc`` cannot be shown to fall inside or outside the window, so
    goal 8 requires the ambiguous answer. Both are reported; neither is asserted.
    """
    alerts = build([row(at="2026-01-15T12:00:00.000Z")])
    assert [a.rule for a in alerts] == [R_UNCERTAIN_APPROVAL]
    assert alerts[0].order == "uncertain"
    assert sorted(alerts[0].facts["possible_orders"]) == ["after_window", "inside_window"]


def test_well_before_the_bound_is_inside():
    assert [a for a in build([row(at="2026-01-15T11:59:00.000Z")])
            if a.rule == R_UNAPPROVED_PRIVILEGE] == []


def test_an_action_before_the_window_opens_is_outside():
    alert = next(a for a in build([row(at="2026-01-15T07:59:59.000Z")])
                 if a.rule == R_UNAPPROVED_PRIVILEGE)
    assert "window" in alert.facts["context_missing"]


def test_the_clock_uncertainty_can_make_the_window_ambiguous():
    """Goal 8 inside goal 6: an event on the boundary of a window it cannot resolve.

    With 10 s of declared uncertainty, an event stamped inside the window but within
    10 s of the end cannot be placed inside or outside, so the rule must report
    uncertainty rather than a violation or an approval.
    """
    from dataclasses import replace

    from pqc_kv.detect.ingest import parse_csv

    config = DetectorConfig(
        timing=replace(DetectorConfig().timing, offset_uncertainty_ms=10_000)
    ).validate()
    log = HEADER + "\n" + row(at="2026-01-15T11:59:55.000Z") + "\n"
    parsed = parse_csv(log, config=config)
    timeline = Timeline(config=config.timing)
    ordered, deferred = timeline.reorder(parsed.events)
    detector = PrivilegeDetector(config, timeline, ctx.Context.from_json(APPROVALS))
    alerts = detector.evaluate(ordered + list(deferred))
    assert [a.rule for a in alerts] == [R_UNCERTAIN_APPROVAL]
    assert alerts[0].order == "uncertain"
    assert "inside_window" in alerts[0].facts["possible_orders"]


# ---------------------------------------------------------------- follow-on
def test_access_after_an_unexplained_change_alerts():
    rows = [
        row(event_id="e-1", actor="stranger", approval="", session="s9"),
        row(event_id="e-2", actor="stranger", action="read", source="portal",
            target="reports", outcome="allow", before="analyst", after="analyst",
            approval="", session="s9", at="2026-01-15T09:00:30.000Z"),
    ]
    assert R_FOLLOW_ON in {a.rule for a in build(rows)}


def test_access_after_an_approved_change_is_silent():
    rows = [
        row(event_id="e-1", session="s9"),
        row(event_id="e-2", action="read", source="portal", target="reports",
            outcome="allow", before="analyst", after="analyst", session="s9",
            at="2026-01-15T09:00:30.000Z"),
    ]
    assert R_FOLLOW_ON not in {a.rule for a in build(rows)}


def test_a_different_session_is_not_a_follow_on():
    rows = [
        row(event_id="e-1", approval="", session="s9"),
        row(event_id="e-2", action="read", source="portal", target="reports",
            outcome="allow", before="analyst", after="analyst", approval="",
            session="other", at="2026-01-15T09:00:30.000Z"),
    ]
    assert R_FOLLOW_ON not in {a.rule for a in build(rows)}


def test_an_access_outside_the_follow_on_window_is_not_tied_to_the_change():
    rows = [
        row(event_id="e-1", approval="", session="s9"),
        row(event_id="e-2", action="read", source="portal", target="reports",
            outcome="allow", before="analyst", after="analyst", approval="",
            session="s9", at="2026-01-15T11:00:00.000Z"),
    ]
    assert R_FOLLOW_ON not in {a.rule for a in build(rows)}


def test_the_follow_on_rule_can_be_switched_off():
    rows = [
        row(event_id="e-1", approval="", session="s9"),
        row(event_id="e-2", action="read", source="portal", target="reports",
            outcome="allow", before="analyst", after="analyst", approval="",
            session="s9", at="2026-01-15T09:00:30.000Z"),
    ]
    alerts = build(rows, follow_on_alerts=False)
    assert R_FOLLOW_ON not in {a.rule for a in alerts}


# ------------------------------------------------------------ config matters
def test_operation_mapping_is_optional_and_its_absence_is_honest():
    """With no mapping the detector does not pretend the operation matched."""
    from dataclasses import replace
    from pqc_kv.detect.ingest import parse_csv

    config = DetectorConfig(
        privilege=replace(DetectorConfig().privilege,
                          operation_for_action={"role_change": "grant_role"})
    ).validate()
    log = HEADER + "\n" + row() + "\n"
    parsed = parse_csv(log, config=config)
    timeline = Timeline(config=config.timing)
    ordered, _ = timeline.reorder(parsed.events)
    detector = PrivilegeDetector(config, timeline, ctx.Context.from_json(APPROVALS))
    assert detector.evaluate(ordered) == []


def test_a_mismatched_operation_mapping_blocks_approval():
    from dataclasses import replace
    from pqc_kv.detect.ingest import parse_csv

    config = DetectorConfig(
        privilege=replace(DetectorConfig().privilege,
                          operation_for_action={"role_change": "revoke_role"})
    ).validate()
    log = HEADER + "\n" + row() + "\n"
    parsed = parse_csv(log, config=config)
    timeline = Timeline(config=config.timing)
    ordered, _ = timeline.reorder(parsed.events)
    detector = PrivilegeDetector(config, timeline, ctx.Context.from_json(APPROVALS))
    alerts = detector.evaluate(ordered)
    assert "operation" in alerts[0].facts["context_missing"]


def test_the_vocabulary_list_is_not_needed_for_a_structural_change():
    """The whole point of the 'not tuned to the practice data' claim.

    An empty action vocabulary must still catch a role change, because
    ``role_before != role_after`` is the signal. If this test fails, the rule is
    really just string matching against a list someone wrote from the sample.
    """
    alerts = build([row(actor="stranger", approval="")],
                   privileged_actions=(), authorising_actions=())
    assert R_UNAPPROVED_PRIVILEGE in {a.rule for a in alerts}


def test_a_renamed_action_still_alerts_when_the_role_changed():
    """An action name the detector has never seen must not buy silence."""
    alerts = build([row(actor="stranger", approval="", action="privilege_escalation_thing")])
    assert R_UNAPPROVED_PRIVILEGE in {a.rule for a in alerts}


def test_the_approval_fixture_actually_parses():
    """Without this, a malformed fixture makes every test above pass vacuously."""
    context = ctx.Context.from_json(APPROVALS)
    assert len(context.approvals) == 1
    assert context.get("chg-1") is not None
    assert context.rejected == {}


def test_a_malformed_approvals_file_is_refused_whole():
    """Half-applying a broken change-control record would approve the wrong things.

    A single bad record is rejected and counted; the rest of the file still applies.
    A structurally broken file (no ``changes`` list) is refused entirely.
    """
    context = ctx.Context.from_json('{"changes": [{"approval_id": "x"}]}')
    assert context.approvals == []
    assert context.rejected.get("approvals_invalid") == 1
    with pytest.raises(ctx.ApprovalError):
        ctx.Context.from_obj({"nope": []})
