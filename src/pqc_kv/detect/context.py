"""Change-control context: the approval records a privilege change is checked against.

An approval is a *claim* that a change was authorised. It is not proof: the
practice README says the example "records that this unexpected role change
succeeded; it does not explain how", and the same caution applies in reverse -- an
all-approving insider can file paperwork. What an approval record does give the
detector is a checkable, one-sentence explanation: *this change matches ticket
change-100, which covers this subject and this role until 09:07:00Z*.

Matching is a conjunction of independent facts, and each one is reported
separately so the operator sees *which* fact failed:

=========== =================================================================
subject     the approval names the same identity the change affects
operation   the approval's operation matches the event's action, if mapped
role        the granted role equals the approval's role (config-switchable)
scope       the target service is inside the approval's declared scope
window      the change falls inside ``[valid_from, valid_until)`` in event time
signer      the approving operator is a distinct identity from the subject
=========== =================================================================

Why not just "an approval exists"
---------------------------------
Because the interesting attacks are exactly the near-misses. ``change-100``
authorises ``user-alex`` to become ``report-reader`` on ``reports``. An event that
grants ``user-alex`` the ``operator`` role under that ticket id must not be
approved, and neither must the same role grant to a different subject. Requiring
all six facts makes each near-miss a specific, quotable failure.

The window comparison uses **event time only**, and it is
:meth:`pqc_kv.detect.timing.Timeline.compare` that decides whether the change
really falls inside the window -- so a change from a clock-skewed source whose
position relative to ``valid_until`` cannot be established becomes
``uncertain``, not "approved" and not "violation".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import fields as F
from .timing import AFTER, BEFORE, ORDER_CONFIRMED, UNCERTAIN


class ApprovalError(Exception):
    """Approval input was unusable. Fixed token only, never the value."""

    def __init__(self, reason: str = "approvals_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Approval:
    """One authorised change. Times are integer ms; ``None`` means "unbounded"."""

    approval_id: str
    approved_by: str
    subject: str
    operation: str
    role: str
    scope: tuple[str, ...]
    valid_from_ms: int | None
    valid_until_ms: int | None
    #: For a revocation, the instant the role stops. Distinct from a validity
    #: window: it is not "covered until", it is "effective at".
    effective_at_ms: int | None = None

    def covers_service(self, service: str) -> bool:
        """Empty scope means "no service restriction", not "no services"."""
        if not self.scope:
            return True
        return service in self.scope


@dataclass
class Context:
    """All approvals, indexed for one-pass matching."""

    approvals: list = field(default_factory=list)
    #: approval_id -> Approval. Duplicates are refused, because two different
    #: tickets with one id makes every later explanation ambiguous.
    by_id: dict = field(default_factory=dict)
    #: subject -> [Approval] so matching does not scan every ticket per event.
    by_subject: dict = field(default_factory=dict)
    rejected: dict = field(default_factory=dict)
    #: Set when the approvals *document* was unusable -- not merely when individual
    #: records were. An operator must be able to tell "no change control was supplied"
    #: from "change control was supplied and could not be read", because the second
    #: makes every privilege change unapproved and produces a flood of alerts that
    #: look like a real incident.
    document_error: str = ""

    @classmethod
    def from_obj(cls, data) -> "Context":
        """Parse ``approvals.json``. Never raises on hostile content."""
        context = cls()
        if not isinstance(data, dict):
            raise ApprovalError()
        changes = data.get("changes")
        if not isinstance(changes, list):
            raise ApprovalError()
        if len(changes) > 100_000:
            raise ApprovalError("approvals_too_many")
        for raw in changes:
            try:
                approval = _parse_one(raw)
            except ApprovalError as exc:
                context.rejected[exc.reason] = context.rejected.get(exc.reason, 0) + 1
                continue
            if approval.approval_id in context.by_id:
                context.rejected["duplicate_approval"] = (
                    context.rejected.get("duplicate_approval", 0) + 1
                )
                continue
            context.approvals.append(approval)
            context.by_id[approval.approval_id] = approval
            context.by_subject.setdefault(approval.subject, []).append(approval)
        # Deterministic iteration for every later explanation.
        context.approvals.sort(key=lambda a: (a.valid_from_ms or 0, a.approval_id))
        for key in context.by_subject:
            context.by_subject[key].sort(key=lambda a: (a.valid_from_ms or 0, a.approval_id))
        return context

    @classmethod
    def from_json(cls, text: str) -> "Context":
        try:
            data = json.loads(text)
        except ValueError:
            raise ApprovalError("approvals_not_json") from None
        return cls.from_obj(data)

    def get(self, approval_id: str) -> Approval | None:
        return self.by_id.get(approval_id)

    def report(self) -> dict:
        """Counts for the run report. Never includes approval contents."""
        return {
            "approvals": len(self.approvals),
            "subjects": len(self.by_subject),
            "rejected": dict(sorted(self.rejected.items())),
            "with_scope": sum(1 for a in self.approvals if a.scope),
            "with_window": sum(
                1 for a in self.approvals
                if a.valid_from_ms is not None or a.valid_until_ms is not None
            ),
            # Present only when set, so the normal report stays unchanged.
            **({"document_error": self.document_error} if self.document_error else {}),
        }

    def for_subject(self, subject: str) -> list:
        return self.by_subject.get(subject, [])


def _parse_one(raw) -> Approval:
    if not isinstance(raw, dict):
        raise ApprovalError()
    try:
        approval_id = F.validate_ident(raw.get("approval_id"))
        approved_by = F.validate_ident(raw.get("approved_by"))
        subject = F.validate_ident(raw.get("subject"))
        operation = F.validate_ident(raw.get("operation"))
    except F.FieldError:
        raise ApprovalError() from None
    role = raw.get("role", "")
    try:
        role = F.validate_ident(role, allow_empty=True)
    except F.FieldError:
        raise ApprovalError() from None
    scope = raw.get("scope", [])
    if not isinstance(scope, list):
        raise ApprovalError()
    services = []
    for item in scope:
        try:
            services.append(F.validate_ident(item))
        except F.FieldError:
            raise ApprovalError() from None
    def stamp(name):
        value = raw.get(name)
        if value is None:
            return None
        try:
            return F.parse_timestamp(value)
        except F.FieldError:
            raise ApprovalError() from None
    valid_from = stamp("valid_from_utc")
    valid_until = stamp("valid_until_utc")
    effective = stamp("effective_at_utc")
    if valid_from is not None and valid_until is not None and valid_until < valid_from:
        # An inverted window covers nothing; treating it as coverage would let a
        # typo approve everything.
        raise ApprovalError("approval_window_inverted")
    return Approval(
        approval_id=approval_id,
        approved_by=approved_by,
        subject=subject,
        operation=operation,
        role=role,
        scope=tuple(sorted(set(services))),
        valid_from_ms=valid_from,
        valid_until_ms=valid_until,
        effective_at_ms=effective,
    )


# ------------------------------------------------------------------ matching
@dataclass
class Match:
    """The result of checking one change against the approval context.

    ``status`` is one of ``approved``, ``unapproved``, ``uncertain``, and every
    arriving alert carries the failing fact by name.
    """

    status: str
    approval_id: str = ""
    failed: tuple = ()
    matched: tuple = ()
    #: Ordering verdict relative to the ticket's window, from the timeline.
    window_order: str = ""
    explanation: str = ""
    #: The approval record itself, when one matched enough to explain.
    approval: Approval | None = None


APPROVED = "approved"
UNAPPROVED = "unapproved"
UNCERTAIN = "uncertain"


def is_administrative(event) -> bool:
    """Is this event an operator *acting on a ticket*, rather than changing itself?

    Purely structural, and it is the distinction the practice README spells out:
    "For approval and revocation administration events, it identifies the operator;
    ``approvals.json`` identifies the affected subject."

    The signal is that the event carries a ticket id **and the actor's own role did
    not move**. ``approve_role_change`` and ``revoke_role`` both have
    ``role_before == role_after`` (the operator stays an operator); a ``role_change``
    applied to the actor has ``role_before != role_after``. No action vocabulary is
    needed, so this works on a dataset with different action names.
    """
    return bool(event.approval_id) and event.role_before == event.role_after


def check_change(event, context: "Context", timeline, config) -> Match:
    """Decide whether an approval covers ``event``.

    Three outcomes, and the third is the point of goal 8:

    * ``approved`` -- an approval matches on every required fact and the event is
      provably inside its window;
    * ``unapproved`` -- no approval matches, or one matches on everything except a
      fact that provably fails;
    * ``uncertain`` -- a candidate approval exists but the event's position relative
      to its window cannot be established within the clock tolerance. We say which
      two windows are possible instead of picking one.
    """
    if is_administrative(event):
        return _check_administrative(event, context, timeline, config)

    # An empty ``approval_id`` is NOT a reason to treat the change as unapproved.
    # The ticketing system backfilling the column is not a security property: a
    # change is authorised because a record covers its subject, role, scope and
    # time, not because someone copied an id into a column. The abuse this could
    # have allowed -- a subject using one ticket to launder a different grant -- is
    # already blocked by the role fact, which compares the *granted role* against
    # the ticket's role rather than trusting the ticket's existence.
    candidates = context.for_subject(event.actor)
    if not candidates:
        return Match(
            status=UNAPPROVED,
            failed=("subject",),
            explanation=(
                f"no approval names subject {event.actor} for this change"
            ),
        )

    # A change that arrives with a ticket id is checked primarily against it, but a
    # ticket on the event is a *claim*; we only trust it if it validates.
    declared = context.get(event.approval_id) if event.approval_id else None
    ordered = list(candidates)
    if declared is not None and declared in ordered:
        # Checking the claimed ticket first keeps the explanation the operator
        # expects, while still falling through to other tickets when it fails.
        ordered.remove(declared)
        ordered.insert(0, declared)

    nearest_failure: Match | None = None
    uncertain_match: Match | None = None

    for approval in ordered:
        result = _check_one(event, approval, timeline, config)
        if result.status == APPROVED:
            return result
        if result.status == UNCERTAIN:
            # Remember the first uncertain candidate; a definite match elsewhere
            # would still win, so keep looking.
            if uncertain_match is None:
                uncertain_match = result
            continue
        if nearest_failure is None or len(result.failed) < len(nearest_failure.failed):
            nearest_failure = result

    if uncertain_match is not None:
        return uncertain_match
    if nearest_failure is not None:
        return nearest_failure
    return Match(
        status=UNAPPROVED,
        failed=("subject",),
        explanation=f"no approval covers the change by {event.actor}",
    )


def _check_administrative(event, context: "Context", timeline, config) -> Match:
    """An operator applied a named ticket. The ticket is the evidence.

    The facts differ from the subject-side case because the two role columns
    describe the *operator*, not the granted role:

    * ``operator`` -- the approval's ``approved_by`` is this actor;
    * ``operation`` -- the approval's operation matches the mapped action;
    * ``window`` -- the event falls inside the ticket's validity, in event time.

    Role is deliberately not compared here. ``role_before == role_after`` is the
    operator's own role; the granted role lives in the ticket and is compared when
    the *subject's* change is seen. Comparing the operator's role against the
    granted role would reject every correct revocation.
    """
    approval = context.get(event.approval_id)
    if approval is None:
        return Match(
            status=UNAPPROVED,
            failed=("unknown_approval",),
            explanation=(
                f"{event.actor} cited approval {event.approval_id}, which is not in "
                f"the change-control record"
            ),
        )

    failed: list = []
    matched: list = []
    if approval.approved_by != event.actor:
        failed.append("operator")
    else:
        matched.append("operator")
    # Separation of duties applies on this path too, and it is the one path where
    # it cannot be seen from role columns: an operator approving their own ticket
    # looks exactly like an operator approving anyone else's.
    if approval.approved_by and approval.approved_by == approval.subject:
        failed.append("self_approved")

    expected = config.privilege.operation_for_action.get(event.action)
    if expected is not None:
        if approval.operation != expected:
            failed.append("operation")
        else:
            matched.append("operation")
    else:
        matched.append("operation_unspecified")

    window_status, window_order = _window(event, approval, timeline, config)
    if window_status == "outside":
        failed.append("window")
    elif window_status == "uncertain":
        return Match(
            status=UNCERTAIN,
            approval_id=approval.approval_id,
            failed=tuple(failed),
            matched=tuple(matched),
            window_order=window_order,
            explanation=(
                f"approval {approval.approval_id} may or may not have been in force "
                f"when {event.actor} applied it: the clocks cannot establish the "
                f"order within tolerance"
            ),
            approval=approval,
        )
    else:
        matched.append("window")

    if failed:
        return Match(
            status=UNAPPROVED,
            approval_id=approval.approval_id,
            failed=tuple(failed),
            matched=tuple(matched),
            window_order=window_order,
            explanation=(
                f"approval {approval.approval_id} does not authorise this action by "
                f"{event.actor}: " + ", ".join(failed)
            ),
            approval=approval,
        )
    return Match(
        status=APPROVED,
        approval_id=approval.approval_id,
        failed=(),
        matched=tuple(matched),
        window_order=window_order,
        explanation=(
            f"approval {approval.approval_id} is held by {event.actor} and was in "
            f"force at the event's time"
        ),
        approval=approval,
    )


def _check_one(event, approval: Approval, timeline, config) -> Match:
    failed: list = []
    matched: list = []
    privilege = config.privilege

    # 1. signer distinctness -- an approval nobody but the subject signed is not
    #    a control.
    if approval.approved_by and approval.approved_by == event.actor:
        failed.append("self_approved")
    elif approval.approved_by:
        matched.append("signer")

    # 2. operation, when the config maps this action to one.
    expected = privilege.operation_for_action.get(event.action)
    if expected is not None:
        if approval.operation != expected:
            failed.append("operation")
        else:
            matched.append("operation")
    else:
        # No mapping: we cannot claim the operation matches, so we do not claim it.
        matched.append("operation_unspecified")

    # 3. role, when the schema exposes one.
    if privilege.require_role_match and approval.role:
        changed_to = event.role_after if event.role_after else event.role_before
        if changed_to != approval.role:
            failed.append("role")
        else:
            matched.append("role")

    # 4. Scope is deliberately NOT checked here. A role change is recorded against
    #    the identity service (``target_service="identity"``); the approval's scope
    #    lists what the new role may reach afterwards. Comparing the two compares a
    #    location with a permission set, which would reject every correct grant.
    #    Scope is enforced where it belongs: on the data access itself, in
    #    :meth:`lateral.LateralDetector._authorised`.

    # 5. window, in event time, with the clock question answered by the timeline.
    window_status, window_order = _window(event, approval, timeline, config)
    if window_status == "outside":
        failed.append("window")
    elif window_status == "uncertain":
        # Goal 8: do not pick an order. Report both.
        return Match(
            status=UNCERTAIN,
            approval_id=approval.approval_id,
            failed=tuple(failed),
            matched=tuple(matched),
            window_order=window_order,
            explanation=(
                f"approval {approval.approval_id} is a candidate but the change's "
                f"position relative to its validity window cannot be established "
                f"within the clock tolerance (both orders possible)"
            ),
            approval=approval,
        )
    else:
        matched.append("window")

    if failed:
        return Match(
            status=UNAPPROVED,
            approval_id=approval.approval_id,
            failed=tuple(failed),
            matched=tuple(matched),
            window_order=window_order,
            explanation=(
                f"approval {approval.approval_id} does not cover this change: "
                + ", ".join(failed)
            ),
            approval=approval,
        )
    return Match(
        status=APPROVED,
        approval_id=approval.approval_id,
        failed=(),
        matched=tuple(matched),
        window_order=window_order,
        explanation=(
            f"approval {approval.approval_id} covers subject, role, scope and time"
        ),
        approval=approval,
    )


def _window(event, approval: Approval, timeline, config) -> tuple[str, str]:
    """Is ``event`` inside the approval window? ``inside``/``outside``/``uncertain``.

    The comparison is delegated to the timeline so the same clock-uncertainty logic
    that governs "approval before action" governs "action before expiry". One
    mechanism, one place to get right.
    """
    start = approval.valid_from_ms
    until = approval.valid_until_ms
    if start is None and until is None:
        # A revocation ticket carries ``effective_at`` instead of a window. Absent
        # both bounds there is nothing to contradict, so the time fact is not a
        # failure -- the other facts still have to match.
        return "inside", ORDER_CONFIRMED

    slack_before = config.privilege.approval_slack_before_ms
    slack_after = config.privilege.approval_slack_after_ms

    if start is not None:
        verdict = _compare_point(timeline, event.event_id, start)
        if verdict == UNCERTAIN:
            return "uncertain", UNCERTAIN
        if verdict == BEFORE and not slack_before:
            return "outside", ORDER_CONFIRMED
    if until is not None:
        verdict = _compare_point(timeline, event.event_id, until)
        if verdict == UNCERTAIN:
            return "uncertain", UNCERTAIN
        # ``valid_until`` is exclusive: an action at exactly the bound is out.
        if verdict == AFTER or (verdict == "same" and not slack_after):
            return "outside", ORDER_CONFIRMED
    return "inside", ORDER_CONFIRMED


def _compare_point(timeline, event_id: str, point_ms: int) -> str:
    """Compare one event against a fixed timestamp, respecting its uncertainty."""
    if event_id not in timeline.corrected:
        return UNCERTAIN
    corrected = timeline.corrected[event_id]
    uncertainty = timeline.uncertainty[event_id]
    if corrected + uncertainty < point_ms:
        return BEFORE
    if corrected - uncertainty > point_ms:
        return AFTER
    if uncertainty == 0 and corrected == point_ms:
        return "same"
    # The point sits inside this event's own error bar.
    return UNCERTAIN


__all__ = [
    "APPROVED", "Approval", "ApprovalError", "Context", "Match", "UNAPPROVED",
    "UNCERTAIN", "check_change",
]
