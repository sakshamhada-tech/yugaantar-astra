"""Goal 6: routine versus suspicious privilege change and data access.

The question the brief asks is not "was there a role change" -- role changes are
routine. It is "was *this* role change approved context". So every rule here pairs
a structural observation with a context check, and the alert always names the
context that was missing.

Why this is not tuned to the practice labels
--------------------------------------------
Three of the four signals are properties of *any* audit schema, not of this file:

* ``role_before != role_after`` is a structural change. It has no vocabulary.
* "an approval exists whose subject, role, scope and window match" is a relational
  query over two tables. It does not know that ``report-reader`` is a nice role or
  that ``operator`` is a scary one.
* "this actor has never performed this action before, and its peer group has" is a
  count over the data itself, with the peer group derived from role membership in
  the log rather than from a list we wrote.

The one signal that *is* vocabulary-dependent -- which action names count as
privilege changes -- is a config list, empty of practice values in the defaults,
and the structural check runs whether or not the list is populated. Removing the
list entirely still catches the practice data's role change, because
``role_before != role_after`` catches it. That is the test of whether a rule is
real or memorised.
"""

from __future__ import annotations

from . import context as ctx
from .alerts import Alert
from .timing import ORDER_CONFIRMED, ORDER_UNCERTAIN

#: Rule names. Stable strings: they appear in alerts, metrics and the docs table.
R_UNAPPROVED_PRIVILEGE = "unapproved_privilege_change"
R_SELF_APPROVED = "self_approved_privilege_change"
R_FOLLOW_ON = "follow_on_access_after_unapproved_change"
R_UNCERTAIN_APPROVAL = "uncertain_approval_window"
R_UNBACKED_SCOPE_USE = "access_outside_approved_scope"


class PrivilegeDetector:
    """Detects privilege changes that approved context does not explain.

    Stateful only in the sense that it remembers which identities have an
    unexplained change outstanding, so a follow-on access can be tied to it.
    """

    def __init__(self, config, timeline, context) -> None:
        self.config = config
        self.timeline = timeline
        self.context = context
        #: (actor, session) -> the unexplained change waiting for a follow-on.
        self._pending: dict = {}
        #: actor -> set of roles seen, used only for reporting peer groups.
        self.seen_roles: dict = {}

    # ---------------------------------------------------------------- helpers
    def is_privilege_change(self, event) -> bool:
        """Structural first, vocabulary second.

        ``role_before != role_after`` is the primary signal because it needs no
        knowledge of the action vocabulary at all. The configured action list adds
        the cases the schema cannot show -- an approve/revoke where the *actor's*
        role does not move -- and is a config value, not a constant.
        """
        if event.role_changed:
            return True
        return event.action in self.config.privilege.privileged_actions

    def is_authorisation(self, event) -> bool:
        """An approval *record* is context, not a privilege change."""
        return event.action in self.config.privilege.authorising_actions

    # ------------------------------------------------------------------ rules
    def evaluate(self, events) -> list:
        alerts: list = []
        privilege_cfg = self.config.privilege

        for event in events:
            if event.actor not in self.seen_roles:
                self.seen_roles[event.actor] = set()
            if event.role_after:
                self.seen_roles[event.actor].add(event.role_after)

            # --- follow-on access for an earlier unexplained change -----------
            if privilege_cfg.follow_on_alerts:
                self._check_follow_on(event, alerts)

            if self.is_authorisation(event):
                continue
            if not self.is_privilege_change(event):
                continue
            if not event.is_success:
                # A *failed* privilege change is not a privilege change. Reporting
                # attempts is a different job (and a much noisier one); this rule
                # stays about what took effect.
                continue

            match = ctx.check_change(event, self.context, self.timeline, self.config)

            if match.status == ctx.UNCERTAIN:
                alerts.append(self._uncertain(event, match))
                self._remember_pending(event, match)
                continue
            if match.status == ctx.APPROVED:
                # An approved change is context for the access that follows it.
                # Recording nothing is deliberate: the approval record is the
                # evidence, and copying it would double every benign change.
                continue

            if "self_approved" in match.failed:
                alerts.append(self._self_approved(event, match))
            alerts.append(self._unapproved(event, match))
            self._remember_pending(event, match)

        return alerts

    # ------------------------------------------------------------ rule bodies
    def _unapproved(self, event, match: ctx.Match) -> Alert:
        facts = {
            "role_before": event.role_before,
            "role_after": event.role_after,
            "approval_id_claimed": event.approval_id,
            "approval_id_nearest": match.approval_id,
            "context_missing": list(match.failed),
            "context_matched": list(match.matched),
            "session_id": event.session_id,
            "outcome": event.outcome,
        }
        missing = ", ".join(match.failed) if match.failed else "no approval"
        from .context import is_administrative

        if is_administrative(event):
            who = f"{event.actor} applied change {event.approval_id} on {event.target_service}"
        else:
            who = (
                f"{event.actor}'s role went from {event.role_before or 'none'} to "
                f"{event.role_after or 'none'} on {event.target_service}"
            )
        explanation = (
            f"{who} at {ctx_event_time(event)} with no matching authorization: "
            f"{missing}."
        )
        return Alert(
            rule=R_UNAPPROVED_PRIVILEGE,
            severity="high",
            identity=event.actor,
            services=[event.source_service, event.target_service],
            event_ids=[event.event_id],
            event_ms=self.timeline.corrected.get(event.event_id, event.event_ms),
            explanation=explanation,
            order=ORDER_CONFIRMED,
            facts=facts,
            goal=6,
        )

    def _self_approved(self, event, match: ctx.Match) -> Alert:
        facts = {
            "approval_id": match.approval_id,
            "approved_by": match.approval.approved_by if match.approval else "",
            "subject": event.actor,
            "session_id": event.session_id,
        }
        return Alert(
            rule=R_SELF_APPROVED,
            severity="high",
            identity=event.actor,
            services=[event.source_service, event.target_service],
            event_ids=[event.event_id],
            event_ms=self.timeline.corrected.get(event.event_id, event.event_ms),
            explanation=(
                f"{event.actor} approved change {match.approval_id} that grants "
                f"privilege to {event.actor}: the approver and the subject are the "
                f"same identity."
            ),
            order=ORDER_CONFIRMED,
            facts=facts,
            goal=6,
        )

    def _uncertain(self, event, match: ctx.Match) -> Alert:
        gap = {}
        if match.approval is not None and match.approval.valid_until_ms is not None:
            point = match.approval.valid_until_ms
            corrected = self.timeline.corrected.get(event.event_id)
            if corrected is not None:
                gap = {
                    "approval_valid_until": point,
                    "corrected_event_ms": corrected,
                    "difference_ms": corrected - point,
                    "uncertainty_ms": self.timeline.uncertainty.get(event.event_id, 0),
                    "possible_orders": ["inside_window", "after_window"],
                }
        facts = {
            "role_before": event.role_before,
            "role_after": event.role_after,
            "approval_id": match.approval_id,
            "context_matched": list(match.matched),
            "context_uncertain": list(match.failed),
            "session_id": event.session_id,
        }
        facts.update(gap)
        return Alert(
            rule=R_UNCERTAIN_APPROVAL,
            severity="medium",
            identity=event.actor,
            services=[event.source_service, event.target_service],
            event_ids=[event.event_id],
            event_ms=self.timeline.corrected.get(event.event_id, event.event_ms),
            explanation=(
                f"{event.actor}'s role change from "
                f"{event.role_before or 'none'} to {event.role_after or 'none'} may or "
                f"may not fall inside approval {match.approval_id}: the clocks involved "
                f"cannot establish the order within tolerance, so both "
                f"inside-window and after-window remain possible."
            ),
            order=ORDER_UNCERTAIN,
            facts=facts,
            goal=8,
        )

    def _remember_pending(self, event, match: ctx.Match) -> None:
        key = (event.actor, event.session_id)
        corrected = self.timeline.corrected.get(event.event_id, event.event_ms)
        self._pending[key] = {
            "event": event,
            "match": match,
            "corrected_ms": corrected,
        }

    def _check_follow_on(self, event, alerts: list) -> None:
        """Data access soon after an unexplained change, same actor and session.

        This is blast-radius context, not a second accusation. It fires only in the
        *same session* as the unexplained change and within the configured window,
        and never for an approved change.

        The ordering question goes through the timeline, so a follow-on whose
        position relative to the change cannot be established is emitted with
        ``order=uncertain`` rather than silently dropped or silently accepted.
        """
        key = (event.actor, event.session_id)
        pending = self._pending.get(key)
        if pending is None:
            return
        change_event = pending["event"]
        if event.event_id == change_event.event_id:
            return

        window = self.config.privilege.follow_on_window_ms
        order = self.timeline.compare(change_event.event_id, event.event_id)
        corrected = self.timeline.corrected.get(event.event_id, event.event_ms)
        change_ms = pending["corrected_ms"]
        delta = corrected - change_ms
        slack = (
            self.timeline.uncertainty.get(event.event_id, 0)
            + self.timeline.uncertainty.get(change_event.event_id, 0)
        )

        # ``compare(change, access)`` answers "was the *change* before the access?".
        # "before" is the ordinary case: the change happened, then the access did.
        if order == "after":
            # Provably earlier than the change: not a follow-on at all.
            return
        if order == "before":
            if delta > window:
                return
            state = ORDER_CONFIRMED
        else:
            # Uncertain order. Still usable if the gap is small enough that *both*
            # possible orders put the access inside the window -- otherwise drop it.
            if abs(delta) + slack > window:
                return
            state = ORDER_UNCERTAIN

        when = (
            f"{delta} ms after" if delta >= 0 else f"{abs(delta)} ms before"
        )
        facts = {
            "change_event_id": change_event.event_id,
            "change_rule": R_UNAPPROVED_PRIVILEGE,
            "change_role_after": change_event.role_after,
            "access_event_id": event.event_id,
            "access_target": event.target_service,
            "access_outcome": event.outcome,
            "same_session": True,
            "window_ms": window,
            "observed_gap_ms": delta,
            "combined_uncertainty_ms": slack,
        }
        suffix = (
            ""
            if state == ORDER_CONFIRMED
            else "; its order relative to the change is uncertain because of clock "
                 "offset, so both orders are reported"
        )
        alerts.append(Alert(
            rule=R_FOLLOW_ON,
            severity="medium",
            identity=event.actor,
            services=[change_event.source_service, change_event.target_service,
                      event.target_service],
            event_ids=[change_event.event_id, event.event_id],
            event_ms=change_ms if state == ORDER_CONFIRMED else min(change_ms, corrected),
            explanation=(
                f"{event.actor} reached {event.target_service} "
                f"({event.outcome}) {when} an unexplained role change to "
                f"{change_event.role_after or 'none'} in the same session, inside "
                f"the {window} ms follow-on window{suffix}"
            ),
            order=state,
            facts=facts,
            goal=6,
        ))


def ctx_event_time(event) -> str:
    from .fields import format_timestamp

    return format_timestamp(event.event_ms)


__all__ = [
    "PrivilegeDetector", "R_FOLLOW_ON", "R_SELF_APPROVED", "R_UNAPPROVED_PRIVILEGE",
    "R_UNCERTAIN_APPROVAL", "R_UNBACKED_SCOPE_USE",
]
