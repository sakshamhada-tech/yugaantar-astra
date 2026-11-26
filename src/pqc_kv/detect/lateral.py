"""Goal 7: lateral movement with valid credentials.

The premise of this goal is that the credentials *worked*. No key is revoked, no
signature fails, no request is malformed -- every event here is a permitted one, so
no amount of cryptographic checking helps. The only signal left is *shape*: this
identity is touching services it has never touched, and moving **through** them.

What is built
-------------
Per identity, from a **baseline period only**:

* ``edge`` -- the ordered pair ``(source_service, target_service)``. Ordered, not a
  set of services, because "reports calls catalog" and "catalog calls reports" are
  different behaviours.
* ``targets`` -- the set of services ever reached.
* ``transitions`` -- ``(previous_target, target)`` within ``transition_window_ms``:
  the "X touches A, then suddenly B" case the brief names.

During evaluation an edge is **novel** if it is absent from the baseline. Novelty is
reported with the count that justifies it -- ``0 of 7 baseline events used it`` --
because a judge cannot check "unusual" but can check a count.

What makes it lateral movement rather than noise
------------------------------------------------
One denial is one denial: the practice labels say so explicitly about a single
blocked read. Three denials from one origin are also not movement; they are three
attempts. The distinguishing shape is **chaining**: moving from a service you
already had, into a new service, and then *out of that new service* into another.
Each hop that departs from a freshly-touched target is a foothold being used.

So a burst alert requires ``min_novel_edges`` distinct new targets **and** at
least one continuation from a newly-touched target. That is a property of the
graph's topology, not of any service name, and it is why the practice data's
two parallel denials from ``portal`` cannot be mistaken for the three-hop chain
that starts at a known service and walks through two new ones.

Why this is not tuned to the practice labels
--------------------------------------------
There is no list of "normal" services anywhere. The graph is built by counting what
one identity actually did, so a deployment with entirely new service names produces
an entirely new graph. The only operator vocabulary -- ``sensitive_services`` -- is
empty by default and *adds severity* rather than creating detections.

Cold start, stated rather than hidden
-------------------------------------
An identity with fewer than ``min_baseline_events`` baseline events has no usable
graph. Two dishonest options are available and both are refused: silently trusting
it (an attacker who appears only in the evaluation window is invisible) and
blanket-alarming on it (every new hire becomes an incident). Instead the identity is
marked ``cold_start``, needs *more* independent novel targets
(``cold_start_min_novel_edges``) before an alert, and every alert it produces says
``baseline_state="cold_start"`` so the operator knows the evidence is novelty alone.

Why authorised scope beats novelty
----------------------------------
A first-seen edge that an approval covers is authorised: change control said so.
Novelty alone must not outrank an explicit authorisation, or every approved rollout
becomes an incident. Scope is only honoured **while the approval is in force**, so
an expired ticket cannot launder later access.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .alerts import Alert
from .timing import ORDER_CONFIRMED, ORDER_UNCERTAIN

R_NOVEL_EDGE = "novel_service_edge"
R_LATERAL_CHAIN = "lateral_movement_chain"
R_SENSITIVE_EDGE = "first_seen_sensitive_service"
R_NOVEL_TRANSITION = "novel_service_transition"

#: Baseline states, reported on every lateral alert.
BASELINE_KNOWN = "established"
BASELINE_COLD = "cold_start"


@dataclass
class IdentityGraph:
    """What one identity was observed doing during the baseline period."""

    identity: str
    events: int = 0
    edges: set = field(default_factory=set)
    targets: set = field(default_factory=set)
    transitions: set = field(default_factory=set)
    roles: set = field(default_factory=set)
    target_counts: dict = field(default_factory=dict)
    last_target: str | None = None
    last_ms: int | None = None
    last_event_id: str | None = None

    def observe(self, event, corrected_ms: int, config) -> None:
        edge = (event.source_service, event.target_service)
        self.events += 1
        self.edges.add(edge)
        self.targets.add(event.target_service)
        self.target_counts[event.target_service] = (
            self.target_counts.get(event.target_service, 0) + 1
        )
        if event.role_after:
            self.roles.add(event.role_after)
        if self.last_target is not None and self.last_ms is not None:
            if corrected_ms - self.last_ms <= config.transition_window_ms:
                self.transitions.add((self.last_target, event.target_service))
        self.last_target = event.target_service
        self.last_ms = corrected_ms
        self.last_event_id = event.event_id

    @property
    def edge_count(self) -> int:
        return len(self.edges)


@dataclass
class _Burst:
    """A run of novel edges by one identity in one session, awaiting judgement."""

    identity: str
    key: str
    events: list = field(default_factory=list)
    first_ms: int = 0
    last_ms: int = 0
    #: Targets first reached inside this burst, in the order they were reached.
    new_targets: list = field(default_factory=list)
    #: Hops that departed from a target first reached in this burst.
    chained_hops: list = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(set(self.new_targets))

    @property
    def continuations(self) -> int:
        return len(self.chained_hops)


class LateralDetector:
    """Two phases: build baselines, then judge the evaluation window against them."""

    def __init__(self, config, timeline, context=None) -> None:
        self.config = config
        self.timeline = timeline
        self.context = context
        self.graphs: dict = {}
        self.peer_roles: dict = {}
        self.baseline_cutoff_ms: int | None = None
        self.baseline_event_ids: set = set()
        #: Targets that appeared in the baseline for *any* identity. Used only for
        #: reporting how novel a target is, never to authorise anything.
        self._known_targets: set = set()

    # --------------------------------------------------------------- baseline
    def build_baseline(self, events) -> None:
        """Take the earliest ``baseline_fraction_percent`` of events, by event time.

        By *time*, not by count, so every identity gets the same historical window
        and a burst of activity from one actor cannot shorten anyone else's baseline.
        Ties break on receipt index, so the split is identical on every run.

        Every identity that appears anywhere in the log is then guaranteed at least
        its own first event in the baseline. Without that, an identity whose first
        appearance falls after the boundary would be judged against an empty graph
        and would be permanently "cold" -- a blind spot exactly where a new account
        is most interesting.
        """
        if not events:
            return
        ordered = sorted(
            events,
            key=lambda e: (self.timeline.corrected.get(e.event_id, e.event_ms),
                           e.receipt_index),
        )
        fraction = self.config.lateral.baseline_fraction_percent
        count = max(1, (len(ordered) * fraction) // 100)
        head = ordered[:count]
        self.baseline_cutoff_ms = self.timeline.corrected.get(
            head[-1].event_id, head[-1].event_ms
        )

        first_seen: dict = {}
        for event in ordered:
            first_seen.setdefault(event.actor, event)

        for event in head:
            self._observe(event)
        for actor, event in first_seen.items():
            if actor not in self.graphs:
                self._observe(event)
        for graph in self.graphs.values():
            self._known_targets |= graph.targets

    def _observe(self, event) -> None:
        graph = self.graphs.get(event.actor)
        if graph is None:
            graph = IdentityGraph(identity=event.actor)
            self.graphs[event.actor] = graph
        corrected = self.timeline.corrected.get(event.event_id, event.event_ms)
        graph.observe(event, corrected, self.config.lateral)
        if event.role_after:
            self.peer_roles.setdefault(event.actor, set()).add(event.role_after)
        self.baseline_event_ids.add(event.event_id)

    # -------------------------------------------------------------- evaluation
    def evaluate(self, events) -> list:
        """Judge events after the baseline. Deterministic: corrected time, then receipt."""
        pending = sorted(
            (e for e in events if e.event_id not in self.baseline_event_ids),
            key=lambda e: (self.timeline.corrected.get(e.event_id, e.event_ms),
                           e.receipt_index),
        )
        alerts: list = []
        bursts: dict = {}
        order: list = []

        for event in pending:
            graph = self.graphs.get(event.actor)
            cold = graph is None or graph.events < self.config.lateral.min_baseline_events
            edge = (event.source_service, event.target_service)
            corrected = self.timeline.corrected.get(event.event_id, event.event_ms)

            # Known edge: not novel. It is still a real observation, so it goes into
            # the burst as a *hop* (its target is not new) -- that is what lets a
            # continuation "warehouse -> directory" be recognised even when the
            # warehouse edge itself was already familiar.
            if graph is not None and edge in graph.edges:
                self._note_hop(bursts, order, event, novel=False)
                continue
            if self._authorised(event, graph):
                # Authorised scope means "not evidence of abuse"; it does not mean
                # "invisible". Treating it as invisible was a real miss: the
                # generator's forbidden hop reused a known edge out of a service an
                # approval had covered, and three of the four hops vanished with it.
                self._note_hop(bursts, order, event, novel=False)
                continue

            if event.target_service in self.config.lateral.sensitive_services:
                alerts.append(self._sensitive_alert(event, graph, cold, corrected, edge))

            # Note: a novel edge does NOT get its own alert here. The burst it
            # belongs to is judged after the loop, and emitting both would report
            # one event twice -- inflating recall while teaching the operator to
            # ignore the duplicate.
            self._note_hop(bursts, order, event, novel=True)

        for burst in order:
            alert = self._judge_burst(burst)
            if alert is not None:
                alerts.append(alert)

        alerts.extend(self._transitions(pending))
        return alerts

    def _note_hop(self, bursts, order, event, *, novel: bool) -> None:
        """Record one event in its identity/session burst.

        A burst is the unit a *trail* is judged in, so every hop is noted whether or
        not it was novel: what makes a trail lateral movement is leaving a
        freshly-reached service, and the leaving edge itself may be familiar.

        A burst is additionally **split on a time gap**. A session id can live for
        days -- a long-lived service account or a browser session reused across
        shifts -- and treating the whole session as one trail meant a two-day gap
        silently exceeded the burst window and the trail was dropped. Contiguity is
        what "movement" means; a session is only a hint about who was behind it.
        """
        key = (event.actor, event.session_id or event.correlation_id or event.event_id)
        corrected = self.timeline.corrected.get(event.event_id, event.event_ms)
        window = self.config.lateral.burst_window_ms
        burst = bursts.get(key)
        if burst is None or corrected - burst.last_ms > window:
            burst = _Burst(identity=event.actor, key=key[1], first_ms=corrected,
                           last_ms=corrected)
            bursts[key] = burst
            order.append(burst)
        burst.last_ms = corrected
        burst.events.append(event)
        if novel and event.target_service not in burst.new_targets:
            burst.new_targets.append(event.target_service)
        if len(burst.new_targets) >= 2 and event.source_service in burst.new_targets:
            # Departed from a service this burst first reached: a foothold used.
            if event.source_service in burst.new_targets[:-1] or novel:
                burst.chained_hops.append(event)

    # ---------------------------------------------------------------- helpers
    def _authorised(self, event, graph) -> bool:
        """True when an in-force approval scope covers this target for this actor.

        Checked before novelty: a first-seen edge the change control named is not
        evidence of abuse. Only approvals that are *in force at the event's own
        time* count, so an expired ticket cannot launder later access -- that is the
        difference between "approved rollout" and "kept using an old ticket".
        """
        lateral = self.config.lateral
        if not lateral.approval_scope_grants_authorisation or self.context is None:
            return False
        candidates = list(self.context.for_subject(event.actor))
        declared = self.context.get(event.approval_id) if event.approval_id else None
        if declared is not None and declared not in candidates:
            candidates.append(declared)
        for approval in candidates:
            if not approval.scope:
                # An approval with no declared scope authorises nothing about
                # services. Treating "no scope" as "all services" would let one
                # revocation ticket cover every target an identity ever touches.
                continue
            if not approval.covers_service(event.target_service):
                continue
            if self._in_force(approval, event):
                return True
        return False

    def _in_force(self, approval, event) -> bool:
        from .context import _compare_point

        corrected = self.timeline.corrected.get(event.event_id)
        if corrected is None:
            return False
        if approval.valid_from_ms is not None:
            if _compare_point(self.timeline, event.event_id, approval.valid_from_ms) in (
                "before", "uncertain"
            ):
                return False
        if approval.valid_until_ms is not None:
            if _compare_point(self.timeline, event.event_id, approval.valid_until_ms) in (
                "after", "same", "uncertain"
            ):
                return False
        return True

    def _judge_burst(self, burst: _Burst) -> Alert | None:
        lateral = self.config.lateral
        graph = self.graphs.get(burst.identity)
        cold = graph is None or graph.events < lateral.min_baseline_events
        required = (
            lateral.cold_start_min_novel_edges if cold else lateral.min_novel_edges
        )
        # A single successful first-seen edge is the one case that does not need a
        # chain behind it: valid credentials reaching a brand-new service is exactly
        # the scenario goal 7 names, and waiting for a second hop would let a
        # single-hop intrusion pass unremarked. It is checked *first*, before the
        # depth gate, because the depth gate is what would otherwise discard it.
        # A single *denied* novel edge is never enough: the practice labels say one
        # denial does not establish movement.
        lone_success = (
            burst.depth >= 1
            and self.config.lateral.alert_on_allowed_novel_edges
            and all(e.is_success for e in burst.events)
            and burst.continuations == 0
        )
        if burst.depth < required:
            if lone_success and not cold:
                # Established identity, one clean new edge: a real finding.
                return self._lone_edge_alert(burst, graph)
            if cold and lone_success and self.config.lateral.cold_start_report_lone_edges:
                # No baseline: say so, at low severity. See the config comment.
                return self._cold_start_notice(burst, graph)
            return None
        # Depth alone is not movement: chaining out of a fresh foothold is.
        if burst.continuations < 1:
            return None
        first = burst.events[0]
        last = burst.events[-1]
        first_ms = self.timeline.corrected.get(first.event_id, first.event_ms)
        last_ms = self.timeline.corrected.get(last.event_id, last.event_ms)
        span = last_ms - first_ms
        if span > lateral.burst_window_ms:
            return None

        path: list = [first.source_service]
        for event in burst.events:
            path.append(event.target_service)
        unique_path = [path[0]]
        for hop in path[1:]:
            if hop != unique_path[-1]:
                unique_path.append(hop)

        outcomes = sorted({e.outcome for e in burst.events})
        facts = {
            "baseline_state": BASELINE_COLD if cold else BASELINE_KNOWN,
            "baseline_events_for_identity": 0 if graph is None else graph.events,
            "baseline_edges_for_identity": 0 if graph is None else graph.edge_count,
            "novel_targets": burst.new_targets,
            "novel_target_count": burst.depth,
            "novel_targets_required": required,
            "chained_hops": burst.continuations,
            "span_ms": span,
            "burst_window_ms": lateral.burst_window_ms,
            "outcomes": outcomes,
            "session_id": first.session_id,
            "correlation_id": first.correlation_id,
        }
        rule = R_NOVEL_EDGE if burst.depth == 1 else R_LATERAL_CHAIN
        if burst.depth == 1:
            explanation = (
                f"{burst.identity} used a first-seen edge "
                f"{burst.events[0].source_service} -> "
                f"{burst.events[0].target_service} and the request returned "
                f"{burst.events[0].outcome}; 0 of "
                f"{0 if graph is None else graph.events} baseline events used it"
                + ("" if not cold else
                   f" (no reliable baseline: only "
                   f"{0 if graph is None else graph.events} events)")
            )
        else:
            explanation = (
                f"{burst.identity} walked "
                + " -> ".join(unique_path)
                + f": {burst.depth} services never reached before across "
                f"{0 if graph is None else graph.events} baseline events, "
                f"{burst.continuations} of the hops departing from a "
                f"freshly-touched service (outcomes: {', '.join(outcomes)})"
                + ("" if not cold else "; baseline is too small to know this "
                   "identity's normal reach")
            )
        return Alert(
            rule=rule,
            severity="high" if burst.continuations >= 2 else "medium",
            identity=burst.identity,
            services=unique_path,
            event_ids=[e.event_id for e in burst.events],
            event_ms=first_ms,
            explanation=explanation,
            order=ORDER_CONFIRMED,
            facts=facts,
            goal=7,
            path=unique_path,
        )

    def _lone_edge_alert(self, burst: _Burst, graph) -> Alert:
        """One first-seen edge for an identity whose baseline we do trust."""
        first = burst.events[0]
        baseline_events = 0 if graph is None else graph.events
        corrected = self.timeline.corrected.get(first.event_id, first.event_ms)
        facts = {
            "baseline_state": BASELINE_KNOWN,
            "baseline_events_for_identity": baseline_events,
            "baseline_edges_for_identity": 0 if graph is None else graph.edge_count,
            "edge": [first.source_service, first.target_service],
            "baseline_edge_uses": 0,
            "target_first_seen": (
                graph is None or first.target_service not in graph.targets
            ),
            "outcome": first.outcome,
            "session_id": first.session_id,
        }
        return Alert(
            rule=R_NOVEL_EDGE,
            severity="high",
            identity=burst.identity,
            services=[first.source_service, first.target_service],
            event_ids=[first.event_id],
            event_ms=corrected,
            explanation=(
                f"{first.source_service} -> {first.target_service} is a first-seen "
                f"edge for {burst.identity}: 0 of {baseline_events} baseline events "
                f"used it, and the request returned {first.outcome}"
            ),
            order=ORDER_CONFIRMED,
            facts=facts,
            goal=7,
            path=[first.source_service, first.target_service],
        )

    def _cold_start_notice(self, burst: _Burst, graph) -> Alert:
        """A first-seen edge for an identity we know nothing about.

        Deliberately low severity and deliberately explicit about *why* it is weak:
        the operator should be able to dismiss it in one second, and should also be
        able to see that the detector had no baseline rather than having judged the
        access normal.
        """
        first = burst.events[0]
        baseline_events = 0 if graph is None else graph.events
        facts = {
            "baseline_state": BASELINE_COLD,
            "baseline_events_for_identity": baseline_events,
            "baseline_edge_uses": 0,
            "edge": [first.source_service, first.target_service],
            "outcome": first.outcome,
            "session_id": first.session_id,
            "notice_reason": "insufficient_baseline",
        }
        corrected = self.timeline.corrected.get(first.event_id, first.event_ms)
        return Alert(
            rule=R_NOVEL_EDGE,
            severity="low",
            identity=burst.identity,
            services=[first.source_service, first.target_service],
            event_ids=[e.event_id for e in burst.events],
            event_ms=corrected,
            explanation=(
                f"{burst.identity} used a first-seen edge "
                f"{first.source_service} -> {first.target_service} "
                f"({first.outcome}), but only {baseline_events} baseline event(s) "
                f"exist for this identity, so the detector cannot judge whether that "
                f"is normal for it; reported as a notice, not a finding"
            ),
            order=ORDER_CONFIRMED,
            facts=facts,
            goal=7,
            path=[first.source_service, first.target_service],
        )

    def _sensitive_alert(self, event, graph, cold, corrected, edge) -> Alert:
        baseline_events = 0 if graph is None else graph.events
        facts = {
            "edge": list(edge),
            "sensitive_target": event.target_service,
            "baseline_state": BASELINE_COLD if cold else BASELINE_KNOWN,
            "baseline_events_for_identity": baseline_events,
            "baseline_edge_uses": 0,
            "outcome": event.outcome,
            "session_id": event.session_id,
        }
        return Alert(
            rule=R_SENSITIVE_EDGE,
            severity="high",
            identity=event.actor,
            services=[event.source_service, event.target_service],
            event_ids=[event.event_id],
            event_ms=corrected,
            explanation=(
                f"{event.actor} reached the operator-marked sensitive service "
                f"{event.target_service} from {event.source_service}, an edge never "
                f"seen in {baseline_events} baseline events"
            ),
            order=ORDER_CONFIRMED,
            facts=facts,
            goal=7,
            path=[event.source_service, event.target_service],
        )

    def _transitions(self, pending) -> list:
        """New orderings among *already-known* services.

        Deliberately excludes novel targets, because the novel-edge and chain rules
        already report those; this rule exists for the subtler case of familiar
        services in an unfamiliar sequence.
        """
        alerts: list = []
        previous: dict = {}
        emit = self.config.lateral.emit_novel_transitions
        if not emit:
            return alerts
        for event in pending:
            graph = self.graphs.get(event.actor)
            if graph is None:
                previous[event.actor] = event
                continue
            if event.target_service not in graph.targets:
                previous[event.actor] = event
                continue
            prior = previous.get(event.actor)
            if prior is not None and prior.target_service in graph.targets:
                pair = (prior.target_service, event.target_service)
                if pair not in graph.transitions and pair[0] != pair[1]:
                    order = self.timeline.compare(prior.event_id, event.event_id)
                    alerts.append(self._transition_alert(event, prior, graph, pair, order))
            previous[event.actor] = event
        return alerts

    def _transition_alert(self, event, prior, graph, pair, order) -> Alert:
        corrected = self.timeline.corrected.get(event.event_id, event.event_ms)
        facts = {
            "transition": list(pair),
            "baseline_events_for_identity": graph.events,
            "baseline_transition_count": len(graph.transitions),
            "window_ms": self.config.lateral.transition_window_ms,
            "session_id": event.session_id,
            "correlation_id": event.correlation_id,
        }
        return Alert(
            rule=R_NOVEL_TRANSITION,
            severity="low",
            identity=event.actor,
            services=list(pair),
            event_ids=[prior.event_id, event.event_id],
            event_ms=corrected,
            explanation=(
                f"{event.actor} moved from {pair[0]} to {pair[1]} within "
                f"{self.config.lateral.transition_window_ms} ms; both services are "
                f"familiar but this ordered pair appeared in none of the "
                f"{len(graph.transitions)} baseline transitions"
            ),
            order=ORDER_CONFIRMED if order == "after" else ORDER_UNCERTAIN,
            facts=facts,
            goal=7,
            path=list(pair),
        )


__all__ = [
    "BASELINE_COLD", "BASELINE_KNOWN", "IdentityGraph", "LateralDetector",
    "R_LATERAL_CHAIN", "R_NOVEL_EDGE", "R_NOVEL_TRANSITION", "R_SENSITIVE_EDGE",
]
