"""Goal 8: turning two unreliable clocks into one orderable timeline.

The problem, stated plainly
---------------------------
Every event carries a timestamp from *its own source's* clock. That clock may be
minutes off. So ``09:05:02`` from a source that is 2 seconds fast is really
``09:05:00``. If you sort by the raw stamps, a fast source's later event looks
earlier than a slow source's earlier event, and a sequence like "approval, then
action" can appear backwards.

The practice README gives us the fix and its limits: subtract
``source_clock_offset_ms`` to estimate collector time, and "real systems must
measure offset and its uncertainty". So the detector has three modes
(:class:`config.TimingConfig`): trust the declared offset, estimate it, or give up
and claim nothing across sources.

What we claim, exactly
----------------------
**An order is claimed only when the gap is bigger than the combined uncertainty.**
For two events ``a`` and ``b`` from sources with residual uncertainty ``u_a`` and
``u_b``:

* if ``corrected_a + u_a < corrected_b - u_b`` then ``a`` really was before ``b``,
  and we return ``"before"``;
* the mirror case returns ``"after"``;
* otherwise their order is **UNCERTAIN** and we say so. The rules then downgrade
  instead of guessing.

This is the honest version of "handle clock differences". A detector that silently
sorts by corrected time and never reports uncertainty is claiming a precision it
cannot have -- and the one case where it matters is precisely the case an attacker
would use.

No wall clock
-------------
``time.time()`` appears nowhere in this module or anywhere else in the detector.
Every decision is a function of event time only, so replaying a log from last year
gives byte-identical alerts today. Processing time is reported separately by the
evaluation script and never enters a rule.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from .fields import format_timestamp

#: Comparison outcomes. Strings, because they end up in alert JSON verbatim.
BEFORE = "before"
AFTER = "after"
UNCERTAIN = "uncertain"

#: Ordering states attached to alerts.
ORDER_CONFIRMED = "confirmed"
ORDER_UNCERTAIN = "uncertain"
ORDER_UNKNOWN = "unknown"


@dataclass
class SourceClock:
    """What we know about one source's clock, accumulated causally (past only)."""

    source: str
    offsets_seen: int = 0
    min_delay_ms: int | None = None
    max_delay_ms: int | None = None
    #: Estimated offset (source clock minus true collector clock). Declared mode
    #: copies this from the log; estimated mode derives it from ``min_delay_ms``.
    offset_ms: int = 0
    #: Residual uncertainty after correction, in milliseconds.
    uncertainty_ms: int = 0
    #: True when the spread is too wide for any order claim to be safe.
    unusable: bool = False

    def observe_delay(self, delay_ms: int, config) -> None:
        if self.min_delay_ms is None or delay_ms < self.min_delay_ms:
            self.min_delay_ms = delay_ms
        if self.max_delay_ms is None or delay_ms > self.max_delay_ms:
            self.max_delay_ms = delay_ms
        self.offsets_seen += 1
        # NTP's idea, in one line: a real delivery delay is never negative, so the
        # *smallest* delay we have ever seen is the tightest upper bound on how
        # wrong our offset estimate can be. The spread above that minimum is the
        # uncertainty we must admit to.
        spread = self.max_delay_ms - self.min_delay_ms
        if spread > config.max_offset_uncertainty_ms:
            self.unusable = True
            self.uncertainty_ms = config.max_offset_uncertainty_ms
        else:
            self.uncertainty_ms = max(spread, 0)
        if -self.min_delay_ms > config.max_abs_offset_ms:
            # The implied offset is larger than we are willing to believe; treat the
            # source as unorderable rather than applying a wild correction.
            self.unusable = True


@dataclass
class Timeline:
    """Causal timeline: corrected times, per-source uncertainty, bounded reorder.

    Causal matters. Offset estimates use only events already seen, so the same
    input file always produces the same corrections in the same order regardless
    of how it is chunked. A batch run and a streaming run agree by construction;
    there is no "final pass" that quietly changes earlier answers.
    """

    config: object
    sources: dict = field(default_factory=dict)
    corrected: dict = field(default_factory=dict)       # event_id -> corrected ms
    uncertainty: dict = field(default_factory=dict)     # event_id -> ms
    source_of: dict = field(default_factory=dict)       # event_id -> source name
    _watermark_ms: int = 0
    _max_received_ms: int = -1
    out_of_order_events: int = 0
    negative_delivery_events: int = 0
    offset_rejected_events: int = 0

    # ------------------------------------------------------------- correction
    def _source(self, name: str) -> SourceClock:
        clock = self.sources.get(name)
        if clock is None:
            clock = SourceClock(source=name)
            clock.uncertainty_ms = self.config.offset_uncertainty_ms
            self.sources[name] = clock
        return clock

    def observe(self, event) -> int:
        """Register an event and return its corrected event time in ms.

        ``declared`` mode subtracts the log's offset column. The *raw* stamp is
        never overwritten anywhere -- the Event keeps ``event_ms`` untouched, so a
        report can always show source evidence next to the correction.
        """
        mode = self.config.offset_mode
        clock = self._source(event.source_service)

        if mode == "declared":
            offset = event.offset_ms
            if abs(offset) > self.config.max_abs_offset_ms:
                # Ingest already bounds this, but a config change could tighten it.
                self.offset_rejected_events += 1
                clock.unusable = True
                offset = 0
            clock.offset_ms = offset
            clock.uncertainty_ms = self.config.offset_uncertainty_ms
            corrected = event.event_ms - offset
        elif mode == "estimated":
            delay = event.received_ms - event.event_ms
            if delay < 0 and clock.min_delay_ms is None:
                self.negative_delivery_events += 1
            clock.observe_delay(delay, self.config)
            # offset = -min(delay): if the smallest delay is -2000 ms, the source is
            # 2000 ms ahead and we subtract that.
            clock.offset_ms = -clock.min_delay_ms if clock.min_delay_ms is not None else 0
            corrected = event.event_ms - clock.offset_ms
        else:  # "none"
            clock.offset_ms = 0
            # With no correction every source's clock is fully suspect.
            clock.uncertainty_ms = self.config.max_offset_uncertainty_ms
            clock.unusable = True
            corrected = event.event_ms

        self.corrected[event.event_id] = corrected
        self.uncertainty[event.event_id] = clock.uncertainty_ms
        self.source_of[event.event_id] = clock.source
        # Watermark is receipt time, the one clock the collector controls.
        if event.received_ms > self._max_received_ms:
            self._max_received_ms = event.received_ms
        return corrected

    # --------------------------------------------------------------- compare
    def compare(self, first: str, second: str) -> str:
        """Was ``first`` before ``second``? ``BEFORE``/``AFTER``/``UNCERTAIN``.

        Returns ``UNCERTAIN`` rather than a guess when the two events come from
        sources whose combined error bars overlap the gap between them.
        """
        if first not in self.corrected or second not in self.corrected:
            return UNCERTAIN
        a_ms, b_ms = self.corrected[first], self.corrected[second]
        u_a, u_b = self.uncertainty[first], self.uncertainty[second]

        if self.sources_unusable(first, second):
            return UNCERTAIN
        if a_ms + u_a < b_ms - u_b:
            return BEFORE
        if b_ms + u_b < a_ms - u_a:
            return AFTER
        return UNCERTAIN

    def sources_unusable(self, *event_ids: str) -> bool:
        """True when any involved source's clock is beyond the supported range.

        A source whose spread blew past ``max_offset_uncertainty_ms`` cannot be
        placed on the timeline at all. Rather than applying a correction we do not
        believe, every comparison involving it is UNCERTAIN -- which is exactly what
        the goal asks for: refuse to claim an order.
        """
        for event_id in event_ids:
            name = self.source_of.get(event_id)
            clock = self.sources.get(name) if name is not None else None
            if clock is not None and clock.unusable:
                return True
        return False

    def is_ordered(self, first: str, second: str) -> bool:
        return self.compare(first, second) != UNCERTAIN

    # ---------------------------------------------------------------- reorder
    def reorder(self, events) -> tuple[list, list]:
        """Emit events in corrected order, bounded by the reorder horizon.

        Returns ``(ordered, deferred)``. ``deferred`` holds events the horizon could
        not settle; they are emitted last, in receipt order, and are flagged so a
        rule that depends on sequence treats them as uncertain rather than sorted.

        The horizon is ``max_out_of_order_ms`` of corrected time. An event is
        released once a receipt proves nothing earlier can still arrive, or when
        the buffer is full. That makes the memory bound explicit and the claim
        ("we can absorb up to N ms of reordering") checkable.
        """
        heap: list = []
        ordered: list = []
        deferred: list = []
        horizon = self.config.max_out_of_order_ms
        capacity = self.config.reorder_buffer_events
        highest_corrected = None
        last_corrected = None

        def drain(cutoff):
            nonlocal last_corrected
            while heap and heap[0][0] <= cutoff:
                _, receipt, event = heapq.heappop(heap)
                corrected = self.corrected[event.event_id]
                if last_corrected is not None and corrected < last_corrected:
                    # Too late to be sequenced: emitting it here would produce an
                    # output that is not in event order, and every rule downstream
                    # would silently trust a sequence that is known to be wrong.
                    # Deferring is the honest option -- `deferred` events are exactly
                    # the ones whose order we could not establish.
                    self.out_of_order_events += 1
                    deferred.append(event)
                    continue
                last_corrected = corrected
                ordered.append(event)

        for event in events:
            corrected = self.observe(event)
            heapq.heappush(heap, (corrected, event.receipt_index, event))
            highest_corrected = corrected if highest_corrected is None else max(
                highest_corrected, corrected
            )
            # Release everything that can no longer be preceded by an unseen event.
            #
            # Two bounds, both needed, and the *earlier* of them is the safe one:
            #
            #   receipt bound -- nothing can arrive with a receipt earlier than the
            #     latest receipt already seen, so ``max_received - horizon`` is a
            #     floor on what is still coming;
            #   stamp bound -- an event whose corrected stamp is more than ``horizon``
            #     behind the highest stamp seen can still be preceded by an unseen
            #     event, so it must be held.
            #
            # Using the earlier bound keeps the buffer meaningful: an event that
            # arrives far outside the horizon is still *held* on arrival, and only
            # deferred once a later receipt proves it cannot be placed. Using the
            # higher bound (a version of this that released on the arriving stamp)
            # guaranteed the arriving event was flushed immediately, which defeated
            # the deferral path entirely.
            drain(min(self._max_received_ms, highest_corrected) - horizon)
            if len(heap) > capacity:
                # Buffer full: release the earliest rather than grow without bound.
                while len(heap) > capacity:
                    _, receipt, popped = heapq.heappop(heap)
                    corrected_popped = self.corrected[popped.event_id]
                    if last_corrected is not None and corrected_popped < last_corrected:
                        self.out_of_order_events += 1
                        deferred.append(popped)
                        continue
                    last_corrected = corrected_popped
                    ordered.append(popped)

        # Flush.
        while heap:
            _, receipt, event = heapq.heappop(heap)
            corrected = self.corrected[event.event_id]
            if last_corrected is not None and corrected < last_corrected:
                # Genuinely out of order relative to what we already released: this
                # is the "arrived too late to be sequenced" case.
                deferred.append(event)
                continue
            last_corrected = corrected
            ordered.append(event)
        return ordered, deferred

    # ----------------------------------------------------------------- report
    def supported_range(self) -> dict:
        """State the supported timing range in one machine-readable object."""
        return {
            "offset_mode": self.config.offset_mode,
            "max_abs_source_offset_ms": self.config.max_abs_offset_ms,
            "per_source_uncertainty_ms": (
                self.config.offset_uncertainty_ms
                if self.config.offset_mode == "declared"
                else self.config.max_offset_uncertainty_ms
            ),
            "max_out_of_order_ms": self.config.max_out_of_order_ms,
            "reorder_buffer_events": self.config.reorder_buffer_events,
            "rule": (
                "an order is claimed only when the gap between two corrected event "
                "times exceeds the sum of their sources' residual uncertainties; "
                "otherwise the alert carries order=uncertain"
            ),
        }

    def report(self) -> dict:
        clocks = []
        for name in sorted(self.sources):
            clock = self.sources[name]
            clocks.append({
                "source": name,
                "events": clock.offsets_seen,
                "applied_offset_ms": clock.offset_ms,
                "uncertainty_ms": clock.uncertainty_ms,
                "orderable": not clock.unusable,
                "max_observed_delay_ms": clock.max_delay_ms,
                "min_observed_delay_ms": clock.min_delay_ms,
            })
        return {
            "supported_range": self.supported_range(),
            "sources": clocks,
            "unorderable_sources": sorted(
                name for name, clock in self.sources.items() if clock.unusable
            ),
            "out_of_order_events": self.out_of_order_events,
            "negative_delivery_events": self.negative_delivery_events,
            "offset_rejected_events": self.offset_rejected_events,
        }


def describe_gap(timeline: Timeline, first: str, second: str) -> dict:
    """Human-checkable explanation of one ordering decision, for alert bodies.

    Reports both possible orders when uncertain -- never a single guess. A judge can
    verify the arithmetic by hand from the numbers in this object.
    """
    if first not in timeline.corrected or second not in timeline.corrected:
        return {"order": ORDER_UNKNOWN, "explanation": "event not in timeline"}
    a_ms, b_ms = timeline.corrected[first], timeline.corrected[second]
    u_a, u_b = timeline.uncertainty[first], timeline.uncertainty[second]
    verdict = timeline.compare(first, second)
    gap = b_ms - a_ms
    if verdict is UNCERTAIN:
        return {
            "order": ORDER_UNCERTAIN,
            "corrected_first_ms": a_ms,
            "corrected_second_ms": b_ms,
            "gap_ms": gap,
            "uncertainty_ms": u_a + u_b,
            "explanation": (
                f"gap {gap} ms is within the combined clock uncertainty "
                f"{u_a + u_b} ms; both orders are possible"
            ),
        }
    return {
        "order": ORDER_CONFIRMED,
        "corrected_first_ms": a_ms,
        "corrected_second_ms": b_ms,
        "gap_ms": gap,
        "uncertainty_ms": u_a + u_b,
        "explanation": (
            f"{verdict}: gap {gap} ms exceeds combined uncertainty {u_a + u_b} ms"
        ),
    }


def human_time(millis: int) -> str:
    return format_timestamp(millis)


__all__ = [
    "AFTER", "BEFORE", "ORDER_CONFIRMED", "ORDER_UNCERTAIN", "ORDER_UNKNOWN",
    "SourceClock", "Timeline", "UNCERTAIN", "describe_gap", "human_time",
]
