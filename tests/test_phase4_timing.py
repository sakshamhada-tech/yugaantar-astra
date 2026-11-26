"""Goal 8: clock offsets, out-of-order delivery, and refusing to guess.

The behaviour under test is *conservatism*: the detector must claim an order when
the arithmetic supports it and refuse when it does not. A test that only checked
"the offsets are subtracted" would pass on an implementation that silently sorted
by corrected time and reported confidence it had not earned.
"""

from __future__ import annotations

import pytest

from pqc_kv.detect import timing
from pqc_kv.detect.config import TimingConfig
from pqc_kv.detect.ingest import Event


def event(event_id, *, event_ms, received_ms=None, source="svc-a", offset_ms=0, index=0):
    return Event(
        event_id=event_id,
        event_ms=event_ms,
        received_ms=received_ms if received_ms is not None else event_ms + 100,
        offset_ms=offset_ms,
        actor="user-a",
        source_service=source,
        target_service="catalog",
        action="read",
        role_before="viewer",
        role_after="viewer",
        outcome="allow",
        approval_id="",
        session_id="s1",
        correlation_id="c1",
        receipt_index=index,
    )


def timeline(**overrides):
    return timing.Timeline(config=TimingConfig(**overrides).validate())


# --------------------------------------------------------------- correction
def test_declared_offset_is_subtracted():
    """The README's rule: subtract the source offset to get collector time."""
    tl = timeline()
    corrected = tl.observe(event("e-1", event_ms=1_000_000, offset_ms=2000))
    assert corrected == 998_000


def test_declared_offset_can_be_negative():
    tl = timeline()
    corrected = tl.observe(event("e-1", event_ms=1_000_000, offset_ms=-1500))
    assert corrected == 1_001_500


def test_the_raw_stamp_is_never_overwritten():
    """Source evidence must survive the correction, so a report can show both."""
    tl = timeline()
    raw = event("e-1", event_ms=1_000_000, offset_ms=2000)
    tl.observe(raw)
    assert raw.event_ms == 1_000_000
    assert tl.corrected["e-1"] == 998_000


def test_a_fast_source_no_longer_looks_later_than_a_slow_one():
    """The bug this whole module exists to prevent.

    Source ``fast`` is 5 s ahead. Its event reads 09:00:04 but really happened at
    08:59:59. Source ``slow`` is 0 and reads 09:00:00. Naively sorted, ``fast``
    looks later; corrected, it is clearly earlier.
    """
    tl = timeline()
    tl.observe(event("fast", event_ms=10_004_000, offset_ms=5000, source="fast"))
    tl.observe(event("slow", event_ms=10_000_000, offset_ms=0, source="slow"))
    assert tl.compare("fast", "slow") == timing.BEFORE
    assert tl.compare("slow", "fast") == timing.AFTER


# ------------------------------------------------------------------ compare
def test_a_small_gap_is_uncertain_not_guessed():
    """Two sources, 250 ms of uncertainty each: a 100 ms gap cannot be resolved."""
    tl = timeline(offset_uncertainty_ms=250)
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=1_000_100, source="s2"))
    assert tl.compare("a", "b") == timing.UNCERTAIN


def test_a_gap_larger_than_combined_uncertainty_is_claimed():
    tl = timeline(offset_uncertainty_ms=250)
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=1_000_600, source="s2"))
    assert tl.compare("a", "b") == timing.BEFORE


def test_the_boundary_is_exclusive():
    """Exactly at the combined uncertainty is still uncertain -- no free passes."""
    tl = timeline(offset_uncertainty_ms=250)
    # combined uncertainty = 500; gap = 500 must NOT establish an order
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=1_000_500, source="s2"))
    assert tl.compare("a", "b") == timing.UNCERTAIN
    # 501 ms is enough
    tl2 = timeline(offset_uncertainty_ms=250)
    tl2.observe(event("a", event_ms=1_000_000, source="s1"))
    tl2.observe(event("b", event_ms=1_000_501, source="s2"))
    assert tl2.compare("a", "b") == timing.BEFORE


def test_same_source_ordering_is_still_uncertain_at_zero_tolerance():
    """Uncertainty is per source, so two events from one source share an error bar."""
    tl = timeline(offset_uncertainty_ms=100)
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=1_000_150, source="s1"))
    assert tl.compare("a", "b") == timing.UNCERTAIN


def test_unknown_event_ids_are_uncertain_not_an_exception():
    tl = timeline()
    assert tl.compare("nope", "also-nope") == timing.UNCERTAIN


# ------------------------------------------------------------------- modes
def test_estimated_mode_uses_the_minimum_delay():
    """NTP's idea: delay is never negative, so the smallest delay bounds the offset."""
    tl = timeline(offset_mode="estimated")
    # source 2 s fast: every event arrives 2 s "early" plus real transit
    tl.observe(event("a", event_ms=1_000_000, received_ms=1_000_300, offset_ms=2000,
                     source="fast"))
    tl.observe(event("b", event_ms=1_000_500, received_ms=998_400, offset_ms=2000,
                     source="fast"))
    clock = tl.sources["fast"]
    assert clock.min_delay_ms == -2100
    assert clock.offset_ms == 2100


def test_estimated_mode_refuses_a_source_with_a_wild_spread():
    tl = timeline(offset_mode="estimated", max_offset_uncertainty_ms=1000)
    tl.observe(event("a", event_ms=1_000_000, received_ms=1_000_100, source="s"))
    tl.observe(event("b", event_ms=2_000_000, received_ms=2_100_000, source="s"))
    assert tl.sources["s"].unusable is True
    assert tl.compare("a", "b") == timing.UNCERTAIN


def test_none_mode_claims_no_cross_source_order_at_all():
    tl = timeline(offset_mode="none")
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=9_000_000, source="s2"))
    assert tl.compare("a", "b") == timing.UNCERTAIN


def test_negative_delivery_is_counted_not_condemned():
    """The README: 'Do not infer malicious activity from an apparent negative delay'."""
    tl = timeline(offset_mode="estimated")
    tl.observe(event("a", event_ms=1_000_000, received_ms=998_000, offset_ms=2000))
    assert tl.negative_delivery_events == 1
    assert tl.compare("a", "a") == timing.UNCERTAIN


# ------------------------------------------------------------------ reorder
def test_out_of_order_delivery_is_reordered_by_event_time():
    tl = timeline(max_out_of_order_ms=60_000)
    # received later, but happened earlier
    late_arrival = event("late", event_ms=1_000_000, received_ms=1_030_000, index=0)
    early_arrival = event("early", event_ms=1_010_000, received_ms=1_010_100, index=1)
    ordered, deferred = tl.reorder([late_arrival, early_arrival])
    assert [e.event_id for e in ordered] == ["late", "early"]
    assert deferred == []


def test_reordering_within_the_horizon_is_corrected_not_flagged():
    """A late arrival that is still inside the horizon is simply reordered.

    This is the *designed* behaviour and the reason for the buffer: the output is in
    event order, so no rule downstream has to reason about it. Deferral is for the
    cases this cannot fix.
    """
    tl = timeline(max_out_of_order_ms=1000)
    a = event("a", event_ms=1_000_000, received_ms=1_000_100, index=0)
    b = event("b", event_ms=1_005_000, received_ms=1_005_100, index=1)
    # c happened at 1_001_000 but arrives at 1_100_000: still inside 1000 ms of
    # corrected-time horizon *at the moment it arrives*, so it can be placed.
    c = event("c", event_ms=1_001_000, received_ms=1_100_000, index=2)
    ordered, deferred = tl.reorder([a, b, c])
    assert [e.event_id for e in ordered] == ["a", "c", "b"]
    assert deferred == []


def test_a_straggler_beyond_the_horizon_is_deferred_not_mis_ordered():
    """A late arrival *after* the pipeline moved on must be refused, not spliced in.

    ``a`` and ``b`` are released as receipts advance past them. ``c`` really happened
    just after ``a`` but arrives only once ``b`` has already been emitted. Emitting
    ``c`` after ``b`` would hand every downstream rule a sequence known to be wrong,
    so it is deferred instead. What must hold regardless: ``ordered`` is always in
    non-decreasing event time.
    """
    tl = timeline(max_out_of_order_ms=1000)
    a = event("a", event_ms=1_000_000, received_ms=1_000_100, index=0)
    b = event("b", event_ms=1_010_000, received_ms=1_010_100, index=1)
    d = event("d", event_ms=1_300_000, received_ms=1_300_100, index=2)   # advances receipts
    c = event("c", event_ms=1_001_000, received_ms=1_250_000, index=3)   # straggler
    ordered, deferred = tl.reorder([a, b, d, c])
    assert [e.event_id for e in deferred] == ["c"]
    assert "c" not in [e.event_id for e in ordered]
    stamps = [tl.corrected[e.event_id] for e in ordered]
    assert stamps == sorted(stamps)


def test_deferred_events_are_counted_in_the_report():
    tl = timeline(max_out_of_order_ms=1000)
    a = event("a", event_ms=1_000_000, received_ms=1_000_100, index=0)
    b = event("b", event_ms=1_010_000, received_ms=1_010_100, index=1)
    d = event("d", event_ms=1_300_000, received_ms=1_300_100, index=2)
    c = event("c", event_ms=1_001_000, received_ms=1_250_000, index=3)
    tl.reorder([a, b, d, c])
    assert tl.report()["out_of_order_events"] >= 1


def test_the_ordered_output_is_always_monotonic_under_a_stock_horizon():
    """The property, checked over messy random delivery patterns."""
    import random

    rng = random.Random(99)
    for _ in range(20):
        tl = timeline(max_out_of_order_ms=rng.choice([500, 2000, 10_000]))
        base = 1_000_000
        events = []
        for i in range(40):
            happened = base + rng.randint(0, 20_000)
            transit = rng.randint(10, 15_000)
            events.append(event(f"e{i}", event_ms=happened,
                                received_ms=happened + transit, index=i))
        ordered, deferred = tl.reorder(events)
        assert len(ordered) + len(deferred) == len(events)
        stamps = [tl.corrected[e.event_id] for e in ordered]
        assert stamps == sorted(stamps), "ordered output must never go backwards"


def test_the_buffer_capacity_is_enforced():
    tl = timeline(reorder_buffer_events=2, max_out_of_order_ms=10_000_000)
    events = [
        event(f"e{i}", event_ms=1_000_000 + i, received_ms=1_000_100 + i, index=i)
        for i in range(10)
    ]
    ordered, deferred = tl.reorder(events)
    # Everything is emitted exactly once, whatever the buffer size.
    assert len(ordered) + len(deferred) == 10
    assert {e.event_id for e in ordered + deferred} == {e.event_id for e in events}


def test_a_stable_sort_is_used_for_equal_times():
    tl = timeline()
    a = event("a", event_ms=1_000_000, received_ms=1_000_100, index=0)
    b = event("b", event_ms=1_000_000, received_ms=1_000_100, index=1)
    ordered, _ = tl.reorder([a, b])
    assert [e.event_id for e in ordered] == ["a", "b"]


# ------------------------------------------------------------------- report
def test_the_supported_range_is_stated_in_machine_readable_form():
    tl = timeline(max_out_of_order_ms=60_000, offset_uncertainty_ms=200)
    tl.observe(event("a", event_ms=1_000_000))
    report = tl.report()
    assert report["supported_range"]["max_out_of_order_ms"] == 60_000
    assert report["supported_range"]["per_source_uncertainty_ms"] == 200
    assert "uncertain" in report["supported_range"]["rule"]


def test_the_report_names_the_unorderable_sources():
    tl = timeline(offset_mode="none")
    tl.observe(event("a", event_ms=1_000_000, source="bad"))
    report = tl.report()
    assert report["unorderable_sources"] == ["bad"]
    assert report["sources"][0]["orderable"] is False


def test_describe_gap_reports_both_orders_when_uncertain():
    tl = timeline(offset_uncertainty_ms=500)
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=1_000_200, source="s2"))
    described = timing.describe_gap(tl, "a", "b")
    assert described["order"] == timing.ORDER_UNCERTAIN
    assert "both orders are possible" in described["explanation"]
    assert described["uncertainty_ms"] == 1000


def test_describe_gap_states_the_arithmetic_when_confirmed():
    tl = timeline(offset_uncertainty_ms=100)
    tl.observe(event("a", event_ms=1_000_000, source="s1"))
    tl.observe(event("b", event_ms=1_000_900, source="s2"))
    described = timing.describe_gap(tl, "a", "b")
    assert described["order"] == timing.ORDER_CONFIRMED
    assert described["gap_ms"] == 900


def test_no_wall_clock_is_read_anywhere_in_the_detector():
    """A source-level check, so a future edit cannot quietly introduce one.

    ``time.time`` would make the same log produce different alerts on different
    days. The only module allowed a clock is ``scripts/measure_timing.py``, which is
    instrumentation and not part of the package.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "src" / "pqc_kv" / "detect"
    forbidden = {
        ("time", "time"), ("time", "monotonic"), ("time", "perf_counter"),
        ("datetime", "now"), ("datetime", "utcnow"), ("datetime", "today"),
        ("datetime", "fromtimestamp"),
    }
    offenders = []
    for path in sorted(root.glob("*.py")):
        # Parsed, not grepped: this module's own docstring *says* the word
        # "time.time()", and a text search would flag the promise as a violation.
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value
                if isinstance(owner, ast.Name) and (owner.id, node.func.attr) in forbidden:
                    offenders.append(f"{path.name}:{node.lineno} {owner.id}.{node.func.attr}")
            # datetime.fromtimestamp(x, tz=...) is used legitimately for *rendering*
            # an already-computed integer; only the no-tz form reads the host clock.
    assert offenders == []
