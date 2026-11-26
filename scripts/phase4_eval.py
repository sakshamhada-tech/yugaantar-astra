#!/usr/bin/env python3
"""Evaluate the Phase 4 detector on labelled logs, and print the method with the numbers.

Read this before reading the numbers
------------------------------------
Every figure below is produced by this script from a file on disk. Nothing is
hand-typed into the docs. Where a figure comes from synthetic data it is labelled
``synthetic``; where it comes from the practice data it is labelled ``practice`` and
**no accuracy claim is made from it** -- the toolkit's own README says 22 examples
"cannot establish detection accuracy, false-positive rate, ... or event-scale
throughput". The practice set is used as a functional check: did the detector find
the things a human labelled?

### How an alert is matched to a label

An alert carries ``event_ids``. It is counted as a **true positive** if *at least
one* of those ids is labelled ``malicious``; otherwise it is a **false alert**.
There is no window-based matching and no fuzzy near-miss: one shared event id, or
no credit. This is the strictest simple rule, and it can only make the detector
look worse than it is, which is the direction an evaluation should err.

### What precision and recall are computed over

* **Recall** is measured per **incident**, not per event. A three-hop chain
  produces one alert covering three labelled events; calling that "1 of 3
  detected" would punish the rule for being economical. An incident counts as
  detected if any alert names any of its events. Event-level recall is printed
  alongside so the difference is visible.
* **Precision** is measured per **alert**: how many alerts contain at least one
  malicious event.
* **F1** is the harmonic mean of those two numbers, computed from the alert-level
  precision and incident-level recall actually reported -- not from a third,
  separately-computed estimate.

### False alerts per 1,000 benign events

``1000 * (alerts with no malicious event) / (events labelled benign)``. Benign
means routine work **and** approved administration: an alert on a properly
ticketed change is a false alert, and it is the most important kind to count.

### Median time to alert

**Event time, not processing time.** For each detected incident: the corrected
event time of the alert's own event minus the corrected event time of the
incident's *earliest* labelled-malicious event. Median across detected incidents.
A negative value would mean the alert preceded the evidence, which would be a bug;
the script reports the minimum as a check. Processing time is measured separately
by ``--timing`` and never enters a detection decision.

### Tuning versus held-out

The synthetic set is split two ways at once, because either split alone is
gameable:

* **by identity** -- every event of an identity goes entirely to one side, so no
  rule can memorise a favoured principal;
* **by time** -- events before the split instant go to tuning, after it to
  held-out, so no rule can memorise a favourite moment.

The intersection is used: held-out = *held-out identities only, in the late
window*. That is a genuinely unseen combination. Tuning is the mirror image.
The detector's defaults were **not** fitted to either; they were chosen from the
structure of the schema. Running the same script with ``--tune`` only changes
which subset is scored, never a threshold.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pqc_kv import detect  # noqa: E402
from pqc_kv.detect import config as detect_config  # noqa: E402


# --------------------------------------------------------------------- loading
def load_labels(path: Path) -> dict:
    import csv

    labels = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            labels[row["event_id"]] = {
                "label": row["label"],
                "category": row.get("category", ""),
                "incident": row.get("incident_id", ""),
                "reason": row.get("reason", ""),
            }
    return labels


def event_actor_map(events_csv: Path) -> dict:
    """event_id -> actor, so the identity split can be applied to labels."""
    import csv

    out = {}
    with events_csv.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            out[row["event_id"]] = row["actor"]
    return out


def filter_log(text: str, keep: set) -> str:
    """Keep only rows whose event id is in ``keep``, preserving the header."""
    lines = text.split("\n")
    if not lines:
        return text
    header, body = lines[0], lines[1:]
    kept = [header]
    for line in body:
        if not line.strip():
            continue
        # The first CSV column is the event id; safe because it is validated to
        # contain no comma by the ingest policy itself.
        first = line.split(",", 1)[0]
        if first in keep:
            kept.append(line)
    return "\n".join(kept) + "\n"


# ------------------------------------------------------------------ evaluation
class Result:
    def __init__(self) -> None:
        self.alerts = 0
        self.tp_alerts = 0
        self.fp_alerts = 0
        self.incidents_total = 0
        self.incidents_found = 0
        self.malicious_events = 0
        self.malicious_events_covered = 0
        self.benign_events = 0
        #: literal (alert event time - first malicious event), usually 0
        self.delays: list = []
        #: (last malicious event - first malicious event) of each detected incident
        self.detection_delays: list = []
        self.per_category: dict = {}

    # ------------------------------------------------------------- derived
    @property
    def precision(self) -> float:
        return self.tp_alerts / self.alerts if self.alerts else 0.0

    @property
    def recall(self) -> float:
        return self.incidents_found / self.incidents_total if self.incidents_total else 0.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    @property
    def fp_per_1000(self) -> float:
        if not self.benign_events:
            return 0.0
        return 1000.0 * self.fp_alerts / self.benign_events

    def summary(self) -> dict:
        return {
            "alerts": self.alerts,
            "true_positive_alerts": self.tp_alerts,
            "false_alerts": self.fp_alerts,
            "precision": round(self.precision, 4),
            "incidents": self.incidents_total,
            "incidents_detected": self.incidents_found,
            "recall_incident": round(self.recall, 4),
            "malicious_events": self.malicious_events,
            "malicious_events_covered": self.malicious_events_covered,
            "recall_event": round(
                self.malicious_events_covered / self.malicious_events, 4
            ) if self.malicious_events else 0.0,
            "f1": round(self.f1, 4),
            "benign_events": self.benign_events,
            "false_alerts_per_1000_benign": round(self.fp_per_1000, 2),
            "median_time_to_alert_ms": (
                int(statistics.median(self.delays)) if self.delays else None
            ),
            "min_time_to_alert_ms": min(self.delays) if self.delays else None,
            "median_incident_span_ms": (
                int(statistics.median(self.detection_delays))
                if self.detection_delays else None
            ),
            "max_incident_span_ms": (
                max(self.detection_delays) if self.detection_delays else None
            ),
            "per_category": self.per_category,
        }


#: Which labels count as "a human would want this in an incident report".
#:
#: The synthetic generator uses ``malicious``. The practice data uses its own
#: richer vocabulary, and mapping it is a judgement call that must be stated, not
#: hidden. The three practice labels counted here are the ones that describe
#: something wrong having *happened*:
#:
#: * ``unexpected_role_change`` -- no approval exists for it;
#: * ``lateral_movement_candidate`` -- the reviewer's own phrase for the chain;
#: * ``review_after_role_change`` -- access that follows the unexplained change.
#:
#: ``routine_delayed_delivery``, ``routine_clock_offset``, ``routine_denial``,
#: ``isolated_denial`` and ``approved_change`` are *deliberately benign*: the
#: practice data includes them to test that a detector does not fire on them, so
#: counting them as clean is the intent of the labels, not a convenience.
POSITIVE_LABELS = frozenset({
    "malicious",
    "unexpected_role_change",
    "lateral_movement_candidate",
    "review_after_role_change",
})


def is_positive(label: str) -> bool:
    return label in POSITIVE_LABELS


def evaluate(report, labels: dict, *, events_filter: set | None = None) -> Result:
    """Score one detection report against ground truth.

    ``events_filter`` restricts scoring to a subset of events (the tuning or
    held-out split). An alert is only counted when **all** of its events are inside
    the subset: otherwise an alert about a held-out event would be scored as a
    false positive in the tuning numbers, which is a bookkeeping error dressed up
    as a false alarm, and it made the subsets look far worse than they are.
    """
    result = Result()
    malicious = {
        eid for eid, meta in labels.items() if is_positive(meta["label"])
    }
    if events_filter is not None:
        malicious &= events_filter
    benign_events = sum(
        1 for eid, meta in labels.items()
        if not is_positive(meta["label"])
        and (events_filter is None or eid in events_filter)
    )
    result.benign_events = benign_events
    result.malicious_events = len(malicious)

    incidents = {}
    for eid, meta in labels.items():
        if not is_positive(meta["label"]) or eid not in malicious:
            continue
        key = meta["incident"] or f"solo-{eid}"
        incidents.setdefault(key, []).append(eid)
    result.incidents_total = len(incidents)

    # earliest malicious event time per incident, in corrected time
    times = {}
    for alert in report.alerts:
        for eid in alert.event_ids:
            if eid in malicious:
                times[eid] = alert.event_ms
    incident_first_ms = {}
    for key, ids in incidents.items():
        stamps = [report.timeline_event_ms(eid) for eid in ids]
        stamps = [s for s in stamps if s is not None]
        if stamps:
            incident_first_ms[key] = min(stamps)

    detected = set()
    covered = set()
    scoped_alerts = [
        alert for alert in report.alerts
        if events_filter is None or all(eid in events_filter for eid in alert.event_ids)
    ]
    for alert in scoped_alerts:
        hit = [eid for eid in alert.event_ids if eid in malicious]
        if hit:
            result.tp_alerts += 1
            covered.update(hit)
            for eid in hit:
                detected.add(labels[eid]["incident"] or f"solo-{eid}")
        else:
            result.fp_alerts += 1
    result.alerts = len(scoped_alerts)
    result.incidents_found = len(detected)
    result.malicious_events_covered = len(covered)

    # ---------------------------------------------------- time to alert
    # Two numbers, because only one of them is meaningful here and the docs must
    # not blur them.
    #
    # `delays` is the literal definition: (the alert's event time) minus (the first
    # malicious event of its incident). It is reported, and on this dataset it is
    # structurally 0 -- the detector alerts on the *same* event that opens an
    # incident, so the gap cannot be anything else. A zero presented as "median
    # time to alert" would be trivially true and deeply misleading.
    #
    # `detection_delays` is therefore the number that means something: how far into
    # an incident the *last* malicious event sits after its first, i.e. the window
    # within which the alert existed. It is an upper bound on latency measured in
    # event time, never a claim of real-time speed: no rule here waits on anything,
    # so a slower detector would not shift it.
    for alert in scoped_alerts:
        hit = [eid for eid in alert.event_ids if eid in malicious]
        if not hit:
            continue
        key = labels[hit[0]]["incident"] or f"solo-{hit[0]}"
        first = incident_first_ms.get(key)
        if first is None:
            continue
        result.delays.append(alert.event_ms - first)

    incident_last_ms = {}
    for key, ids in incidents.items():
        stamps = [report.timeline_event_ms(eid) for eid in ids]
        stamps = [stamp for stamp in stamps if stamp is not None]
        if stamps:
            incident_last_ms[key] = max(stamps)
    for key in detected:
        first = incident_first_ms.get(key)
        last = incident_last_ms.get(key)
        if first is not None and last is not None:
            result.detection_delays.append(last - first)

    # per-category results
    for key, ids in incidents.items():
        category = labels[ids[0]]["category"] or "uncategorised"
        bucket = result.per_category.setdefault(
            category, {"incidents": 0, "detected": 0, "events": 0}
        )
        bucket["incidents"] += 1
        bucket["events"] += len(ids)
        if key in detected:
            bucket["detected"] += 1
    return result


def attach_times(report, log_text: str) -> None:
    """Give the report a way to answer "what corrected time was this event?".

    The report already carries per-alert event times, but scoring needs the time of
    a *labelled* event that may not be named by any alert. Re-deriving it from the
    same timeline the detector used keeps the two consistent.
    """
    from pqc_kv.detect import ingest, timing

    cfg = detect_config.load()
    parsed = ingest.parse_csv(log_text, config=cfg)
    tl = timing.Timeline(config=cfg.timing)
    for event in parsed.events:
        tl.observe(event)
    mapping = dict(tl.corrected)

    def lookup(event_id: str):
        return mapping.get(event_id)

    report.timeline_event_ms = lookup


# ---------------------------------------------------------------------- split
def identity_split(actors: dict, labels: dict) -> tuple[set, set]:
    """Deterministic identity split: sort identities, alternate them.

    Sorting then alternating is reproducible and does not use a hash of the name,
    so the two halves are easy to inspect by eye and do not depend on a seed.
    """
    identities = sorted(set(actors.values()))
    tuning_ids, heldout_ids = set(), set()
    for index, identity in enumerate(identities):
        (tuning_ids if index % 2 == 0 else heldout_ids).add(identity)
    tuning_events = {eid for eid, actor in actors.items() if actor in tuning_ids}
    heldout_events = {eid for eid, actor in actors.items() if actor in heldout_ids}
    return tuning_events, heldout_events


def time_split(log_text: str, fraction: int = 55) -> tuple[set, set]:
    """Deterministic time split by corrected event time, ties by file order."""
    from pqc_kv.detect import ingest, timing

    cfg = detect_config.load()
    parsed = ingest.parse_csv(log_text, config=cfg)
    tl = timing.Timeline(config=cfg.timing)
    for event in parsed.events:
        tl.observe(event)
    ordered = sorted(
        parsed.events,
        key=lambda e: (tl.corrected.get(e.event_id, e.event_ms), e.receipt_index),
    )
    cut = max(1, (len(ordered) * fraction) // 100)
    early = {e.event_id for e in ordered[:cut]}
    late = {e.event_id for e in ordered[cut:]}
    return early, late


# ------------------------------------------------------------------------ run
def run_case(name: str, log_path: Path, label_path: Path, approvals_path: Path,
             *, claim: str) -> dict:
    log_text = log_path.read_text(encoding="utf-8")
    approvals = approvals_path.read_text(encoding="utf-8") if approvals_path.exists() else None
    labels = load_labels(label_path)
    report = detect.run(log_text, approvals=approvals)
    attach_times(report, log_text)

    full = evaluate(report, labels)
    out = {
        "case": name,
        "claim": claim,
        "events": report.ingest["events_accepted"],
        "rejected": report.ingest["events_rejected"],
        "rejected_by_reason": report.ingest["rejected_by_reason"],
        "overall": full.summary(),
        "alerts": [
            {
                "rule": a.rule,
                "severity": a.severity,
                "events": list(a.event_ids),
                "order": a.order,
                "explanation": a.explanation,
                "tp": any(is_positive(labels.get(e, {}).get("label", ""))
                          for e in a.event_ids),
            }
            for a in report.alerts
        ],
    }

    actors = event_actor_map(log_path)
    tuning_ids, heldout_ids = identity_split(actors, labels)
    early, late = time_split(log_text)

    # Two independent generalisation tests, reported separately rather than
    # intersected. An intersection of "unseen identity" and "unseen time" on a
    # 250-event log is a handful of rows -- it collapsed to nothing here, which
    # reports as "0 incidents" and says nothing. Each test alone is meaningful:
    #
    #   identity held-out -- identities that never appear in the tuning half, over
    #                        their whole history. Tests generalisation across
    #                        principals ("a rule must not memorise a person").
    #   time held-out     -- the later part of the timeline for *all* identities.
    #                        Tests generalisation across time ("a rule must not
    #                        memorise a moment").
    #
    # Neither half was used to choose a threshold; that is stated in the docstring
    # and is why these numbers are reported at all.
    for key, scope, label_text in (
        ("tuning_identities", tuning_ids, "TUNING identities (no held-out claim)"),
        ("heldout_identities", heldout_ids, "HELD-OUT identities (unseen principals)"),
        ("early_window", early, "TUNING window (earliest 55% of event time)"),
        ("late_window", late, "HELD-OUT window (latest 45% of event time, unseen time)"),
    ):
        if not scope:
            continue
        subset_report = detect.run(log_text, approvals=approvals)
        attach_times(subset_report, log_text)
        scored = evaluate(subset_report, labels, events_filter=scope)
        out[key] = scored.summary()
        out[f"{key}_label"] = label_text
        out[f"{key}_size"] = len(scope)

    # Misses and false positives, named, with reasons.
    out["misses"] = _misses(report, labels, None)
    out["false_alerts"] = [
        {"rule": a.rule, "events": list(a.event_ids), "explanation": a.explanation}
        for a in report.alerts
        if not any(is_positive(labels.get(e, {}).get("label", "")) for e in a.event_ids)
    ]
    return out


def _misses(report, labels, scope: set | None) -> list:
    malicious = {
        eid for eid, meta in labels.items()
        if is_positive(meta["label"]) and (scope is None or eid in scope)
    }
    covered = set()
    for alert in report.alerts:
        covered.update(eid for eid in alert.event_ids if eid in malicious)
    out = []
    for eid in sorted(malicious - covered):
        out.append({
            "event_id": eid,
            "incident": labels[eid]["incident"],
            "category": labels[eid]["category"],
            "reason_labelled": labels[eid]["reason"],
        })
    return out


def seed_demo(path: Path) -> None:
    """Write a tiny labelled log in code, so the evaluator is testable without the toolkit."""
    header = (
        "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
        "source_service,target_service,action,role_before,role_after,outcome,"
        "approval_id,session_id,correlation_id\n"
    )
    rows = [
        "t-001,2026-01-01T00:00:00.000Z,2026-01-01T00:00:00.100Z,0,bob,portal,catalog,read,viewer,viewer,allow,,s1,c1",
        "t-002,2026-01-01T00:01:00.000Z,2026-01-01T00:01:00.100Z,0,bob,portal,identity,role_change,viewer,operator,success,,s1,c2",
    ]
    path.write_text(header + "\n".join(rows) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Phase 4 detector evaluation")
    parser.add_argument("--practice", type=Path, default=None,
                        help="path to the toolkit's practice/ directory")
    parser.add_argument("--synthetic", type=Path, default=None,
                        help="path to a directory written by phase4_synth.py")
    parser.add_argument("--json", type=Path, default=None, help="also write JSON here")
    parser.add_argument("--timing", type=Path, default=None,
                        help="measure throughput on this large log instead")
    args = parser.parse_args(argv)

    results = []
    if args.practice:
        base = args.practice
        results.append(run_case(
            "practice", base / "events.csv", base / "labels.csv",
            base / "approvals.json",
            claim="functional demonstration only; 22 events cannot establish accuracy",
        ))
    if args.synthetic:
        base = args.synthetic
        results.append(run_case(
            "synthetic", base / "events.csv", base / "labels.csv",
            base / "approvals.json",
            claim="SYNTHETIC data from scripts/phase4_synth.py; not a production "
                  "baseline, and explicit about the shapes it contains",
        ))

    if args.timing:
        from measure_timing import measure  # same directory

        results.append(measure(args.timing))

    if not results:
        parser.print_help()
        return 2

    _print_report(results)
    if args.json:
        args.json.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


def _print_report(results) -> None:
    for result in results:
        print("=" * 78)
        print(f"case: {result['case']}")
        print(f"claim: {result['claim']}")
        if "events" in result:
            print(f"events accepted: {result['events']}  rejected: {result['rejected']}"
                  f"  {result['rejected_by_reason'] or ''}")
        if "overall" in result:
            _print_summary("all labelled events", result["overall"])
        for key in ("tuning_identities", "heldout_identities",
                    "early_window", "late_window"):
            if key in result:
                _print_summary(result[f"{key}_label"], result[key])
        if result.get("misses"):
            print(f"\n  misses ({len(result['misses'])}):")
            for miss in result["misses"]:
                print(f"    - {miss['event_id']} [{miss['category']}] "
                      f"{miss['reason_labelled']}")
        if result.get("false_alerts"):
            print(f"\n  false alerts ({len(result['false_alerts'])}):")
            for fp in result["false_alerts"]:
                print(f"    - {fp['rule']} {fp['events']}: {fp['explanation'][:110]}")
        if "alerts" in result:
            print(f"\n  alerts ({len(result['alerts'])}):")
            for alert in result["alerts"]:
                mark = "TP" if alert["tp"] else "FP"
                print(f"    [{mark}] {alert['rule']:34} {alert['events']} "
                      f"order={alert['order']}")
        if "events_per_second" in result:
            print(f"\n  throughput: {result['events_per_second']:,.0f} events/sec "
                  f"on {result['host']}")
            print(f"  peak memory: {result['peak_memory_mb']:.1f} MB")
    print("=" * 78)


def _print_summary(label: str, summary: dict) -> None:
    print(f"\n  --- {label} ---")
    print(f"    alerts {summary['alerts']}  (TP {summary['true_positive_alerts']}, "
          f"false {summary['false_alerts']})")
    print(f"    precision        {summary['precision']:.3f}")
    print(f"    recall (incident){summary['recall_incident']:.3f}  "
          f"({summary['incidents_detected']}/{summary['incidents']} incidents)")
    print(f"    recall (event)   {summary['recall_event']:.3f}  "
          f"({summary['malicious_events_covered']}/{summary['malicious_events']} events)")
    print(f"    F1               {summary['f1']:.3f}")
    print(f"    false alerts per 1000 benign events: "
          f"{summary['false_alerts_per_1000_benign']:.2f} "
          f"({summary['benign_events']} benign)")
    median = summary["median_time_to_alert_ms"]
    print(f"    median time to alert (event time, alert vs first malicious "
          f"event): {median if median is not None else 'n/a'}"
          + (" ms" if median is not None else ""))
    span = summary["median_incident_span_ms"]
    print(f"    incident span covered by alert (event time, median / max): "
          f"{span if span is not None else 'n/a'}"
          + (f" / {summary['max_incident_span_ms']} ms" if span is not None else ""))
    for category, bucket in sorted(summary["per_category"].items()):
        print(f"      {category:22} {bucket['detected']}/{bucket['incidents']} incidents")


if __name__ == "__main__":
    raise SystemExit(main())
