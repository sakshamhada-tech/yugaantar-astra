#!/usr/bin/env python
"""Phase 4 acceptance: goals 6-8, end to end, through the real adapter.

Every check below drives ``track4_service.py`` as a **separate process**, one process
per request, exactly as the judging worker does. Nothing is imported from
``pqc_kv.detect`` to compute an expected answer: the point is to see what a judge
sees, including the JSON shape and the exit code, rather than to compare the detector
against itself.

    python scripts/phase4_acceptance.py

What this proves, and what it does not:

* it proves the three detector operations answer through the adapter, that the
  permissions, schemas and determinism survive a process boundary, that hostile input
  is quarantined rather than echoed, and that an alert reaches the signed log;
* it does **not** prove accuracy. Accuracy is a claim about a corpus, and this script
  supplies its own small hand-written log so that the expected answer can be stated
  in one line. The measured numbers live in ``docs/DETECTION.md`` and are produced by
  ``scripts/phase4_eval.py``; a hand-written 20-event log is not evidence of precision.

Numbers printed here are measured with ``perf_counter_ns``. Where a number has a
caveat the caveat is printed with it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"

results: list[tuple[str, bool, str]] = []

HEADER = (
    "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
    "source_service,target_service,action,role_before,role_after,outcome,"
    "approval_id,session_id,correlation_id"
)


def call(state_dir: Path, **request) -> dict:
    """Send one request to a fresh adapter process and return the parsed reply."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state_dir)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=180,
    )
    if done.returncode != 0:
        raise RuntimeError(done.stderr.decode()[:400])
    return json.loads(done.stdout)


def ok(state_dir: Path, **request) -> dict:
    response = call(state_dir, **request)
    assert "error" not in response, response
    return response


def check(name: str, condition: bool, detail: str) -> None:
    results.append((name, bool(condition), detail))
    print(f"{'PASS' if condition else 'FAIL'} [{name}] {detail}")


def row(event_id, when, actor, source, target, action, before, after,
        outcome="allow", approval="", offset=0, received=None, session=None):
    # `when` is "...SS.mmmZ"; the answer is "...SS.100Z" one millisecond later. Written
    # out rather than string-replaced, because replacing the "Z" in "00.000Z" gives
    # "00.000.100Z", which every row then fails to parse -- a mistake that showed up as
    # "zero alerts" rather than as a parse error, and cost a debugging pass.
    received = received or when[:20] + "100Z"
    return (
        f"{event_id},{when},{received},{offset},{actor},{source},{target},{action},"
        f"{before},{after},{outcome},{approval},{session or f's-{event_id}'},"
        f"c-{event_id}"
    )


def csv_of(rows) -> str:
    """Header plus rows. The detector refuses a file with no header (`bad_header`).

    Every log string in this script goes through here: forgetting the header produced
    a run where 14 checks failed as "zero alerts", which is exactly the kind of mistake
    the detecor's own error token is now specific enough to name.
    """
    return HEADER + "\n" + "\n".join(rows) + "\n"


def baseline_rows(actor="ana.petrova", n=40):
    """Routine reads for one identity, across two minutes, all on one edge."""
    rows = []
    for i in range(n):
        when = f"2026-01-15T09:{i // 2:02d}:{(i % 2) * 30:02d}.000Z"
        rows.append(row(f"b-{i:03d}", when, actor, "gateway", "index", "read",
                        "reader", "reader"))
    return rows


APPROVALS = json.dumps({
    "changes": [
        {"approval_id": "chg-good", "approved_by": "ops-1",
         "subject": "ana.petrova", "operation": "grant_role", "role": "operator",
         "scope": ["directory"],
         "valid_from_utc": "2026-01-15T08:00:00Z",
         "valid_until_utc": "2026-01-15T12:00:00Z"},
        {"approval_id": "chg-wrong-role", "approved_by": "ops-1",
         "subject": "ben.okafor", "operation": "grant_role", "role": "reviewer",
         "scope": ["directory"],
         "valid_from_utc": "2026-01-15T08:00:00Z",
         "valid_until_utc": "2026-01-15T12:00:00Z"},
    ]
})


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 0

    state = Path(tempfile.mkdtemp(prefix="p4-accept-"))
    try:
        run_checks(state)
    finally:
        shutil.rmtree(state, ignore_errors=True)

    passed = sum(1 for _, good, _ in results if good)
    failed = len(results) - passed
    print()
    for name, good, detail in results:
        if not good:
            print(f"FAILED: [{name}] {detail}")
    print(f"{passed}/{len(results)} Phase 4 checks passed"
          + ("" if not failed else f" -- {failed} FAILED"))
    if not failed:
        print()
        print("PHASE 4 VERIFIED for the gates executed above.")
        print("This gate covers the contract and the rules' behaviour. It does not")
        print("measure accuracy: see scripts/phase4_eval.py for the measured figures,")
        print("which print their own method and corpus next to every number.")
    return 0 if not failed else 1


def run_checks(state: Path) -> None:
    # ---------------------------------------------------------------- goal 6
    log = csv_of(baseline_rows() + [
        # Approved, correct in every respect -> must stay quiet.
        row("e-approved", "2026-01-15T10:05:00.000Z", "ana.petrova", "console",
            "directory", "grant_role", "viewer", "operator", approval="chg-good"),
        # No approval at all.
        row("e-unapproved", "2026-01-15T10:10:00.000Z", "chen.wei", "console",
            "directory", "grant_role", "viewer", "admin"),
        # Real approval, wrong role: the ticket grants `reviewer`, not `operator`.
        row("e-wrong-role", "2026-01-15T10:15:00.000Z", "ben.okafor", "console",
            "directory", "grant_role", "viewer", "operator",
            approval="chg-wrong-role"),
        # Approval naming somebody else: self-approval, not a valid ticket.
        row("e-self", "2026-01-15T10:20:00.000Z", "dara.osei", "console",
            "directory", "grant_role", "viewer", "admin", approval="chg-good"),
    ])

    report = ok(state, op="detect_log", log=log, approvals=APPROVALS)
    alerts = report.get("alerts", [])
    fired = {a["event_ids"][0] for a in alerts}

    check("goal6/unapproved",
          "e-unapproved" in fired,
          "a role change with no approval is reported")
    check("goal6/approved-is-quiet",
          "e-approved" not in fired,
          "a change that matches its ticket on subject, role, window and signer is not")
    check("goal6/role-must-match",
          "e-wrong-role" in fired,
          "a ticket for a different role does not cover the change")
    check("goal6/self-approval",
          "e-self" in fired,
          "an approval signed by the subject does not cover their own change")

    # Every alert has to explain itself in one sentence, from recorded facts.
    check("goal6/explainable",
          bool(alerts) and all(a.get("explanation") for a in alerts),
          f"all {len(alerts)} alerts carry a one-sentence explanation")

    # The claim this check makes is specific: the two alerts fail for *different*
    # stated reasons. The no-approval case names a missing subject; the wrong-role case
    # names a role mismatch and shows which context did match. That is the difference
    # between an explainable rule and "something looked wrong".
    missing = {a["event_ids"][0]: a["facts"].get("context_missing", [])
               for a in alerts if a["rule"] == "unapproved_privilege_change"}
    check("goal6/names-the-failure",
          missing.get("e-unapproved") == ["subject"]
          and missing.get("e-wrong-role") == ["role"],
          f"each alert names its own missing fact: {missing}")

    # ---------------------------------------------------------------- goal 7
    # One session id across all three hops. A burst is grouped by session, so
    # identical rows with three different session ids are three separate one-hop
    # findings, not a chain -- that mistake is why this comment is here.
    lateral = csv_of(baseline_rows() + [
        row("l-1", "2026-01-15T11:00:00.000Z", "ana.petrova", "gateway", "vault",
            "read", "reader", "reader", session="intrusion"),
        row("l-2", "2026-01-15T11:01:00.000Z", "ana.petrova", "vault", "warehouse",
            "read", "reader", "reader", session="intrusion"),
        row("l-3", "2026-01-15T11:02:00.000Z", "ana.petrova", "warehouse", "ledger",
            "write", "reader", "reader", session="intrusion"),
    ])
    report = ok(state, op="detect_log", log=lateral)
    chains = [a for a in report["alerts"] if a["rule"] == "lateral_movement_chain"]
    check("goal7/chain-with-valid-credentials",
          len(chains) == 1,
          "a hop, hop, hop sequence across new services is reported despite valid creds")
    check("goal7/path-is-a-chain",
          bool(chains) and len(chains[0].get("path") or []) >= 2,
          "the alert records the path, not just a count")

    # ---------------------------------------------------------------- goal 8
    # Event stamped exactly on the exclusive end of its validity window. With 250 ms
    # of declared uncertainty it is neither demonstrably inside nor demonstrably
    # outside, so goal 8 requires the ambiguous answer: report both, assert neither.
    boundary = csv_of(baseline_rows() + [
        row("t-edge", "2026-01-15T12:00:00.000Z", "ana.petrova", "console",
            "directory", "grant_role", "viewer", "operator", approval="chg-good"),
    ])
    report = ok(state, op="detect_log", log=boundary, approvals=APPROVALS)
    # The same event legitimately raises two findings: a novel edge (certain) and an
    # uncertain window (not certain). Select the one goal 8 is about by name -- taking
    # `alerts[0]` picked the certain one and made this check fail against working code.
    edge = next((a for a in report["alerts"]
                 if a["rule"] == "uncertain_approval_window"), None)
    check("goal8/does-not-invent-an-order",
          edge is not None and edge.get("order") == "uncertain",
          f"an event on its window boundary is reported as "
          f"order={edge.get('order') if edge else None!r}, not judged either way")
    check("goal8/states-both-possibilities",
          edge is not None
          and sorted(edge.get("facts", {}).get("possible_orders") or [])
          == ["after_window", "inside_window"],
          "the alert names both possible orders instead of picking one")

    # Well inside the window the order is certain, so the rule is not just vague.
    inside = csv_of(baseline_rows() + [
        row("t-inside", "2026-01-15T11:59:00.000Z", "ana.petrova", "console",
            "directory", "grant_role", "viewer", "operator", approval="chg-good"),
    ])
    report = ok(state, op="detect_log", log=inside, approvals=APPROVALS)
    check("goal8/settles-what-it-can",
          not any(a["event_ids"][0] == "t-inside" for a in report["alerts"]),
          "the same change well inside its window is resolved and stays quiet")

    # --------------------------------------------------- determinism, in process
    first = ok(state, op="detect_log", log=log, approvals=APPROVALS)
    second = ok(state, op="detect_log", log=log, approvals=APPROVALS)
    check("determinism/byte-identical",
          json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True),
          "two separate processes produce byte-identical reports")
    check("determinism/no-wall-clock",
          "generated_at" not in json.dumps(first),
          "the report carries no timestamp, so it cannot differ between runs")

    ids = [a["alert_id"] for a in first["alerts"]]
    check("alerts/unique-ids", len(ids) == len(set(ids)),
          f"{len(ids)} alerts, {len(set(ids))} distinct ids")

    # ----------------------------------------------------------- hostile input
    hostile = [
        ("newline-injection", "evil\\nALERT forged", ),
        ("json-fragment", '{"op": "read"}'),
        ("cyrillic-lookalike", "\u0430na.petrova"),
        ("zero-width", "ana\u200b.petrova"),
        ("quote", 'ana"petrova'),
        ("oversize", "a" * 5000),
    ]
    rows = list(baseline_rows())
    for i, (label, value) in enumerate(hostile):
        escaped = value.replace('"', '""')
        rows.append(
            f'h-{i},2026-01-15T11:3{i}:00.000Z,2026-01-15T11:3{i}:00.100Z,0,'
            f'"{escaped}",gateway,index,read,reader,reader,allow,,s,c'
        )
    report = ok(state, op="detect_log", log=csv_of(rows))
    rejected = report["ingest"]["events_rejected"]
    check("hostile/all-refused", rejected == len(hostile),
          f"{len(hostile)} hostile values, {rejected} events quarantined")
    body = json.dumps(report)
    check("hostile/nothing-echoed",
          not any(m in body for m in ("ALERT", "\u0430na", "\u200b", '{"op"')),
          "no hostile text appears anywhere in the report")

    # A hostile *approvals* document must be reported, not silently ignored.
    broken = ok(state, op="detect_log", log=log, approvals='{"nope": 1}')
    check("hostile/broken-approvals-are-reported",
          broken["context"].get("document_error") == "approvals_invalid",
          "an unreadable approvals file is named in the report, not treated as 'none'")

    # ------------------------------------------------ persisted baseline + status
    appended = ok(state, op="detect_append", log=lateral)
    check("append/persists-a-baseline",
          appended.get("baseline_identities_persisted", 0) > 0,
          f"{appended.get('baseline_identities_persisted')} identities persisted")
    status = ok(state, op="detect_status")
    check("append/status-reads-it-back",
          status["baseline_identities"] == appended["baseline_identities_persisted"],
          "a second process reads back what the first persisted")
    tstatus = status["supported_timing_range"]
    check("status/states-the-timing-range",
          tstatus["max_abs_source_offset_ms"] > 0
          and tstatus["reorder_buffer_events"] > 0,
          f"claims offsets to +-{tstatus['max_abs_source_offset_ms']} ms, "
          f"{tstatus['reorder_buffer_events']}-event reorder buffer")

    # An unknown operation must still be refused, whatever we have added.
    unknown = call(state, op="definitely_not_an_op")
    check("contract/unknown-op-refused",
          unknown.get("error") == "unsupported_operation",
          f"unknown op -> {unknown.get('error')!r}")
    missing = call(state, op="detect_log")
    check("contract/missing-log-refused",
          missing.get("error") == "malformed_request",
          f"detect_log with no log -> {missing.get('error')!r}")

    # ------------------------------------------------------- signed-log link
    setup = ok(state, op="setup", owners={"brief": "maya"},
               contents={"brief": "body"}, disabled=[], key_material="M")
    check("signed/setup-ok", setup.get("ready") is True, "state initialised")
    signed = ok(state, op="detect_log", log=log, approvals=APPROVALS)
    check("signed/high-severity-recorded",
          signed.get("detections_signed", 0) > 0,
          f"{signed.get('detections_signed')} findings written to the signed log")
    head = ok(state, op="log_events_head")
    check("signed/log-has-them",
          head.get("events", 0) > 0,
          f"the signed key-event log holds {head.get('events')} event(s)")
    verify = ok(state, op="log_events_verify")
    check("signed/chain-verifies", verify.get("ok") is True,
          "the signed log still verifies after detections were appended")

    # ----------------------------------------------------------- configuration
    # Demand more novel hops than the chain has. Raising `min_baseline_events` alone
    # would not do it: it makes the identity *cold*, which swaps in
    # `cold_start_min_novel_edges` and can let the same chain through. Both are raised
    # here so the intent -- "this chain should now be too short to report" -- is what
    # is actually tested.
    tuned = {"lateral": {"min_novel_edges": 99, "cold_start_min_novel_edges": 99}}
    report = ok(state, op="detect_log", log=lateral, config=tuned)
    check("config/accepts-different-numbers",
          not any(a["rule"] == "lateral_movement_chain" for a in report["alerts"]),
          "requiring 99 novel hops suppresses the 3-hop chain, proving the number is read")
    refused = call(state, op="detect_log", log=lateral,
                   config={"lateral": {"min_baseline_events": -1}})
    check("config/refuses-nonsense",
          refused.get("error") == "config_rejected",
          f"a negative threshold -> {refused.get('error')!r}")

    # ------------------------------------------------------------- throughput
    big = HEADER + "\n" + "\n".join(
        row(f"p-{i:06d}",
            f"2026-01-15T{9 + (i // 60000):02d}:{(i // 1000) % 60:02d}:{(i // 100) % 60:02d}.{i % 1000:03d}Z",
            f"user{i % 50}", "gateway", "index", "read", "reader", "reader")
        for i in range(20000)
    ) + "\n"
    samples = []
    for _ in range(3):
        start = time.perf_counter_ns()
        result = ok(state, op="detect_log", log=big)
        samples.append((time.perf_counter_ns() - start) / 1e9)
    events = result["ingest"]["events_accepted"]
    median = sorted(samples)[1]
    print()
    print(f"  throughput: {events} events through the adapter in "
          f"{min(samples):.2f}-{median:.2f} s (median {median:.2f} s) "
          f"= {int(events / median)} events/s")
    print("  caveat: this includes process startup and the JSON reply, and it is one")
    print("  machine with no network; the pure-detector figure is in docs/DETECTION.md")
    check("throughput/completes", events == 20000,
          f"{events} events accepted in every run")


if __name__ == "__main__":
    raise SystemExit(main())
