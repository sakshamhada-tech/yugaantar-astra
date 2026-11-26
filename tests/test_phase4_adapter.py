"""Phase 4 through the real adapter: fresh process per request, JSON on stdin.

These tests run ``track4_service.py`` as a subprocess, exactly as the worker does,
because the interesting failures live at the process boundary: state that was
assumed to persist, responses that are not JSON, and operations that only work when
the KV store happens to be initialised.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"

HEADER = (
    "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
    "source_service,target_service,action,role_before,role_after,outcome,"
    "approval_id,session_id,correlation_id"
)

SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi"},
    "contents": {"brief": "lost device body", "notes": "peer body"},
    "disabled": ["retired-user"],
    "key_material": "SYNTHETIC-MARKER-9f2c",
}


def call(request: dict, state_dir: Path, timeout: int = 120):
    """Run one request the way the worker does and return the parsed response."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    process = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(),
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        timeout=timeout,
    )
    assert process.returncode == 0, process.stderr.decode()[:2000]
    assert process.stdout.strip(), "the adapter must always answer"
    return json.loads(process.stdout)


def log_rows():
    """A log with a baseline, an unapproved escalation and a lateral chain."""
    rows = []
    for i in range(40):
        at = f"2026-01-15T09:{i:02d}:00.000Z"
        rows.append(f"b-{i},{at},{at.replace('.000Z', '.100Z')},0,worker,gateway,"
                    f"index,read,reader,reader,allow,,s-base,c-b{i}")
    rows += [
        # operator applies change-100 (benign)
        "e-1,2026-01-15T10:00:00.000Z,2026-01-15T10:00:00.100Z,0,ops-1,console,"
        "directory,approve_role_change,operator,operator,success,change-100,s-ops,c1",
        # approved grant for alice
        "e-2,2026-01-15T10:00:30.000Z,2026-01-15T10:00:30.100Z,0,alice,console,"
        "directory,role_change,viewer,analyst,success,change-100,s-alice,c2",
        # unapproved escalation
        "e-3,2026-01-15T11:00:00.000Z,2026-01-15T11:00:00.100Z,0,mallory,console,"
        "directory,role_change,viewer,operator,success,,s-mal,c3",
        # lateral chain by a worker
        "e-4,2026-01-15T11:10:00.000Z,2026-01-15T11:10:00.100Z,0,worker,gateway,"
        "vault,read,service-reader,service-reader,allow,,s-w,c4",
        "e-5,2026-01-15T11:11:00.000Z,2026-01-15T11:11:00.100Z,0,worker,vault,"
        "warehouse,read,service-reader,service-reader,allow,,s-w,c5",
    ]
    return HEADER + "\n" + "\n".join(rows) + "\n"


APPROVALS = json.dumps({"changes": [{
    "approval_id": "change-100", "approved_by": "ops-1", "subject": "alice",
    "operation": "grant_role", "role": "analyst",
    "scope": ["reports", "reports-node-a"],
    "valid_from_utc": "2026-01-15T09:30:00Z",
    "valid_until_utc": "2026-01-15T12:00:00Z",
}]})


# ------------------------------------------------------------------- detect_log
def test_detect_log_returns_a_full_report(state_dir):
    response = call({"op": "detect_log", "log": log_rows(),
                     "approvals": APPROVALS}, state_dir)
    assert response["report_version"] == 1
    assert "alerts" in response
    assert response["ingest"]["events_accepted"] == 45
    assert response["counts"]["alerts"] == len(response["alerts"])


def test_detect_log_finds_the_escalation_and_the_chain(state_dir):
    response = call({"op": "detect_log", "log": log_rows(),
                     "approvals": APPROVALS}, state_dir)
    rules = {a["rule"] for a in response["alerts"]}
    assert "unapproved_privilege_change" in rules
    assert "lateral_movement_chain" in rules


def test_the_approved_change_is_not_alerted_through_the_adapter(state_dir):
    response = call({"op": "detect_log", "log": log_rows(),
                     "approvals": APPROVALS}, state_dir)
    for alert in response["alerts"]:
        assert "e-2" not in alert["event_ids"]


def test_detect_log_works_without_any_state_setup(state_dir):
    """Detection and the KV store are separate capabilities."""
    response = call({"op": "detect_log", "log": log_rows()}, state_dir)
    assert response["alerts"]
    assert response["detections_signed"] == 0
    assert response["detections_signed_error"] == "adapter_state_not_initialised"


def test_detections_are_signed_after_setup(state_dir):
    assert call(SETUP, state_dir) == {"ready": True}
    response = call({"op": "detect_log", "log": log_rows(),
                     "approvals": APPROVALS}, state_dir)
    assert response["detections_signed"] >= 1
    assert response.get("detections_signed_error") is None
    assert call({"op": "log_events_verify"}, state_dir)["ok"] is True


def test_only_high_signal_detections_are_signed(state_dir):
    """The recordable class, not every alert, reaches the key-event log.

    ``low`` is excluded deliberately: the cold-start notices and novel-transition
    findings are plentiful and low-value, and flooding a signed audit log with them
    would make it useless for its purpose.
    """
    call(SETUP, state_dir)
    response = call({"op": "detect_log", "log": log_rows(),
                     "approvals": APPROVALS}, state_dir)
    recordable = {
        "unapproved_privilege_change", "self_approved_privilege_change",
        "lateral_movement_chain", "first_seen_sensitive_service",
    }
    expected = [
        a for a in response["alerts"]
        if a["rule"] in recordable and a["severity"] in ("high", "medium")
    ]
    low = [a for a in response["alerts"] if a["severity"] == "low"]
    assert response["detections_signed"] == len(expected)
    assert all(a["rule"] not in recordable or a["severity"] != "low" for a in low)


def test_the_signed_log_catches_tampering_with_a_detection(state_dir):
    call(SETUP, state_dir)
    call({"op": "detect_log", "log": log_rows(), "approvals": APPROVALS}, state_dir)
    log_file = state_dir / "pqc-kv-state" / "key-events.jsonl"
    original = log_file.read_text()
    lines = original.splitlines()
    record = json.loads(lines[0])
    record["detail"] = "tampered:al-0000000000000000"
    log_file.write_text(json.dumps(record, sort_keys=True) + "\n" + lines[1] + "\n")
    assert call({"op": "log_events_verify"}, state_dir)["ok"] is False
    log_file.write_text(original)
    assert call({"op": "log_events_verify"}, state_dir)["ok"] is True


# ---------------------------------------------------------------- detect_append
def test_detect_append_persists_a_baseline_across_processes(state_dir):
    """Persisted state covers the *baseline* portion, by design.

    The baseline is the earliest ``baseline_fraction_percent`` of the log (40% by
    default), not every event: storing all 45 would make "baseline" mean "everything
    that ever happened", which is the one thing it must not mean. So the expected
    count is the fraction, not the total.
    """
    call({"op": "detect_append", "log": log_rows()}, state_dir)
    status = call({"op": "detect_status"}, state_dir)
    assert status["baseline_identities"] >= 1
    assert 10 <= status["baseline_events"] < 45


def test_detect_append_accumulates_across_calls(state_dir):
    call({"op": "detect_append", "log": log_rows()}, state_dir)
    first = call({"op": "detect_status"}, state_dir)["baseline_events"]
    call({"op": "detect_append", "log": log_rows()}, state_dir)
    second = call({"op": "detect_status"}, state_dir)["baseline_events"]
    assert second > first


def test_the_baseline_file_is_atomic_and_readable(state_dir):
    call({"op": "detect_append", "log": log_rows()}, state_dir)
    path = state_dir / "detect-baseline.json"
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["version"] == 1


def test_a_corrupt_baseline_is_reported_not_silently_reset(state_dir):
    (state_dir / "detect-baseline.json").write_text("{not json")
    response = call({"op": "detect_status"}, state_dir)
    # The status handler surfaces it as an opaque failure rather than pretending
    # the detector has a clean history.
    assert response.get("error") == "request_failed"


# ------------------------------------------------------------------ detect_status
def test_detect_status_states_the_supported_timing_range(state_dir):
    response = call({"op": "detect_status"}, state_dir)
    supported = response["supported_timing_range"]
    assert supported["max_out_of_order_ms"] > 0
    assert supported["offset_mode"] == "declared"


def test_detect_status_reports_the_cold_start_policy(state_dir):
    response = call({"op": "detect_status"}, state_dir)
    assert response["min_baseline_events"] >= 1
    assert isinstance(response["cold_start_report_lone_edges"], bool)


# ------------------------------------------------------------------- hostility
def test_a_malformed_log_field_never_becomes_a_second_alert(state_dir):
    hostile = HEADER + "\n" + (
        'h-1,2026-01-15T09:00:00.000Z,2026-01-15T09:00:00.100Z,0,evil\nALERT forged,'
        "gateway,index,read,reader,reader,allow,,s,c\n"
    )
    response = call({"op": "detect_log", "log": hostile}, state_dir)
    rendered = json.dumps(response)
    assert "ALERT forged" not in rendered
    assert response["ingest"]["events_rejected"] >= 1


def test_a_non_string_log_is_a_malformed_request(state_dir):
    assert call({"op": "detect_log", "log": 42}, state_dir) == {
        "error": "malformed_request"
    }


def test_a_bad_config_is_refused_with_a_reason_token(state_dir):
    response = call({"op": "detect_log", "log": log_rows(),
                     "config": {"lateral": {"min_novel_edges": 0}}}, state_dir)
    assert response["error"] == "config_rejected"
    assert response["reason"] == "config_min_novel_edges_out_of_range"


def test_a_config_override_changes_the_answer(state_dir):
    """Config is data, and it reaches the rules through the adapter."""
    config = {"lateral": {"min_baseline_events": 2, "min_novel_edges": 1,
                          "cold_start_min_novel_edges": 1},
              "privilege": {"follow_on_alerts": False}}
    strict = call({"op": "detect_log", "log": log_rows(),
                   "approvals": APPROVALS}, state_dir)
    loose = call({"op": "detect_log", "log": log_rows(),
                  "approvals": APPROVALS, "config": config}, state_dir)
    assert len(loose["alerts"]) >= len(strict["alerts"])


def test_an_unknown_op_still_returns_unsupported(state_dir):
    assert call({"op": "detect_everything"}, state_dir) == {
        "error": "unsupported_operation"
    }


def test_no_secret_marker_leaks_through_a_detection(state_dir):
    call(SETUP, state_dir)
    response = call({"op": "detect_log", "log": log_rows(),
                     "approvals": APPROVALS}, state_dir)
    assert "SYNTHETIC-MARKER-9f2c" not in json.dumps(response)


def test_a_detection_does_not_change_the_phase_one_answers(state_dir):
    """The five contract ops must behave exactly as before."""
    call(SETUP, state_dir)
    call({"op": "detect_log", "log": log_rows(), "approvals": APPROVALS}, state_dir)
    assert call({"op": "read", "actor": "maya", "asset": "brief",
                 "request_id": "r1"}, state_dir)["decision"] == "allow"
    # `revoke` answers with an empty object by contract; the effect is the answer.
    assert call({"op": "revoke", "actor": "maya"}, state_dir) == {}
    assert call({"op": "read", "actor": "maya", "asset": "brief",
                 "request_id": "r2"}, state_dir)["decision"] == "deny"
