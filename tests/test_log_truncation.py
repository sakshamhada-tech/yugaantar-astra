"""Goal 5 under attack: the signed key-event log must not lie about being intact.

A hash chain proves *internal consistency*. It does not prove the chain is the one that
was written, because a shortened chain is still a valid chain. Deleting the last record
— or every record — leaves a log that verifies perfectly.

This file pins the two things that make that honest:

1. a bare `log_events_verify` never reports a bare green light; it says whether an anchor
   was actually checked, so an operator cannot read `ok: true` as "the log is intact";
2. the head recorded at the last event write is used by default, so the common attack —
   truncate the log file, leave state alone — is *caught* rather than reported as healthy.

The remaining limit, which is not fixable here and is asserted as a limit rather than
hidden: an attacker who can write the state directory can rewrite `events_head` too. Only
an anchor held outside that directory is unforgeable, which is why `expected_head` on the
request still takes precedence.
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


def call(state: Path, **request) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=180,
    )
    assert done.returncode == 0, done.stderr.decode()[:400]
    return json.loads(done.stdout)


def ok(state: Path, **request) -> dict:
    response = call(state, **request)
    assert "error" not in response, response
    return response


@pytest.fixture()
def state(tmp_path):
    ok(tmp_path, op="setup", owners={"brief": "maya"}, contents={"brief": "S"},
       disabled=[], key_material="K")
    for actor in ("alice", "bob", "carol"):
        ok(tmp_path, op="revoke", actor=actor)
    return tmp_path


@pytest.fixture()
def log_path(state):
    return state / "pqc-kv-state" / "key-events.jsonl"


# ------------------------------------------------------------------ the finding
def test_truncating_the_log_is_detected_without_the_operator_passing_a_head(state, log_path):
    """The headline regression.

    Before the fix, deleting the last record left `{"ok": true}`: a shorter valid chain
    is still a valid chain, and nothing compared it to what had been written. The state
    now records the head at every append, so the default verify anchors against it.
    """
    assert ok(state, op="log_events_verify")["ok"] is True

    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines[:-1]) + "\n")

    result = ok(state, op="log_events_verify")
    assert result["ok"] is False
    assert result["reason"] == "head_mismatch"
    assert result["anchor_checked"] is True


def test_emptying_the_log_is_detected(state, log_path):
    """The most destructive version: every event gone, and the file is still valid."""
    log_path.write_text("")
    result = ok(state, op="log_events_verify")
    assert result["ok"] is False
    assert result["reason"] == "head_mismatch"


def test_a_bare_verify_is_never_silently_unanchored(state, log_path):
    """If no anchor is available, the report must say so rather than imply safety."""
    # Remove the recorded head so there is nothing to anchor against.
    path = state / "pqc-kv-state" / "state.json"
    data = json.loads(path.read_text())
    data.pop("events_head", None)
    data.pop("events_count", None)
    path.write_text(json.dumps(data))

    result = ok(state, op="log_events_verify")
    assert result["anchor_checked"] is False
    assert "truncation is NOT detectable" in result["note"]
    # And it still tells the truth about what it did check.
    assert result["records"] == 3


def test_an_operator_supplied_head_takes_precedence(state, log_path):
    """An external anchor is the only unforgeable one, so it must win."""
    head = ok(state, op="log_events_head")["events_head"]
    assert ok(state, op="log_events_verify", expected_head=head)["ok"] is True

    log_path.write_text("\n".join(log_path.read_text().splitlines()[:-1]) + "\n")
    result = ok(state, op="log_events_verify", expected_head=head)
    assert result["ok"] is False
    assert result["reason"] == "head_mismatch"
    assert result["actual_head"] != head


# ------------------------------------------------------- the attacks already caught
def test_reordering_records_is_detected(state, log_path):
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert ok(state, op="log_events_verify")["reason"] == "chain_broken"


def test_editing_an_actor_is_detected(state, log_path):
    log_path.write_text(log_path.read_text().replace('"alice"', '"alicf"', 1))
    assert ok(state, op="log_events_verify")["reason"] == "chain_broken"


def test_duplicating_a_record_is_detected(state, log_path):
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines[:2] + [lines[1]] + lines[2:]) + "\n")
    assert ok(state, op="log_events_verify")["ok"] is False


def test_forging_a_record_is_detected(state, log_path):
    """Appending a copy of the last record fails: seq and prev no longer line up."""
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines + [lines[-1]]) + "\n")
    assert ok(state, op="log_events_verify")["reason"] == "chain_broken"


def test_the_state_head_follows_every_event(state):
    """The head must be stamped atomically with the event it describes.

    A first implementation wrote a second copy of the state inside `record_event` and
    the caller immediately overwrote it, so every stamp was lost -- and the truncation
    check silently degraded to the old unanchored behaviour while looking fixed.
    """
    before = ok(state, op="log_events_head")
    ok(state, op="revoke", actor="dave")
    after = ok(state, op="log_events_head")

    assert after["events"] == before["events"] + 1
    recorded = json.loads(
        (state / "pqc-kv-state" / "state.json").read_text()
    )["events_head"]
    assert recorded == after["events_head"]
