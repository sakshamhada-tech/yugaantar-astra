"""Goal 3: crash recovery at every named fault point, with real killed processes.

Nothing here simulates a crash in-process. Each case starts the real adapter, arms
`TRACK4_FAULT_AT`, and lets the child call os._exit() at the named point. The parent
then verifies the state on disk and runs recovery.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pqc_kv import intent

ROOT = Path(__file__).resolve().parent.parent
SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi", "extra": "maya"},
    "contents": {"brief": "brief body", "notes": "notes body", "extra": "extra body"},
    "disabled": [],
    "key_material": "MARKER",
}

#: Every fault point the hook supports. The test is parametrised over all of them.
POINTS = list(intent.FAULT_POINTS)


def run(state: Path, *, fault: str | None = None, **request):
    """Run one adapter request, optionally with a crash armed at `fault`."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    if fault:
        env[intent.FAULT_ENV] = fault
    done = subprocess.run(
        [sys.executable, "-B", str(ROOT / "track4_service.py")],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=120,
    )
    return done


def call(state: Path, **request):
    done = run(state, **request)
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout)


@pytest.fixture()
def set_up(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    assert call(state, **SETUP) == {"ready": True}
    return state


def state_pqc(state: Path) -> Path:
    return state / "pqc-kv-state"


# ------------------------------------------------------------ the hook itself
def test_an_unknown_fault_point_does_nothing(set_up):
    done = run(set_up, fault="not-a-real-point", op="rotate", grace=2)
    assert done.returncode == 0, "an unknown point must not kill the process"
    assert json.loads(done.stdout)["active_version"] == 2


def test_the_hook_kills_a_real_process_at_the_named_point(set_up):
    done = run(set_up, fault="after_intent", op="rotate", grace=2)
    assert done.returncode == 97, "the child should die at the armed point"
    # And the intent record is genuinely on disk: this was a real interruption.
    assert intent.intent_path(state_pqc(set_up)).exists()


def test_the_hook_is_not_reachable_from_adapter_input(set_up):
    """A request field must never arm the hook: env only, scrubbed at import."""
    # leave the state mid-rotate, then prove no request field can re-arm the hook
    run(set_up, op="rotate", grace=2, fault_at="after_intent",
               TRACK4_FAULT_AT="after_intent", fault="after_intent")
    # `fault` here is the env var name this helper sets, so it *is* armed; the point
    # is that it died from the env, not from the request fields. Prove the request
    # field alone is inert:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(set_up)
    clean = subprocess.run(
        [sys.executable, "-B", str(ROOT / "track4_service.py")],
        input=json.dumps({"op": "rotate", "grace": 2, "fault_at": "after_intent",
                          "TRACK4_FAULT_AT": "after_intent"}).encode(),
        cwd=str(ROOT), env=env, capture_output=True, timeout=120,
    )
    assert clean.returncode == 0, "request fields cannot arm the fault hook"


def test_key_status_reports_only_whether_the_hook_is_armed(set_up):
    status = call(set_up, op="key_status")
    assert status["fault_injection_active"] is False
    assert "after_intent" not in json.dumps(status)


# ------------------------------------------------- crash at every named point
@pytest.mark.parametrize("point", POINTS)
def test_recovery_lands_on_one_consistent_version(set_up, point):
    done = run(set_up, fault=point, op="rotate", grace=2)
    # Some points are past the last visible work; the process still exits 0 there.
    assert done.returncode in (0, 97)

    report = call(set_up, op="recover")
    assert report["recovered"] in (True, False)

    status = call(set_up, op="key_status")
    active = [v for v in status["versions"] if v["state"] == "active"]
    assert len(active) == 1, f"exactly one active version, got {status['versions']}"
    assert active[0]["version"] == status["active_version"]

    # Every asset must be readable, and stamped with the active version.
    for asset, owner in (("brief", "maya"), ("notes", "ravi"), ("extra", "maya")):
        response = call(set_up, op="read", actor=owner, asset=asset,
                        request_id=f"rec-{point}-{asset}")
        assert response["decision"] == "allow", f"{asset} unreadable after crash at {point}"

    # No half-finished intent left behind.
    assert not intent.intent_path(state_pqc(set_up)).exists()


@pytest.mark.parametrize("point", POINTS)
def test_revocation_survives_a_crash_at_every_point(set_up, point):
    call(set_up, op="revoke", actor="maya")
    done = run(set_up, fault=point, op="rotate", grace=2)
    assert done.returncode in (0, 97)
    call(set_up, op="recover")

    # The revoked actor is still revoked, and the peer is still fine.
    assert call(set_up, op="read", actor="maya", asset="brief",
                request_id=f"rev-{point}")["decision"] == "deny"
    assert call(set_up, op="read", actor="ravi", asset="notes",
                request_id=f"ok-{point}")["decision"] == "allow"


def test_assets_are_consistent_after_a_mid_rewrap_crash(set_up):
    """Specifically the messy case: some assets moved, some did not."""
    done = run(set_up, fault="mid_rewrap", op="rotate", grace=2)
    assert done.returncode == 97
    call(set_up, op="recover")
    versions = {
        json.loads((state_pqc(set_up) / "state.json").read_text())["assets"][a]["key_version"]
        for a in ("brief", "notes", "extra")
    }
    assert len(versions) == 1, f"assets ended up on mixed versions: {versions}"


def test_recovery_is_idempotent(set_up):
    run(set_up, fault="after_intent", op="rotate", grace=2)
    first = call(set_up, op="recover")
    second = call(set_up, op="recover")
    assert first["recovered"] is True
    assert second["recovered"] is False, "second recovery has nothing to do"


def test_a_crash_after_commit_only_needs_cleanup(set_up):
    done = run(set_up, fault="after_commit", op="rotate", grace=2)
    assert done.returncode == 97
    # The rotation itself is complete: the version moved and assets are on it.
    report = call(set_up, op="recover")
    assert report["active_version"] == 2
    assert call(set_up, op="read", actor="maya", asset="brief",
                request_id="post-commit")["decision"] == "allow"


def test_a_crash_before_intent_leaves_nothing_to_recover(set_up):
    done = run(set_up, fault="before_intent", op="rotate", grace=2)
    assert done.returncode == 97
    assert not intent.intent_path(state_pqc(set_up)).exists()
    report = call(set_up, op="recover")
    assert report["recovered"] is False
    assert report["active_version"] == 1


def test_recovery_preserves_the_audit_chain(set_up):
    run(set_up, fault="mid_rewrap", op="rotate", grace=2)
    call(set_up, op="recover")
    verification = call(set_up, op="log_verify")
    assert verification["ok"] is True
    records = [json.loads(line) for line in
               (state_pqc(set_up) / "audit.jsonl").read_text().splitlines() if line.strip()]
    assert any(r["op"] == "recover" for r in records), "recovery must be logged (goal 5)"


def test_double_crash_then_recover(set_up):
    """Crash, recover, crash again, recover: still one consistent version."""
    run(set_up, fault="mid_rewrap", op="rotate", grace=2)
    run(set_up, fault="after_intent", op="rotate", grace=2)
    call(set_up, op="recover")
    status = call(set_up, op="key_status")
    assert len([v for v in status["versions"] if v["state"] == "active"]) == 1
    for asset, owner in (("brief", "maya"), ("notes", "ravi"), ("extra", "maya")):
        assert call(set_up, op="read", actor=owner, asset=asset,
                    request_id=f"d-{asset}")["decision"] == "allow"


def test_a_crash_after_commit_does_not_re_wrap_anything(set_up):
    """The commit marker must actually carry information.

    Found by mutation testing: deleting `write_commit` broke no test at first, because
    "finish forward" happens to be idempotent and produced the right end state anyway.
    It is *not* free, though -- it re-seals every asset, which burns fresh nonces and
    does redundant work on data that was already correct. A completed rotation must be
    recognised as complete, not silently redone.
    """
    done = run(set_up, fault="after_commit", op="rotate", grace=2)
    assert done.returncode == 97

    # The commit marker survives the crash and says the work is done.
    marker = intent.read_commit(state_pqc(set_up))
    assert marker is not None, "a completed rotation must leave a commit marker behind"
    assert marker["to_version"] == 2

    report = call(set_up, op="recover")
    assert report["action"] == "cleared", (
        f"recovery re-did finished work instead of clearing the marker: {report}"
    )
    assert "resealed" not in report, "nothing should be re-wrapped after the commit"
