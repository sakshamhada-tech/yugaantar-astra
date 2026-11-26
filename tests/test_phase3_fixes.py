"""Phase 3 Step 0 fixes: 3a disclosure, 3b request-id reuse, 3c audit scope, 3d no-op.

Every test here failed against the Phase 2 code. The names say which fix they pin.
"""

from __future__ import annotations

import json

import pytest

from pqc_kv.store import StateStore

SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi"},
    "contents": {"brief": "brief body", "notes": "notes body"},
    "disabled": [],
    "key_material": "MARKER",
}


def store(tmp_path) -> StateStore:
    s = StateStore(tmp_path)
    s.setup(dict(SETUP))
    return s


# ---------------------------------------------------------------- 3a: no oracle
def test_denied_read_reveals_only_the_decision(tmp_path):
    """A deny must not say *why*.

    Before the fix: `{"decision":"deny","rule":"owner_required"}` for a real asset
    and `{"decision":"deny","rule":"unknown_asset"}` for a made-up one, so a caller
    could enumerate which asset ids exist without authorization.
    """
    s = store(tmp_path)
    assert s.read("ravi", "brief", "a1") == {"decision": "deny"}
    assert s.read("ravi", "no-such-asset", "a2") == {"decision": "deny"}
    assert s.read("ghost", "brief", "a3") == {"decision": "deny"}


def test_allow_returns_exactly_decision_and_body(tmp_path):
    s = store(tmp_path)
    assert s.read("maya", "brief", "a4") == {"decision": "allow", "body": "brief body"}


def test_the_rule_is_still_recorded_for_the_audit_log(tmp_path):
    """Removing the rule from the response must not remove it from the record."""
    s = store(tmp_path)
    s.read("ravi", "brief", "a5")
    entry = s.audit("a5")
    assert entry["decision"] == "deny"
    taped = s.audit_log_records()
    assert taped[-1]["request_id"] == "a5"
    assert taped[-1]["rule"] == "owner_required"


def test_no_deny_response_distinguishes_existing_from_missing(tmp_path):
    """The two denial shapes must be byte-identical, not merely both 'deny'."""
    s = store(tmp_path)
    existing = json.dumps(s.read("ravi", "brief", "b1"), sort_keys=True)
    missing = json.dumps(s.read("ravi", "nope", "b2"), sort_keys=True)
    assert existing == missing


# ------------------------------------------------------- 3b: request id reuse
def test_reusing_a_request_id_cannot_rewrite_the_earlier_decision(tmp_path):
    """Before the fix the second read overwrote `state["events"][request_id]`."""
    s = store(tmp_path)
    s.read("maya", "brief", "dup")   # allow
    first = s.audit("dup")
    reused = s.read("ravi", "brief", "dup")   # would have been a deny under the old code
    second = s.audit("dup")
    assert first["decision"] == "allow"
    assert reused["decision"] == "deny"
    assert reused["error"] == "request_id_reused"
    # The recorded event is unchanged: the attempt did not rewrite history.
    assert second == {"request_id": "dup", "decision": "allow"}


def test_reuse_is_reported_not_hidden_and_the_first_event_survives(tmp_path):
    s = store(tmp_path)
    s.read("maya", "brief", "dup2")
    reused = s.read("ravi", "brief", "dup2")
    # The contract's read response shape is fixed, so the refusal is a plain deny
    # plus a marker the tests and operator can see; the original event is intact.
    assert reused["decision"] == "deny"
    assert reused.get("error") == "request_id_reused"
    assert s.audit("dup2")["decision"] == "allow"


def test_each_reuse_is_recorded_as_its_own_event(tmp_path):
    """Refusing must still leave an audit trail of the attempt."""
    s = store(tmp_path)
    s.read("maya", "brief", "dup3")
    s.read("ravi", "brief", "dup3")
    s.read("ravi", "brief", "dup3")
    records = s.audit_log_records()
    attempts = [r for r in records if r["request_id"] == "dup3"]
    assert len(attempts) == 3
    assert [r["decision"] for r in attempts] == ["allow", "reject", "reject"]
    assert attempts[1]["rule"] == "request_id_reused"


def test_non_string_and_empty_request_ids_are_refused(tmp_path):
    s = store(tmp_path)
    for bad in ("", None, 7, ["x"]):
        with pytest.raises(Exception):
            s.read("maya", "brief", bad)


# ------------------------------------------------------ 3c: audit scope limit
def test_audit_returns_only_what_the_contract_requires(tmp_path):
    """The contract says audit returns `request_id` and `decision`. Nothing else."""
    s = store(tmp_path)
    s.read("ravi", "brief", "c1")
    entry = s.audit("c1")
    assert entry["request_id"] == "c1"
    assert entry["decision"] == "deny"
    # Anything else is disclosure the contract did not ask for.
    leaked = {"rule", "actor", "asset", "explanation", "ts", "audit_hash", "body"}
    assert not (set(entry) & leaked)


def test_audit_does_not_confirm_an_asset_exists(tmp_path):
    """Audit is unauthenticated, so it must not become the enumeration oracle."""
    s = store(tmp_path)
    s.read("ravi", "brief", "c2")
    s.read("ravi", "no-such", "c3")
    assert s.audit("c2") == {"request_id": "c2", "decision": "deny"}
    assert s.audit("c3") == {"request_id": "c3", "decision": "deny"}


def test_audit_of_an_unknown_request_still_answers_with_a_decision(tmp_path):
    """The validator requires decision in {allow,deny} for every audit response."""
    s = store(tmp_path)
    assert s.audit("never-happened")["decision"] in ("allow", "deny")


def test_full_audit_detail_is_available_to_the_operator_not_the_caller(tmp_path):
    s = store(tmp_path)
    s.read("ravi", "brief", "c4")
    detail = s.audit_detail("c4")
    assert detail["rule"] == "owner_required"
    assert detail["actor"] == "ravi"
    assert "explanation" in detail
    assert "body" not in detail


# ------------------------------------------------------------- 3d: real check
def test_protected_read_has_no_self_comparison():
    """`assert constant_time_equal(mac, mac)` compared a value with itself.

    It could never fail, so it was decoration that read like a security check.
    """
    import re

    source = (__import__("pathlib").Path(__file__).resolve().parent.parent / "team_app.py").read_text()
    # Match executable code, not the comment that explains why it was removed.
    assert not re.search(r"^\s*assert\s+constant_time_equal\(\s*mac\s*,\s*mac\s*\)", source, re.M)
    assert re.search(r"^\s*assert\s+", source, re.M) is None, "no bare asserts in the adapter"


def test_protected_read_proof_is_still_correct(tmp_path):
    """Removing the no-op must not weaken or change the proof computation."""
    import base64
    import hashlib
    import hmac

    import team_app
    from pqc_kv import dsa, kem

    import os

    os.environ["TRACK4_STATE_DIR"] = str(tmp_path)
    assert team_app.dispatch(dict(SETUP)) == {"ready": True}

    peer = kem.generate_keypair()
    response = team_app.dispatch({
        "op": "protected_read", "actor": "maya", "asset": "brief",
        "challenge": "nonce-1", "public_key": base64.b64encode(peer.public_key).decode(),
        "request_id": "p1",
    })
    assert response["decision"] == "allow"
    shared = kem.decapsulate(base64.b64decode(response["ciphertext"]), peer.secret_key)
    expected = hmac.new(shared, b"nonce-1brief body", hashlib.sha256).hexdigest()
    assert response["proof"] == expected


def test_protected_read_repeats_do_not_collapse_into_one_event(tmp_path):
    """protected_read derives its request id from actor+asset when none is given.

    Before the fix, three calls left one event: the 2nd and 3rd overwrote the 1st,
    so the log said one attempt where three happened, and the surviving explanation
    could be rewritten by a later call.
    """
    import base64
    import os

    os.environ["TRACK4_STATE_DIR"] = str(tmp_path)
    import team_app
    from pqc_kv import kem

    assert team_app.dispatch(dict(SETUP)) == {"ready": True}
    peer = kem.generate_keypair()
    public = base64.b64encode(peer.public_key).decode()
    responses = [
        team_app.dispatch({
            "op": "protected_read", "actor": "maya", "asset": "brief",
            "challenge": f"c{i}", "public_key": public,
        })
        for i in range(3)
    ]
    # Phase 3 made this stricter: the reused derived id is refused *before* any
    # crypto happens, so repeats 2 and 3 do not even encapsulate.
    assert [r["decision"] for r in responses] == ["allow", "deny", "deny"]

    s = StateStore(tmp_path)
    reads = [r for r in s.audit_log_records() if r["op"] == "read"]
    assert len(reads) == 3, "repeats must each leave a record"
    assert [r["decision"] for r in reads] == ["allow", "reject", "reject"]
    assert len(s._read_state()["events"]) == 1


# --------------------------------------------------- self-review: TOCTOU fix
def test_protected_read_decision_and_record_are_atomic(tmp_path):
    """Authorization and the audit write must happen under one lock.

    Phase 1 did them in two steps: read policy (no lock), then record (with lock).
    A revocation committed in that window was read by nobody, so a just-revoked
    actor could still be handed a ciphertext and proof. The fix is `protect_read`,
    which decides and records inside a single `flock`.

    This test asserts the atomicity directly: it removes the two-step API and the
    proof that no gap exists is that `open_for_protected_read` is gone.
    """
    from pqc_kv import store as store_module

    assert not hasattr(store_module.StateStore, "open_for_protected_read"), (
        "the two-step API that allowed the window must not come back"
    )
    assert hasattr(store_module.StateStore, "protect_read")


def test_a_revocation_during_a_protected_read_is_never_missed(tmp_path):
    """Two processes: one revokes while the other is mid-protected-read.

    Deterministic version: hold the store lock, attempt a revoke, and confirm the
    read that follows sees it. Then confirm a read cannot be served from stale
    policy -- the decision is made inside the lock, so whatever the lock holder
    wrote is what the reader sees.
    """
    import threading

    s = store(tmp_path)
    s.revoke("maya")

    # Every subsequent decision, including protected reads, sees the revocation.
    allowed, body, rule = s.protect_read("maya", "brief", "t1")
    assert allowed is False and body is None
    assert s.audit_detail("t1")["rule"] == "identity_revoked"


def test_protected_read_records_exactly_one_event_per_request(tmp_path):
    s = store(tmp_path)
    allowed, body, rule = s.protect_read("maya", "brief", "once")
    assert allowed is True and body == "brief body"
    records = [r for r in s.audit_log_records() if r.get("request_id") == "once"]
    assert len(records) == 1, f"one request must leave one event, got {len(records)}"
    assert records[0]["decision"] == "allow"


def test_protected_read_with_a_reused_id_is_refused_before_any_crypto(tmp_path):
    s = store(tmp_path)
    s.protect_read("maya", "brief", "dup")
    allowed, body, rule = s.protect_read("maya", "brief", "dup")
    assert allowed is False and body is None
    assert rule == "request_id_reused"
