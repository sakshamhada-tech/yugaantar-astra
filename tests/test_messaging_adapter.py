"""End-to-end messaging through the real adapter: one subprocess per request.

This is the test that proves the design survives the contract's hardest
constraint -- no in-memory state between requests, a fresh process every time.
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


def call(state_dir: Path, **request) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(),
        cwd=str(ROOT), env=env, capture_output=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout)


def ok(state_dir, **request) -> dict:
    response = call(state_dir, **request)
    assert "error" not in response, response
    return response


def setup_two_parties(tmp_path):
    """Two containers, two users, directory exchanged out of band."""
    alice_dir, bob_dir = tmp_path / "alice", tmp_path / "bob"
    alice_dir.mkdir(); bob_dir.mkdir()

    alice_id = ok(alice_dir, op="msg_identity", user_id="alice", export_public=True)
    bob_id = ok(bob_dir, op="msg_identity", user_id="bob", export_public=True)

    # Exchange public records out of band (this is the trust anchor step a real
    # deployment would do via a signed directory or a fingerprint comparison).
    ok(alice_dir, op="msg_directory_add", identity=bob_id["public"])
    ok(bob_dir, op="msg_directory_add", identity=alice_id["public"])
    return alice_dir, bob_dir, alice_id, bob_id


def full_handshake(alice_dir, bob_dir):
    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    accept = ok(bob_dir, op="msg_handshake_finish", self_user="bob", hello=hello["hello"])
    confirm = ok(alice_dir, op="msg_handshake_complete", self_user="alice", accept=accept["accept"])
    ok(bob_dir, op="msg_handshake_confirm", self_user="bob", confirm=confirm["confirm"])
    return hello["session_id"]


# ------------------------------------------------------------------- tests
def test_identity_op_returns_a_fingerprint(tmp_path):
    state = tmp_path / "s"; state.mkdir()
    response = ok(state, op="msg_identity", user_id="alice")
    assert response["user_id"] == "alice"
    assert len(response["fingerprint"]) == 64


def test_directory_round_trip(tmp_path):
    alice_dir, bob_dir, alice_id, bob_id = setup_two_parties(tmp_path)
    shown = ok(alice_dir, op="msg_directory_show")
    assert shown["users"] == ["bob"]
    assert len(shown["directory_digest"]) == 64


def test_hello_names_the_intended_recipient(tmp_path):
    alice_dir, bob_dir, alice_id, bob_id = setup_two_parties(tmp_path)
    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    assert hello["hello"]["to_user"] == "bob"
    assert hello["hello"]["to_fp"] == bob_id["fingerprint"]


def test_handshake_survives_separate_processes(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    session_id = full_handshake(alice_dir, bob_dir)
    status_alice = ok(alice_dir, op="msg_status", session_id=session_id)
    status_bob = ok(bob_dir, op="msg_status", session_id=session_id)
    assert status_alice["role"] == "initiator"
    assert status_bob["role"] == "responder"
    assert status_alice["peer_user"] == "bob"
    assert status_bob["confirmed"] is True


def test_ephemerals_are_gone_after_the_handshake(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    pending = list((alice_dir / "pqc-kv-messaging" / "ephemeral").glob("hs-*.json"))
    assert len(pending) == 1
    accept = ok(bob_dir, op="msg_handshake_finish", self_user="bob", hello=hello["hello"])
    ok(alice_dir, op="msg_handshake_complete", self_user="alice", accept=accept["accept"])
    assert list((alice_dir / "pqc-kv-messaging" / "ephemeral").glob("hs-*.json")) == []
    # The responder never wrote one at all.
    bob_eph = bob_dir / "pqc-kv-messaging" / "ephemeral"
    assert not bob_eph.exists() or list(bob_eph.glob("hs-*.json")) == []


def test_message_round_trip_through_the_adapter(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    session_id = full_handshake(alice_dir, bob_dir)
    body = "the quick brown fox " * 400  # ~7.6 KB -> several fragments
    sent = ok(alice_dir, op="msg_send", session_id=session_id, body=body)
    assert sent["fragment_count"] > 1

    received = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=sent["fragments"])
    assert len(received["delivered"]) == 1
    assert received["delivered"][0]["body"] == body


def test_replay_through_the_adapter_is_refused(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    session_id = full_handshake(alice_dir, bob_dir)
    sent = ok(alice_dir, op="msg_send", session_id=session_id, body="once")
    ok(bob_dir, op="msg_receive", session_id=session_id, fragments=sent["fragments"])
    again = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=sent["fragments"])
    assert again["delivered"] == []
    assert again["duplicate_fragments"] == len(sent["fragments"])


def test_readdressed_message_through_the_adapter_is_refused(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    session_id = full_handshake(alice_dir, bob_dir)
    sent = ok(alice_dir, op="msg_send", session_id=session_id, body="for bob")
    tampered = [{**f, "h": {**f["h"], "ru": "carol"}} for f in sent["fragments"]]
    received = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=tampered)
    assert received["delivered"] == []
    assert received["failures"][0]["reason"] == "wrong_recipient"


def test_revocation_blocks_messaging_through_the_adapter(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    session_id = full_handshake(alice_dir, bob_dir)
    # Phase 1 revocation on bob's side must stop him receiving.
    ok(bob_dir, op="setup", owners={"brief": "bob"}, contents={"brief": "x"},
       disabled=[], key_material="k")
    ok(bob_dir, op="revoke", actor="bob")
    sent = ok(alice_dir, op="msg_send", session_id=session_id, body="blocked")
    received = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=sent["fragments"])
    assert received["delivered"] == []
    assert received["failures"][0]["reason"] == "policy_denied"


def test_handshake_addressed_to_a_third_party_is_refused(tmp_path):
    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    carol_dir = tmp_path / "carol"; carol_dir.mkdir()
    ok(carol_dir, op="msg_identity", user_id="carol")
    alice_public = ok(alice_dir, op="msg_identity", user_id="alice", export_public=True)["public"]
    ok(carol_dir, op="msg_directory_add", identity=alice_public)
    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    response = call(carol_dir, op="msg_handshake_finish", self_user="carol", hello=hello["hello"])
    assert response == {"error": "request_failed"}


def test_unknown_session_is_opaque(tmp_path):
    state = tmp_path / "s"; state.mkdir()
    ok(state, op="msg_identity", user_id="alice")
    assert call(state, op="msg_status", session_id="s-does-not-exist") == {"error": "request_failed"}


def test_malformed_messaging_request_is_opaque(tmp_path):
    state = tmp_path / "s"; state.mkdir()
    for request in (
        {"op": "msg_send"},
        {"op": "msg_receive", "session_id": 1, "fragments": "not-a-list"},
        {"op": "msg_handshake_complete", "self_user": "x"},
        {"op": "msg_identity", "user_id": None},
    ):
        assert call(state, **request) == {"error": "request_failed"}, request


def test_no_secrets_in_messaging_output(tmp_path):
    """Sweep the state dir for key material, then confirm none appears in output."""
    import base64

    alice_dir, bob_dir, *_ = setup_two_parties(tmp_path)
    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    accept = ok(bob_dir, op="msg_handshake_finish", self_user="bob", hello=hello["hello"])
    confirm = ok(alice_dir, op="msg_handshake_complete", self_user="alice", accept=accept["accept"])
    sent = ok(alice_dir, op="msg_send", session_id=hello["session_id"], body="secret body")

    secrets = []
    for path in (alice_dir / "pqc-kv-messaging").rglob("*.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        for key in ("secret_key", "mlkem_secret", "x25519_secret", "chain_key"):
            if isinstance(data, dict) and data.get(key):
                try:
                    secrets.append(base64.b64decode(data[key]))
                except Exception:
                    pass
        for name in ("send", "recv"):
            block = data.get(name) if isinstance(data, dict) else None
            if isinstance(block, dict) and block.get("chain_key"):
                secrets.append(base64.b64decode(block["chain_key"]))

    blobs = [json.dumps(x) for x in (hello, accept, confirm, sent)]
    for secret in secrets:
        for blob in blobs:
            assert secret.hex() not in blob
            assert base64.b64encode(secret).decode() not in blob
