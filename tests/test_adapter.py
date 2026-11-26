"""End-to-end adapter tests: one real subprocess per request, exactly like the judge.

Also checks the two things a judge will probe:
  * the synthetic key material never appears in stdout, stderr or an exception;
  * no private key bytes ever appear in any process output or repr().
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"

SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi"},
    "contents": {"brief": "lost device body", "notes": "peer body"},
    "disabled": ["retired-user"],
    "key_material": "SYNTHETIC-MARKER-9f2c",
}


def call(request: dict, state_dir: Path, expect_ok: bool = True):
    """Run the adapter the way the worker does: fresh process, JSON on stdin."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    process = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(),
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        timeout=30,
    )
    if expect_ok:
        assert process.returncode == 0, process.stderr.decode()
        return json.loads(process.stdout), process
    return None, process


@pytest.fixture()
def configured(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    response, _ = call(dict(SETUP), state)
    assert response == {"ready": True}
    return state


def test_lost_device_scenario(configured):
    state = configured
    assert call({"op": "read", "actor": "maya", "asset": "brief", "request_id": "a1"}, state)[0] == {
        "decision": "allow",
        "body": "lost device body",
    }
    call({"op": "revoke", "actor": "maya"}, state)
    denied, _ = call({"op": "read", "actor": "maya", "asset": "brief", "request_id": "a2"}, state)
    assert denied["decision"] == "deny"
    assert "body" not in denied
    audit, _ = call({"op": "audit", "request_id": "a2"}, state)
    # 3c: exactly the two fields the contract names, nothing else.
    assert audit == {"request_id": "a2", "decision": "deny"}
    peer, _ = call({"op": "read", "actor": "ravi", "asset": "notes", "request_id": "a3"}, state)
    assert peer["body"] == "peer body"


def test_revocation_survives_new_processes(configured):
    call({"op": "revoke", "actor": "maya"}, configured)
    for _ in range(3):
        assert call({"op": "read", "actor": "maya", "asset": "brief", "request_id": "p"}, configured)[0]["decision"] == "deny"


def test_wrong_owner_denied(configured):
    response, _ = call({"op": "read", "actor": "maya", "asset": "notes", "request_id": "w1"}, configured)
    assert response["decision"] == "deny"


def test_disabled_at_setup_denied(configured):
    response, _ = call({"op": "read", "actor": "retired-user", "asset": "brief", "request_id": "w2"}, configured)
    assert response["decision"] == "deny"


def test_unknown_operation(configured):
    response, _ = call({"op": "teleport"}, configured)
    assert response == {"error": "unsupported_operation"}


def test_malformed_request_exits_cleanly(configured):
    _, process = call(["not", "an", "object"], configured, expect_ok=False)
    assert process.returncode == 1
    # The adapter must not echo request data on failure.
    assert b"not an object" not in process.stderr


def test_key_material_never_leaves_the_process(configured):
    _, process = call({"op": "read", "actor": "maya", "asset": "brief", "request_id": "k1"}, configured)
    assert b"SYNTHETIC-MARKER-9f2c" not in process.stdout
    assert b"SYNTHETIC-MARKER-9f2c" not in process.stderr
    # Also absent from the audit surface.
    audit, audit_process = call({"op": "audit", "request_id": "k1"}, configured)
    assert "SYNTHETIC-MARKER-9f2c" not in json.dumps(audit)
    assert b"SYNTHETIC-MARKER-9f2c" not in audit_process.stdout + audit_process.stderr


def test_protected_read_matches_contract(configured):
    """ML-KEM-768 ciphertext + HMAC-SHA-256 proof over challenge+body."""
    from pqc_kv import kem

    recipient = kem.generate_keypair()
    challenge = "nonce-abc-123"
    response, _ = call(
        {
            "op": "protected_read",
            "actor": "maya",
            "asset": "brief",
            "challenge": challenge,
            "public_key": base64.b64encode(recipient.public_key).decode(),
            "request_id": "pr1",
        },
        configured,
    )
    assert response["decision"] == "allow"
    ciphertext = base64.b64decode(response["ciphertext"])
    assert len(ciphertext) == 1088

    shared = kem.decapsulate(ciphertext, recipient.secret_key)
    expected = hmac.new(
        shared, (challenge + "lost device body").encode(), hashlib.sha256
    ).hexdigest()
    assert response["proof"] == expected
    assert response["proof"] == response["proof"].lower()
    assert len(response["proof"]) == 64


def test_protected_read_denied_after_revocation(configured):
    from pqc_kv import kem

    recipient = kem.generate_keypair()
    call({"op": "revoke", "actor": "maya"}, configured)
    response, _ = call(
        {
            "op": "protected_read",
            "actor": "maya",
            "asset": "brief",
            "challenge": "x",
            "public_key": base64.b64encode(recipient.public_key).decode(),
            "request_id": "pr2",
        },
        configured,
    )
    assert response == {"decision": "deny"}
    audit, _ = call({"op": "audit", "request_id": "pr2"}, configured)
    assert audit["decision"] == "deny"


def test_protected_read_rejects_bad_public_key(configured):
    response, process = call(
        {
            "op": "protected_read",
            "actor": "maya",
            "asset": "brief",
            "challenge": "x",
            "public_key": "!!!not base64!!!",
            "request_id": "pr3",
        },
        configured,
    )
    assert response == {"decision": "deny"}
    assert b"Traceback" not in process.stderr


def test_no_private_key_material_in_any_output(configured):
    """Sweep the state directory for secrets, then confirm none appear in output."""
    key_dir = configured / "pqc-kv-state" / "keys"
    secrets = []
    for path in key_dir.glob("*.key"):
        data = json.loads(path.read_text(encoding="utf-8"))
        for field in ("secret_key", "mlkem_secret", "x25519_secret"):
            if field in data:
                secrets.append(base64.b64decode(data[field]))
    assert secrets, "expected private keys on disk"

    responses = [
        call({"op": "read", "actor": "maya", "asset": "brief", "request_id": "z1"}, configured),
        call({"op": "audit", "request_id": "z1"}, configured),
        call({"op": "revoke", "actor": "maya"}, configured),
    ]
    for response, process in responses:
        blob = json.dumps(response).encode() + process.stdout + process.stderr
        for secret in secrets:
            assert secret not in blob
            assert base64.b64encode(secret) not in blob
            assert secret[:32].hex().encode() not in blob


def test_repr_of_key_objects_hides_secrets():
    from pqc_kv import dsa, hybrid, kem

    pairs = [kem.generate_keypair(), dsa.generate_keypair(), hybrid.generate_keypair()]
    for pair in pairs:
        text = repr(pair) + str(pair)
        for name in ("secret_key", "mlkem_secret", "x25519_secret"):
            value = getattr(pair, name, None)
            if value:
                assert value.hex()[:32] not in text
                assert value[:16].hex() not in text


def test_state_directory_permissions_are_private(configured):
    import stat

    key_dir = configured / "pqc-kv-state" / "keys"
    assert stat.S_IMODE(key_dir.stat().st_mode) == 0o700
    for path in key_dir.glob("*.key"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
