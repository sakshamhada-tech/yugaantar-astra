"""Encrypted-at-rest store: policy, revocation, audit chain, integrity failures."""

from __future__ import annotations

import json

import pytest

from pqc_kv import keystore
from pqc_kv.store import StateStore

SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi"},
    "contents": {"brief": "lost-device synthetic body", "notes": "peer synthetic body"},
    "disabled": ["already-gone"],
    "key_material": "SYNTHETIC-SENSITIVE-MARKER",
}


def make_store(tmp_path) -> StateStore:
    return StateStore(tmp_path)


def test_setup_reports_ready_and_writes_no_plaintext(tmp_path):
    store = make_store(tmp_path)
    assert store.setup(dict(SETUP)) == {"ready": True}
    secrets = [b"lost-device synthetic body", b"peer synthetic body", b"SYNTHETIC-SENSITIVE-MARKER"]
    for path in store.root.rglob("*"):
        if path.is_file():
            blob = path.read_bytes()
            for secret in secrets:
                assert secret not in blob, f"plaintext leaked into {path}"


def test_owner_can_read_exact_body(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    # Phase 3 / 3a: the response carries no rule label. The contract specifies only
    # decision and body; the rule lives in the audit record (see test_phase3_fixes).
    assert store.read("maya", "brief", "r1") == {
        "decision": "allow",
        "body": "lost-device synthetic body",
    }


def test_non_owner_denied_without_body(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    response = store.read("maya", "notes", "r2")
    assert response["decision"] == "deny"
    assert "body" not in response


def test_unknown_asset_and_disabled_actor_denied(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    # Both denials are indistinguishable to the caller: that is the point of 3a.
    assert store.read("maya", "nope", "r3") == {"decision": "deny"}
    assert store.read("already-gone", "brief", "r4") == {"decision": "deny"}
    # The operator can still tell them apart in the record.
    assert store.audit_detail("r3")["rule"] == "unknown_asset"
    assert store.audit_detail("r4")["rule"] == "identity_revoked"


def test_revocation_persists_across_instances(tmp_path):
    make_store(tmp_path).setup(dict(SETUP))
    make_store(tmp_path).revoke("maya")
    # A brand-new process would build a brand-new StateStore: simulate that.
    assert make_store(tmp_path).read("maya", "brief", "r5")["decision"] == "deny"


def test_revocation_leaves_peers_alone(tmp_path):
    make_store(tmp_path).setup(dict(SETUP))
    make_store(tmp_path).revoke("maya")
    assert make_store(tmp_path).read("ravi", "notes", "r6")["body"] == "peer synthetic body"


def test_audit_explains_denial(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    store.revoke("maya")
    store.read("maya", "brief", "r7")
    entry = make_store(tmp_path).audit_detail("r7")
    assert entry["request_id"] == "r7"
    assert entry["decision"] == "deny"
    assert entry["rule"] == "identity_revoked"
    assert "revoked" in entry["explanation"]
    assert len(entry["audit_hash"]) == 64
    assert "body" not in entry


def test_unknown_audit_id(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    # `unknown` would be a third label the contract does not allow, and it would
    # confirm the id was never used. Fail closed and answer `deny`.
    assert store.audit("never-happened") == {"request_id": "never-happened", "decision": "deny"}


def test_audit_chain_verifies_and_detects_edits(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    for index in range(4):
        store.read("maya", "brief", f"r{index}")
    assert store.verify_audit_chain() == (True, 4)

    lines = store.audit_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    assert record["decision"] == "allow"
    record["decision"] = "deny"  # attacker rewrites history
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    store.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, checked = store.verify_audit_chain()
    # Verification stops at the first record whose hash no longer matches, which
    # is the second line (index 1) -- exactly where the edit happened.
    assert ok is False
    assert checked == 2


def test_deleted_audit_line_is_detected(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    for index in range(3):
        store.read("maya", "brief", f"d{index}")
    lines = store.audit_path.read_text(encoding="utf-8").splitlines()
    store.audit_path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    ok, _ = store.verify_audit_chain()
    assert ok is False


def test_tampered_asset_envelope_fails_closed(tmp_path):
    """A modified ciphertext must produce a deny, not a wrong body or a crash."""
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    entry = store._read_state()["assets"]["brief"]
    path = store.assets_dir / entry["file"]
    record = keystore.read_key_file(path)
    data = json.loads(record["envelope"])
    raw = bytearray(__import__("base64").b64decode(data["ct"]))
    raw[0] ^= 1
    data["ct"] = __import__("base64").b64encode(bytes(raw)).decode()
    keystore.write_key_file(path, {"kind": "asset-envelope", "envelope": json.dumps(data)})

    response = store.read("maya", "brief", "r8")
    assert response["decision"] == "deny"
    assert "body" not in response


def test_copied_envelope_cannot_be_moved_to_another_asset(tmp_path):
    """AAD binds asset id + recipient label, so a swapped file does not open."""
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    assets = store._read_state()["assets"]
    source = store.assets_dir / assets["brief"]["file"]
    target = store.assets_dir / assets["notes"]["file"]
    target.write_bytes(source.read_bytes())
    response = store.read("ravi", "notes", "r9")
    assert response["decision"] == "deny"


def test_setup_is_idempotent_and_keeps_reads_working(tmp_path):
    """Phase 3 replaced Phase 1's key demolition with a versioned ring (goal 1).

    Through Phase 2 this test asserted that `setup` deleted and re-created the
    service keypair. That behaviour is exactly what goal 1 forbids: a rotation must
    not orphan data. Keys now live in a ring and are rotated explicitly; `setup`
    keeps version 1 and re-seals the assets, so a second setup still reads fine.
    The rotation behaviour has its own tests in tests/test_phase3_rotation.py.
    """
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    before = store.ring.summary()
    store.setup(dict(SETUP))
    after = store.ring.summary()
    assert before["active_version"] == after["active_version"] == 1
    assert store.read("maya", "brief", "r10")["body"] == "lost-device synthetic body"


def test_same_body_twice_has_different_ciphertext(tmp_path):
    store = make_store(tmp_path)
    payload = dict(SETUP, contents={"brief": "identical body", "notes": "identical body"})
    store.setup(payload)
    assets = store._read_state()["assets"]
    first = json.loads(keystore.read_key_file(store.assets_dir / assets["brief"]["file"])["envelope"])
    second = json.loads(keystore.read_key_file(store.assets_dir / assets["notes"]["file"])["envelope"])
    assert first["ct"] != second["ct"]


def test_read_before_setup_raises_store_error(tmp_path):
    from pqc_kv.store import StoreError

    with pytest.raises(StoreError):
        make_store(tmp_path).read("maya", "brief", "r11")


def test_synthetic_key_material_is_never_returned(tmp_path):
    store = make_store(tmp_path)
    store.setup(dict(SETUP))
    blob = json.dumps(store.read("maya", "brief", "r12"))
    assert "SYNTHETIC-SENSITIVE-MARKER" not in blob
    assert "SYNTHETIC-SENSITIVE-MARKER" not in json.dumps(store.audit("r12"))
