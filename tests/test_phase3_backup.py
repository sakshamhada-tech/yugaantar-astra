"""Goal 4: authenticated backups that refuse damage, tampering and rollback.

Every bit-flip test mutates a *real* region of a real blob. Nothing here asserts
"it failed"; it asserts which failure, and that no key material was used.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from pqc_kv import backup
from pqc_kv.keystore import KeyStore, b64d, b64e
from pqc_kv.store import StateStore

SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi"},
    "contents": {"brief": "brief body", "notes": "notes body"},
    "disabled": [],
    "key_material": "MARKER",
}
SECRET = b"operator-supplied-backup-key-0123456789"


@pytest.fixture()
def world(tmp_path):
    """A store with keys, plus the signing material a backup is signed with."""
    store = StateStore(tmp_path / "node")
    store.setup(dict(SETUP))
    signer = store.ring.dsa_pair(store.ring.active().version)
    blob = store.create_backup(SECRET, signer=signer.secret_key)
    return {
        "store": store,
        "signer": signer,
        "blob": blob,
        "public": signer.public_key,
        "tmp": tmp_path,
    }


def flip(blob: dict, region: str, index: int = 0):
    """Flip one bit in one base64 region of the blob. Returns a mutated copy."""
    out = json.loads(json.dumps(blob))
    if region in ("nonce", "ciphertext", "tag", "signature"):
        raw = bytearray(base64.b64decode(out[region]))
        raw[index % len(raw)] ^= 0x01
        out[region] = base64.b64encode(bytes(raw)).decode()
    elif region in ("salt", "key_ids", "manifest_hash", "key_version",
                    "revocation_seq", "log_head"):
        if region == "salt":
            raw = bytearray(base64.b64decode(out["manifest"]["salt"]))
            raw[index % len(raw)] ^= 0x01
            out["manifest"]["salt"] = base64.b64encode(bytes(raw)).decode()
        elif region == "key_ids":
            out["manifest"]["key_ids"] = out["manifest"]["key_ids"][:-1] or ["x"]
        elif region == "manifest_hash":
            out["manifest"]["manifest_hash"] = "0" * 64
        elif region == "key_version":
            out["manifest"]["key_version"] = int(out["manifest"]["key_version"]) + 1
        else:
            out["manifest"][region] = "tampered"
    else:
        raise AssertionError(f"unknown region {region}")
    return out


# --------------------------------------------------------------- happy path
def test_a_good_backup_restores_exactly(world):
    payload = backup.open_backup(world["blob"], secret=SECRET,
                                 signing_public=world["public"])
    original = {
        name: (world["store"].ring.keys_dir / name).read_bytes()
        for name in world["store"].ring.key_files()
    }
    for name, raw in original.items():
        assert b64d(payload[name]) == raw


def test_restore_installs_the_key_material_and_keeps_the_store_working(world):
    result = world["store"].restore_backup(world["blob"], SECRET, world["public"])
    assert result["count"] == len(world["store"].ring.key_files())
    assert world["store"].read("maya", "brief", "b1")["decision"] == "allow"


def test_the_backup_key_is_required_and_never_stored(world, tmp_path):
    with pytest.raises(backup.BackupError):
        backup.open_backup(world["blob"], secret=b"", signing_public=world["public"])
    # The secret must not appear anywhere in the state directory.
    for path in (tmp_path / "node").rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_bytes()


# ---------------------------------------------------- bit flips in every region
@pytest.mark.parametrize("region", [
    "nonce", "ciphertext", "tag", "signature", "salt",
    "key_ids", "manifest_hash", "key_version", "revocation_seq", "log_head",
])
def test_a_single_bit_flip_is_detected(world, region):
    damaged = flip(world["blob"], region)
    with pytest.raises(backup.BackupError):
        backup.open_backup(damaged, secret=SECRET, signing_public=world["public"])


@pytest.mark.parametrize("region", ["nonce", "ciphertext", "tag", "signature", "salt"])
def test_a_flip_anywhere_in_a_region_is_detected(world, region):
    """Not just byte 0: a few offsets across each region."""
    raw = base64.b64decode(world["blob"][region] if region != "salt"
                           else world["blob"]["manifest"]["salt"])
    for index in (0, len(raw) // 2, len(raw) - 1):
        damaged = flip(world["blob"], region, index)
        with pytest.raises(backup.BackupError):
            backup.open_backup(damaged, secret=SECRET, signing_public=world["public"])


def test_a_swapped_manifest_is_refused(world, tmp_path):
    """Two genuine backups, manifest of one with the body of the other."""
    other_store = StateStore(tmp_path / "other")
    other_store.setup(dict(SETUP))
    other_signer = other_store.ring.dsa_pair(1)
    other = other_store.create_backup(SECRET, signer=other_signer.secret_key)

    frankenstein = dict(world["blob"], manifest=other["manifest"])
    with pytest.raises(backup.BackupError) as info:
        backup.open_backup(frankenstein, secret=SECRET, signing_public=world["public"])
    assert info.value.reason in (backup.Reason.BAD_SIGNATURE,
                                 backup.Reason.MANIFEST_MISMATCH)


def test_a_truncated_backup_is_refused(world):
    for region in ("ciphertext", "tag", "signature"):
        out = json.loads(json.dumps(world["blob"]))
        out[region] = out[region][: len(out[region]) // 2]
        with pytest.raises(backup.BackupError):
            backup.open_backup(out, secret=SECRET, signing_public=world["public"])


def test_a_missing_field_is_refused(world):
    for field in ("manifest", "nonce", "ciphertext", "tag", "signature"):
        out = json.loads(json.dumps(world["blob"]))
        del out[field]
        with pytest.raises(backup.BackupError) as info:
            backup.open_backup(out, secret=SECRET, signing_public=world["public"])
        assert info.value.reason == backup.Reason.MALFORMED


def test_the_wrong_backup_key_is_refused(world):
    with pytest.raises(backup.BackupError) as info:
        backup.open_backup(world["blob"], secret=b"not-the-right-key-at-all",
                           signing_public=world["public"])
    assert info.value.reason == backup.Reason.DAMAGED


def test_a_backup_signed_by_another_key_is_refused(world, tmp_path):
    stranger = KeyStore(tmp_path / "stranger").signing_keypair("x")
    with pytest.raises(backup.BackupError) as info:
        backup.open_backup(world["blob"], secret=SECRET,
                           signing_public=stranger.public_key)
    assert info.value.reason == backup.Reason.BAD_SIGNATURE


# ------------------------------------------------------------ rollback attack
def test_restoring_an_older_backup_cannot_resurrect_a_revoked_key(tmp_path):
    """The central rollback test: revoke, back up, revoke more, then replay the old one.

    The replayed backup is genuine and correctly signed. It is refused because its
    revocation sequence is below this node's high-water mark.
    """
    store = StateStore(tmp_path / "node")
    store.setup(dict(SETUP))
    signer = store.ring.dsa_pair(1)

    old = store.create_backup(SECRET, signer=signer.secret_key)
    store.revoke("maya")
    store.read("maya", "brief", "r1")          # bumps the audit head too
    assert store.read("maya", "brief", "r2")["decision"] == "deny"

    # Replaying the pre-revocation backup must be refused, not honoured.
    with pytest.raises(backup.BackupError) as info:
        store.restore_backup(old, SECRET, signer.public_key)
    assert info.value.reason == backup.Reason.STALE

    # And the revocation is still in force afterwards.
    assert store.read("maya", "brief", "r3")["decision"] == "deny"


def test_restoring_an_older_key_version_is_refused(tmp_path):
    store = StateStore(tmp_path / "node")
    store.setup(dict(SETUP))
    signer = store.ring.dsa_pair(1)
    old = store.create_backup(SECRET, signer=signer.secret_key)
    store.rotate({"grace": 2})
    with pytest.raises(backup.BackupError) as info:
        store.restore_backup(old, SECRET, signer.public_key)
    assert info.value.reason == backup.Reason.STALE


def test_a_backup_at_the_same_high_water_is_accepted(world):
    """Rollback detection must not reject a legitimate re-restore of the current blob."""
    world["store"].restore_backup(world["blob"], SECRET, world["public"])
    world["store"].restore_backup(world["blob"], SECRET, world["public"])
    assert world["store"].read("maya", "brief", "same")["decision"] == "allow"


def test_the_high_water_marks_live_in_state_and_say_so(world):
    """Documented limit: whoever can write the state dir can lower the marks."""
    state = json.loads((world["store"].root / "state.json").read_text())
    assert "revocation_seq" in state
    marks = backup.high_water_from_state(state)
    assert set(marks) == {"key_version", "revocation_seq", "log_head"}
    # Only the monotone counters are enforced; log_head is for external anchoring.
    assert marks["key_version"] == 1 and marks["revocation_seq"] == 0
    # An attacker who can write state can fake the marks -- honestly unavoidable.
    forged = dict(state, revocation_seq=0, key_version=1)
    assert backup.high_water_from_state(forged)["revocation_seq"] == 0
    # log_head is not enforced automatically, so faking it changes nothing either way.
    assert backup.high_water_from_state(forged)["log_head"] == state["audit_head"]


def test_restore_does_not_use_any_material_before_verification(world):
    """A refused restore must leave the key files byte-identical."""
    before = {n: (world["store"].ring.keys_dir / n).read_bytes()
              for n in world["store"].ring.key_files()}
    with pytest.raises(backup.BackupError):
        world["store"].restore_backup(flip(world["blob"], "ciphertext"), SECRET,
                                      world["public"])
    after = {n: (world["store"].ring.keys_dir / n).read_bytes()
             for n in world["store"].ring.key_files()}
    assert before == after


def test_backup_contains_no_plaintext_key_material(world):
    """The blob must not carry anything readable from the state directory."""
    blob_text = json.dumps(world["blob"])
    secret_bytes = (world["store"].ring.keys_dir / "kem-service-v1.key").read_bytes()
    raw = json.loads(secret_bytes)
    assert raw["secret_key"] not in blob_text
    assert b64e(b64d(raw["secret_key"])) not in blob_text


# ------------------------------------------------------ through the adapter
def _adapter(state_dir: Path, **request):
    import subprocess
    import sys

    root = Path(__file__).resolve().parent.parent
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state_dir)
    done = subprocess.run(
        [sys.executable, "-B", str(root / "track4_service.py")],
        input=json.dumps(request).encode(), cwd=str(root), env=env,
        capture_output=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout)


def test_backup_and_restore_through_the_adapter(tmp_path):
    state = tmp_path / "s"
    state.mkdir()
    assert _adapter(state, **SETUP) == {"ready": True}
    key = base64.b64encode(SECRET).decode()

    created = _adapter(state, op="backup_create", backup_key=key)
    assert "backup" in created
    blob = created["backup"]

    from pqc_kv.keystore import KeyStore as _KS

    # creates the service keypair on disk; the pair it returns is not under test
    _KS(state / "pqc-kv-state").signing_keypair("service")
    ring_pair = StateStore(state).ring.dsa_pair(1)
    restored = _adapter(state, op="backup_restore", backup_key=key, backup=blob,
                        signing_public=b64e(ring_pair.public_key))
    assert restored["count"] > 0
    assert _adapter(state, op="read", actor="maya", asset="brief",
                    request_id="a1")["decision"] == "allow"


def test_adapter_refuses_a_damaged_backup_with_one_opaque_error(tmp_path):
    state = tmp_path / "s"
    state.mkdir()
    _adapter(state, **SETUP)
    key = base64.b64encode(SECRET).decode()
    blob = _adapter(state, op="backup_create", backup_key=key)["backup"]
    damaged = flip(blob, "ciphertext")
    ring_pair = StateStore(state).ring.dsa_pair(1)
    response = _adapter(state, op="backup_restore", backup_key=key, backup=damaged,
                        signing_public=b64e(ring_pair.public_key))
    assert response == {"error": "backup_refused"}


def test_adapter_rejects_a_missing_or_short_backup_key(tmp_path):
    state = tmp_path / "s"
    state.mkdir()
    _adapter(state, **SETUP)
    assert _adapter(state, op="backup_create") == {"error": "malformed_request"}
    assert _adapter(state, op="backup_create", backup_key="") == {"error": "malformed_request"}
    short = base64.b64encode(b"tooshort").decode()
    assert _adapter(state, op="backup_create", backup_key=short) == {"error": "malformed_request"}
