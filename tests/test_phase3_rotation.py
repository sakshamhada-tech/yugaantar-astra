"""Goal 1: versioned key rotation with a clock-free cutoff.

"A request using the old key" in this adapter = a read whose `key_version` names a
ring version that is no longer active. Ordinary reads never name a version, so the
cutoff only ever affects a client that loaded an asset under version N and keeps
using it after the rotation notice lands.
"""

from __future__ import annotations

import json
import time

import pytest

from pqc_kv.keyring import ACTIVE, RETIRED, RETIRING, REVOKED, KeyRing, KeyRingError
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


# ------------------------------------------------------------------ the ring
def test_initial_ring_has_one_active_version(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    summary = r.summary()
    assert summary["active_version"] == 1
    assert summary["versions"] == [{"version": 1, "state": ACTIVE, "epoch": 0, "grace": 2}]


def test_rotate_creates_n_plus_1_and_retires_n(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    old, new = r.rotate(grace=3)
    assert (old.version, old.state, old.grace) == (1, RETIRING, 3)
    assert (new.version, new.state) == (2, ACTIVE)
    assert r.active().version == 2


def test_versions_are_monotonic_and_never_reused(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    for expected in (2, 3, 4):
        _, new = r.rotate()
        assert new.version == expected
    # Four versions exist after three rotations starting from v1: none were reused
    # and none were skipped.
    assert [v["version"] for v in r.summary()["versions"]] == [1, 2, 3, 4]


def test_each_version_has_distinct_key_material(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate()
    assert r.kem_pair(1).public_key != r.kem_pair(2).public_key
    assert r.dsa_pair(1).public_key != r.dsa_pair(2).public_key


def test_key_files_record_their_ring_version_not_the_file_format_version(tmp_path):
    """Regression: `key_version` is the keystore's file-format field.

    Writing the ring version into it would (a) be clobbered by write_key_file and
    (b) make a v2 key look like a v1 key.
    """
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate()
    for version in (1, 2):
        raw = json.loads((r.keys_dir / f"kem-service-v{version}.key").read_text())
        assert raw["ring_version"] == version
        assert raw["key_version"] == 1, "file format version, not the ring version"


def test_ring_rejects_a_tampered_state(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    path = r.path
    data = json.loads(path.read_text())
    data["entries"][0]["state"] = "not-a-state"
    path.write_text(json.dumps(data))
    with pytest.raises(KeyRingError):
        r.load()


# ------------------------------------------------- the grace boundary, both sides
def test_old_version_accepted_inside_the_grace_budget(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate(grace=2)
    # epoch 0 -> accepted, epoch becomes 1
    allowed, ring = r.admit_read(1)
    assert allowed is True
    r.save(ring)
    assert r.summary()["versions"][0]["epoch"] == 1


def test_old_version_rejected_exactly_at_the_boundary(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate(grace=2)
    for _ in range(2):                      # spend the whole budget
        allowed, ring = r.admit_read(1)
        assert allowed is True
        r.save(ring)
    # The next one is the boundary: this is the "cutoff" the goal asks for.
    allowed, ring = r.admit_read(1)
    assert allowed is False
    r.save(ring)
    assert r.summary()["versions"][0]["state"] == RETIRED


def test_a_zero_grace_means_the_cutoff_is_immediate(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate(grace=0)
    allowed, ring = r.admit_read(1)
    assert allowed is False
    r.save(ring)


def test_retired_and_revoked_versions_are_always_rejected(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate(grace=99)
    r.retire(1)
    assert r.admit_read(1)[0] is False
    r2 = KeyRing(tmp_path / "ring2")
    r2.create_initial()
    r2.rotate(grace=99)
    r2.revoke_version(1)
    assert r2.admit_read(1)[0] is False
    assert r2.summary()["versions"][0]["state"] == REVOKED


def test_active_version_is_never_charged(tmp_path):
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate(grace=1)
    for _ in range(5):
        assert r.admit_read(2)[0] is True
    assert r.summary()["versions"][1]["epoch"] == 0


def test_a_rejected_request_does_not_consume_another_callers_grace(tmp_path):
    """Charging only on acceptance: a denial must not exhaust the budget."""
    r = KeyRing(tmp_path / "ring")
    r.create_initial()
    r.rotate(grace=1)
    r.retire(1)          # now always rejected
    for _ in range(5):
        assert r.admit_read(1)[0] is False
    assert r.summary()["versions"][0]["epoch"] == 0


# --------------------------------------------------------------- store.rotate()
def test_rotation_keeps_data_readable_under_the_new_version(tmp_path):
    s = store(tmp_path)
    result = s.rotate({"grace": 2})
    assert result["active_version"] == 2
    assert result["resealed"] == 2
    assert s.read("maya", "brief", "r1") == {"decision": "allow", "body": "brief body"}
    assert s.read("ravi", "notes", "r2") == {"decision": "allow", "body": "notes body"}


def test_every_asset_is_stamped_with_the_new_version(tmp_path):
    s = store(tmp_path)
    s.rotate({"grace": 2})
    versions = {e["key_version"] for e in s._read_state()["assets"].values()}
    assert versions == {2}


def test_old_envelopes_cannot_be_opened_after_rewrap(tmp_path):
    """Re-wrapping must actually re-encrypt, not merely re-label."""
    s = store(tmp_path)
    before = (s.assets_dir / s._read_state()["assets"]["brief"]["file"]).read_bytes()
    s.rotate({"grace": 2})
    after = (s.assets_dir / s._read_state()["assets"]["brief"]["file"]).read_bytes()
    assert before != after


def test_rotation_does_not_run_the_destructive_setup_path(tmp_path, monkeypatch):
    """Explicitly required: rotate must not be setup() in disguise."""
    s = store(tmp_path)
    killed = []

    def boom(*args, **kwargs):
        killed.append(1)
        raise AssertionError("rotate must not touch the setup-only destructive path")

    monkeypatch.setattr(StateStore, "_rotate_keys", boom)
    monkeypatch.setattr(StateStore, "setup", boom)
    result = s.rotate({"grace": 2})
    assert result["active_version"] == 2
    assert killed == []


def test_rotation_preserves_policy_and_revocation(tmp_path):
    s = store(tmp_path)
    s.revoke("maya")
    s.rotate({"grace": 2})
    # Revocation survives the rotation: policy state is untouched.
    assert s.read("maya", "brief", "r3")["decision"] == "deny"
    assert s.read("ravi", "notes", "r4")["decision"] == "allow"


def test_rotation_preserves_the_audit_chain(tmp_path):
    s = store(tmp_path)
    before = s.verify_audit_chain()
    s.rotate({"grace": 2})
    ok, count = s.verify_audit_chain()
    assert ok is True
    assert count == before[1] + 1, "rotation appends exactly one audit record"


def test_rotation_is_recorded_in_the_audit_log(tmp_path):
    s = store(tmp_path)
    s.rotate({"grace": 2})
    records = s.audit_log_records()
    assert records[-1]["op"] == "rotate"
    assert records[-1]["rule"] == "key_v1_to_v2"


def test_rotate_does_not_leave_the_state_without_an_active_version(tmp_path):
    s = store(tmp_path)
    s.rotate({"grace": 1})
    s.rotate({"grace": 1})
    active = [v for v in s.key_status()["versions"] if v["state"] == ACTIVE]
    assert len(active) == 1
    assert active[0]["version"] == 3


# ------------------------------------- end-to-end: a request that names a version
def test_old_version_request_accepted_then_rejected_through_the_store(tmp_path):
    s = store(tmp_path)
    s.rotate({"grace": 2})
    # Inside the budget the old version still works (in-flight client finishes).
    assert s.read("maya", "brief", "o1", request_version=1)["decision"] == "allow"
    assert s.read("maya", "brief", "o2", request_version=1)["decision"] == "allow"
    # At the boundary it is refused, and the version flips to retired.
    assert s.read("maya", "brief", "o3", request_version=1)["decision"] == "deny"
    assert s.key_status()["versions"][0]["state"] == RETIRED
    # The device keeps working -- only the *old key* was refused.
    assert s.read("maya", "brief", "o4")["decision"] == "allow"


def test_old_version_denial_is_recorded_with_its_reason(tmp_path):
    s = store(tmp_path)
    s.rotate({"grace": 0})
    s.read("maya", "brief", "o5", request_version=1)
    assert s.audit_detail("o5")["rule"] == "key_version_rejected"


def test_unknown_key_version_is_refused(tmp_path):
    s = store(tmp_path)
    assert s.read("maya", "brief", "o6", request_version=99)["decision"] == "deny"
    assert s.audit_detail("o6")["rule"] == "key_version_rejected"


def test_rotation_does_not_break_the_deny_oracle_fix(tmp_path):
    """A version denial and an owner denial must look identical to the caller."""
    s = store(tmp_path)
    s.rotate({"grace": 0})
    a = json.dumps(s.read("maya", "brief", "d1", request_version=1), sort_keys=True)
    b = json.dumps(s.read("ravi", "brief", "d2"), sort_keys=True)
    assert a == b == '{"decision": "deny"}'


def test_rotation_cost_is_measured(tmp_path):
    """Report the real re-wrap cost rather than claiming it is negligible."""
    s = StateStore(tmp_path)
    contents = {f"asset-{i}": f"body {i}" for i in range(20)}
    s.setup({
        "owners": {k: "maya" for k in contents},
        "contents": contents,
        "disabled": [],
        "key_material": "M",
    })
    start = time.perf_counter()
    result = s.rotate({"grace": 2})
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert result["resealed"] == 20
    # Not a performance claim; a guard against accidental O(n^2).
    assert elapsed_ms < 30_000, f"rotation of 20 assets took {elapsed_ms:.0f} ms"
    print(f"\nrotation of 20 assets: {elapsed_ms:.1f} ms")


# --------------------------------------------------- through the real adapter
def _adapter(state_dir, **request):
    import os
    import subprocess
    import sys

    root = __import__("pathlib").Path(__file__).resolve().parent.parent
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state_dir)
    done = subprocess.run(
        [sys.executable, "-B", str(root / "track4_service.py")],
        input=json.dumps(request).encode(), cwd=str(root), env=env,
        capture_output=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout)


def test_rotation_through_the_adapter_end_to_end(tmp_path):
    state = tmp_path / "s"
    state.mkdir()
    assert _adapter(state, **SETUP) == {"ready": True}
    assert _adapter(state, op="key_status")["active_version"] == 1

    rotated = _adapter(state, op="rotate", grace=2)
    assert rotated["active_version"] == 2
    assert rotated["resealed"] == 2

    # Ordinary read still works, under the new version.
    assert _adapter(state, op="read", actor="maya", asset="brief", request_id="e1") == {
        "decision": "allow", "body": "brief body",
    }
    # An in-flight client naming v1 is served inside the grace budget...
    assert _adapter(state, op="read", actor="maya", asset="brief",
                    request_id="e2", key_version=1)["decision"] == "allow"
    assert _adapter(state, op="read", actor="maya", asset="brief",
                    request_id="e3", key_version=1)["decision"] == "allow"
    # ...and refused at the boundary, with no reason disclosed.
    assert _adapter(state, op="read", actor="maya", asset="brief",
                    request_id="e4", key_version=1) == {"decision": "deny"}
    # The cut-off is visible to the operator, and the log chain is still intact.
    status = _adapter(state, op="key_status")
    assert status["versions"][0]["state"] == "retired"
    assert _adapter(state, op="log_verify")["ok"] is True


def test_adapter_rejects_a_malformed_grace(tmp_path):
    state = tmp_path / "s"
    state.mkdir()
    _adapter(state, **SETUP)
    for bad in ("2", -1, 1.5, True, None):
        assert _adapter(state, op="rotate", grace=bad) == {"error": "malformed_request"}


def test_a_rotation_does_not_need_a_new_setup(tmp_path):
    """The contract's setup wipes state. Rotation must never be mistaken for it."""
    state = tmp_path / "s"
    state.mkdir()
    _adapter(state, **SETUP)
    _adapter(state, op="revoke", actor="maya")
    _adapter(state, op="rotate", grace=2)
    # Revocation survived: a plain setup would have dropped it.
    assert _adapter(state, op="read", actor="maya", asset="brief",
                    request_id="n1")["decision"] == "deny"
