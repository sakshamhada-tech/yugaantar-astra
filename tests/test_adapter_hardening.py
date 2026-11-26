"""Regressions for defects found by attacking the shipped adapter.

Every test here corresponds to an attack that **succeeded** against an earlier build.
They are not hypothetical: each was run by hand against `track4_service.py`, one process
per request, and each produced a wrong outcome before the fix beside it.

The through-line is a single class of bug, and it is worth naming because it is easy to
reintroduce: **the project has two sibling exception hierarchies** —
`pqc_kv.store.StoreError` and `pqc_kv.keystore.KeyStoreError`. Neither subclasses the
other. Any code path that reads key material can therefore raise an exception that the
`except StoreError` handlers in `store.py` and `team_app.py` do not catch. The result is
not a wrong answer but **no answer**: the process exits 1 with nothing on stdout, which
violates the adapter's contract just as badly as returning protected data would.

The second finding is unrelated and equally simple: a file opened for append defaults to
0644, so the audit log was world-readable while the ciphertext next to it was 0600.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"

SETUP = dict(
    op="setup",
    owners={"brief": "maya", "notes": "ravi"},
    contents={"brief": "MAYA-SECRET", "notes": "RAVI-SECRET"},
    disabled=[],
    key_material="SYNTHETIC-KEY-MATERIAL",
)


def call(state: Path, **request) -> tuple[int, dict | None, str]:
    """One process per request, exactly as the adapter contract requires."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=180,
    )
    body = None
    if done.stdout.strip():
        try:
            body = json.loads(done.stdout)
        except ValueError:
            body = None
    return done.returncode, body, done.stderr.decode("utf-8", "replace")


def ok(state: Path, **request) -> dict:
    code, body, _ = call(state, **request)
    assert code == 0, f"exit {code} for {request.get('op')}"
    assert body is not None and "error" not in body, body
    return body


@pytest.fixture()
def state(tmp_path):
    ok(tmp_path, **SETUP)
    return tmp_path


@pytest.fixture()
def internal(tmp_path):
    return tmp_path / "pqc-kv-state"


# --------------------------------------------------------------------- crashes
# Each of these produced `exit 1` with empty stdout before the fix. A crash is worse
# than a deny: the judge sees no JSON at all, and any wrapper that assumes a reply
# will itself fail.
CORRUPTIONS = [
    ("asset file deleted", lambda p: p.unlink()),
    ("asset file emptied", lambda p: p.write_text("")),
    ("asset file not json", lambda p: p.write_text("not json at all")),
    ("asset file truncated", lambda p: p.write_text(p.read_text()[:20])),
]


@pytest.mark.parametrize("label,mutate", CORRUPTIONS, ids=[c[0] for c in CORRUPTIONS])
def test_a_damaged_asset_file_denies_instead_of_crashing(state, internal, label, mutate):
    """Found by deleting the asset file and reading it back.

    `_open_asset` called `read_key_file`, which raises `KeyStoreError`; the caller only
    caught `StoreError`. The exception escaped to `track4_service.py`, which correctly
    refused to print details -- and so printed nothing at all, exiting 1.
    """
    mutate(next(iter((internal / "assets").glob("*.env"))))
    code, body, _ = call(state, op="read", actor="maya", asset="brief",
                         request_id=f"c-{label}")
    assert code == 0, "the adapter must always answer with JSON"
    assert body == {"decision": "deny"}, body


def test_a_corrupt_keyring_refuses_the_read_instead_of_crashing(state, internal):
    """`self.ring.load()` sat outside the `try` in `_admit_version`."""
    (internal / "keyring.json").write_text("nope")
    code, body, _ = call(state, op="read", actor="maya", asset="brief", request_id="k1")
    assert code == 0
    assert body is not None and body.get("decision") != "allow"


def test_a_state_directory_replaced_by_a_file_does_not_crash(state, internal):
    """`StateStore.__init__` raises `KeyStoreError` from `ensure_private_dir`.

    Every KV operation crashed, because the construction happens inside `dispatch`
    but ahead of the `except StoreError` clause that was meant to cover it.
    """
    import shutil

    shutil.rmtree(internal)
    internal.write_text("not a directory")
    for op in (dict(op="read", actor="maya", asset="brief", request_id="s1"),
               dict(op="audit", request_id="s1"),
               dict(op="revoke", actor="ravi")):
        code, body, stderr = call(state, **op)
        assert code == 0, f"{op['op']} crashed"
        assert body is not None and "error" in body
        # And the refusal stays opaque: no path, no exception type.
        assert "pqc-kv-state" not in json.dumps(body)
        assert "KeyStore" not in stderr


def test_a_damaged_key_file_never_yields_the_body(state, internal):
    """Fail closed: unavailable key material is a deny, never plaintext."""
    (internal / "keys" / "kem-service-v1.key").write_text("junk")
    code, body, _ = call(state, op="read", actor="maya", asset="brief", request_id="d1")
    assert code == 0
    assert "MAYA-SECRET" not in json.dumps(body)
    assert body.get("decision") != "allow"


# ------------------------------------------------------------------ file modes
def test_no_file_in_the_state_directory_is_readable_by_other_users(state, internal):
    """Found by auditing permissions after a setup.

    `audit.jsonl` was created 0644 by a plain `open(..., "a")` and kept that mode across
    every setup, because the truncate path used `write_bytes` (also 0644). The audit log
    records *who was denied access to which asset* -- exactly the map an attacker wants
    before deciding what to try.
    """
    ok(state, op="read", actor="ravi", asset="brief", request_id="m1")
    ok(state, op="read", actor="maya", asset="brief", request_id="m2")

    offenders = []
    for path in internal.rglob("*"):
        if path.is_file():
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                offenders.append((str(path.relative_to(internal)), oct(mode)))
    assert offenders == [], f"world/group-readable: {offenders}"


def test_the_audit_log_is_not_a_reconnaissance_map_for_local_users(state, internal):
    """The content makes the mode matter: denials name the actor and the asset."""
    ok(state, op="read", actor="ravi", asset="brief", request_id="n1")
    audit = internal / "audit.jsonl"
    assert audit.exists()
    assert stat.S_IMODE(audit.stat().st_mode) == 0o600
    assert "brief" in audit.read_text()  # the data really is sensitive


# ------------------------------------------------------------------ resource limits
def test_an_oversized_field_cannot_stall_the_adapter(state):
    """The judge's per-operation timeout is 8 s. Input must not approach it.

    A megabyte in a single field is refused on length before anything tries to parse
    or compare it, so the cost is bounded by the read, not the content.
    """
    import time

    start = time.perf_counter()
    code, body, _ = call(state, op="read", actor="a" * 1_000_000, asset="brief",
                         request_id="big1")
    elapsed = time.perf_counter() - start
    assert code == 0
    assert body is not None and body.get("decision") != "allow"
    assert elapsed < 5.0, f"took {elapsed:.1f}s of an 8s budget"


def test_a_huge_detection_log_is_capped_not_processed_forever(state):
    """`max_line_len` and `max_events` bound the work; 8 MB answers in well under 8 s."""
    import time

    start = time.perf_counter()
    code, body, _ = call(state, op="detect_log", log="A" * 8_000_000)
    elapsed = time.perf_counter() - start
    assert code == 0
    assert body is not None
    # The line was refused rather than parsed as an event.
    assert body["ingest"]["events_accepted"] == 0
    assert elapsed < 5.0, f"took {elapsed:.1f}s of an 8s budget"
