"""Ephemeral records: initiator-only, private, single-use, bounded, erased."""

from __future__ import annotations

import stat

import pytest

from pqc_kv.messaging import ephemeral


@pytest.fixture()
def root(tmp_path):
    return tmp_path / "state"


def save(root, handshake_id="hs1", **overrides):
    data = dict(
        x25519_secret=b"x" * 32,
        mlkem_secret=b"m" * 2400,
        peer_user="bob",
        peer_fp="f" * 64,
    )
    data.update(overrides)
    ephemeral.save(root, handshake_id, **data)


def path_of(root, handshake_id="hs1"):
    return root / "pqc-kv-messaging" / "ephemeral" / f"hs-{handshake_id}.json"


def test_saved_record_is_private_0600(root):
    save(root)
    assert stat.S_IMODE(path_of(root).stat().st_mode) == 0o600
    directory = root / "pqc-kv-messaging" / "ephemeral"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_round_trip_preserves_secrets(root):
    save(root)
    record = ephemeral.load(root, "hs1")
    assert record["x25519_secret"] == b"x" * 32
    assert record["mlkem_secret"] == b"m" * 2400
    assert record["peer_user"] == "bob"
    assert record["peer_fp"] == "f" * 64


def test_erase_removes_the_file_durably(root):
    save(root)
    assert path_of(root).exists()
    assert ephemeral.erase(root, "hs1") is True
    assert not path_of(root).exists()
    assert ephemeral.pending(root) == []


def test_erase_is_idempotent(root):
    save(root)
    assert ephemeral.erase(root, "hs1") is True
    assert ephemeral.erase(root, "hs1") is False


def test_load_after_erase_fails(root):
    save(root)
    ephemeral.erase(root, "hs1")
    with pytest.raises(ephemeral.EphemeralError):
        ephemeral.load(root, "hs1")


def test_load_of_unknown_handshake_fails(root):
    with pytest.raises(ephemeral.EphemeralError):
        ephemeral.load(root, "never-existed")


def test_corrupt_record_is_refused(root):
    save(root)
    path_of(root).write_text("not json", encoding="utf-8")
    with pytest.raises(ephemeral.EphemeralError):
        ephemeral.load(root, "hs1")


def test_pending_is_capped(root):
    for index in range(ephemeral.MAX_PENDING_HANDSHAKES + 8):
        save(root, f"h{index:03d}")
    assert ephemeral.pending_count(root) == ephemeral.MAX_PENDING_HANDSHAKES


def test_prune_keeps_newest_records(root):
    for index in range(ephemeral.MAX_PENDING_HANDSHAKES + 5):
        save(root, f"h{index:03d}")
    pending = ephemeral.pending(root)
    cap = ephemeral.MAX_PENDING_HANDSHAKES
    assert len(pending) == cap
    assert "h000" not in pending  # oldest gone
    newest = cap + 4  # range(cap + 5) creates ids 0..cap+4
    assert f"h{newest:03d}" in pending  # newest kept
    assert len(set(pending)) == cap


def test_purge_all_clears_everything(root):
    for index in range(5):
        save(root, f"h{index}")
    assert ephemeral.purge_all(root) == 5
    assert ephemeral.pending_count(root) == 0


def test_handshake_id_is_sanitised_not_trusted(root):
    """An id containing path separators must not escape the directory."""
    ephemeral.save(root, "../../etc/passwd", x25519_secret=b"x" * 32,
                   mlkem_secret=b"m" * 32, peer_user="bob", peer_fp="f" * 64)
    files = list((root / "pqc-kv-messaging" / "ephemeral").glob("hs-*.json"))
    assert len(files) == 1
    assert "etc" not in str(files[0].parent)
