"""The directory is the trust anchor; its limits must be visible, not hidden."""

from __future__ import annotations

import pytest

from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import identity
from pqc_kv.messaging.directory import Directory, DirectoryError


@pytest.fixture()
def dirs(tmp_path):
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    directory = Directory(tmp_path / "state")
    directory.add(alice.public)
    directory.add(bob.public)
    return directory, alice, bob


def test_lookup_returns_the_right_identity(dirs):
    directory, alice, bob = dirs
    assert directory.lookup("alice").fingerprint == alice.fingerprint
    assert directory.lookup("bob").fingerprint == bob.fingerprint


def test_unknown_user_is_refused_not_guessed(dirs):
    directory, _, _ = dirs
    with pytest.raises(DirectoryError):
        directory.lookup("mallory")
    with pytest.raises(DirectoryError):
        directory.lookup("Alice")  # no case folding


def test_lookup_is_exact_match_only(dirs):
    directory, _, _ = dirs
    assert directory.contains("alice") is True
    assert directory.contains("alice ") is False
    assert directory.contains("ali") is False


def test_tampered_public_key_is_detected(dirs, tmp_path):
    """Editing a key without editing the fingerprint must fail closed."""
    directory, alice, _ = dirs
    data = directory._load()
    record = dict(data["entries"]["alice"])
    record["kem_public"] = identity.generate(KeyStore(tmp_path / "other"), "x").public.to_dict()["kem_public"]
    data["entries"]["alice"] = record
    directory.path.write_text(__import__("json").dumps(data), encoding="utf-8")
    with pytest.raises(DirectoryError):
        directory.lookup("alice")


def test_directory_digest_changes_when_an_entry_changes(dirs, tmp_path):
    directory, _, _ = dirs
    before = directory.fingerprint()
    directory.add(identity.generate(KeyStore(tmp_path / "third"), "carol").public)
    assert directory.fingerprint() != before


def test_directory_digest_is_stable_when_nothing_changes(dirs):
    directory, _, _ = dirs
    assert directory.fingerprint() == directory.fingerprint()


def test_remove_and_list(dirs):
    directory, _, _ = dirs
    assert directory.known_users() == ["alice", "bob"]
    directory.remove("bob")
    assert directory.known_users() == ["alice"]
    with pytest.raises(DirectoryError):
        directory.lookup("bob")


def test_directory_file_is_private(dirs):
    import stat

    directory, _, _ = dirs
    assert stat.S_IMODE(directory.path.stat().st_mode) == 0o600


def test_replace_is_supported_for_rotation(dirs, tmp_path):
    directory, _, _ = dirs
    replacement = identity.generate(KeyStore(tmp_path / "rot"), "alice")
    directory.add(replacement.public)
    assert directory.lookup("alice").fingerprint == replacement.fingerprint
