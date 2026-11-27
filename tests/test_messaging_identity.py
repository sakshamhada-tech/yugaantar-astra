"""Identities and fingerprints: stable, unambiguous, secret-free."""

from __future__ import annotations

import pytest

from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import identity
from pqc_kv.messaging.identity import IdentityError, PublicIdentity


@pytest.fixture()
def store(tmp_path):
    return KeyStore(tmp_path / "keys")


def test_generate_produces_correct_key_sizes(store):
    who = identity.generate(store, "alice")
    assert len(who.public.signing_public) == 1952
    assert len(who.public.kem_public) == 1184
    assert len(who.fingerprint) == 64


def test_identity_is_stable_across_loads(store):
    first = identity.generate(store, "alice")
    second = identity.generate(store, "alice")
    assert first.fingerprint == second.fingerprint


def test_distinct_users_have_distinct_fingerprints(store):
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    assert alice.fingerprint != bob.fingerprint


def test_fingerprint_is_order_and_length_unambiguous():
    """Swapping a byte boundary must change the hash (length prefixes)."""
    key_a, key_b = b"a" * 4, b"b" * 6
    assert identity.fingerprint_of(key_a, key_b) != identity.fingerprint_of(
        key_a + b"bb", key_b[:4]
    )
    assert identity.fingerprint_of(b"aabb", b"cc") != identity.fingerprint_of(b"aa", b"bbcc")


def test_fingerprint_hex_is_lowercase_sha256(store):
    who = identity.generate(store, "alice")
    assert who.fingerprint == who.fingerprint.lower()
    assert all(c in "0123456789abcdef" for c in who.fingerprint)


def test_sign_and_verify(store):
    who = identity.generate(store, "alice")
    signature = who.sign(b"payload")
    assert who.verify(b"payload", signature) is True
    assert who.verify(b"payloaD", signature) is False


def test_repr_never_leaks_secrets(store):
    who = identity.generate(store, "alice")
    for text in (repr(who), str(who), repr(who.public), str(who.public)):
        assert who.signing_secret.hex()[:32] not in text
        assert who.kem_secret.hex()[:32] not in text
    assert "redacted" in repr(who)


def test_public_identity_round_trips_through_dict(store):
    who = identity.generate(store, "alice")
    revived = PublicIdentity.from_dict(who.public.to_dict())
    assert revived.fingerprint == who.fingerprint
    assert revived.user_id == "alice"


def test_public_identity_rejects_fingerprint_mismatch(store):
    alice = identity.generate(store, "alice")
    record = alice.public.to_dict()
    record["fingerprint"] = "0" * 64
    with pytest.raises(IdentityError):
        PublicIdentity.from_dict(record)


def test_public_identity_rejects_wrong_key_lengths():
    with pytest.raises(IdentityError):
        PublicIdentity(user_id="x", signing_public=b"short", kem_public=b"k" * 1184)
    with pytest.raises(IdentityError):
        PublicIdentity(user_id="", signing_public=b"s" * 1952, kem_public=b"k" * 1184)


def test_identity_files_are_private(store, tmp_path):
    import stat

    identity.generate(store, "alice")
    keys = tmp_path / "keys"
    assert stat.S_IMODE(keys.stat().st_mode) == 0o700
    for path in keys.glob("*.key"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
