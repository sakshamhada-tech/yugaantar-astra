"""Hybrid X25519 + ML-KEM-768: the derived key must depend on BOTH secrets."""

from __future__ import annotations

import pytest

from pqc_kv import hybrid, kem

from .conftest import flip_bit


def test_roundtrip_both_sides_agree(hybrid_keys):
    encap, sender_key = hybrid.encapsulate(hybrid.public_of(hybrid_keys))
    assert hybrid.decapsulate(hybrid_keys, encap) == sender_key
    assert len(sender_key) == 32


def test_two_sessions_differ(hybrid_keys):
    public = hybrid.public_of(hybrid_keys)
    _, first = hybrid.encapsulate(public)
    _, second = hybrid.encapsulate(public)
    assert first != second


def test_changing_x25519_secret_changes_key(hybrid_keys):
    encap, sender_key = hybrid.encapsulate(hybrid.public_of(hybrid_keys))
    swapped = hybrid.HybridKeyPair(
        x25519_public=hybrid_keys.x25519_public,
        mlkem_public=hybrid_keys.mlkem_public,
        x25519_secret=hybrid.generate_keypair().x25519_secret,
        mlkem_secret=hybrid_keys.mlkem_secret,
    )
    wrong = hybrid.decapsulate(swapped, encap)
    assert wrong != sender_key


def test_changing_mlkem_secret_changes_key(hybrid_keys):
    encap, sender_key = hybrid.encapsulate(hybrid.public_of(hybrid_keys))
    swapped = hybrid.HybridKeyPair(
        x25519_public=hybrid_keys.x25519_public,
        mlkem_public=hybrid_keys.mlkem_public,
        x25519_secret=hybrid_keys.x25519_secret,
        mlkem_secret=kem.generate_keypair().secret_key,
    )
    wrong = hybrid.decapsulate(swapped, encap)
    assert wrong != sender_key


def test_derive_key_depends_on_either_component():
    """Direct unit check of the mixer: each input alone changes the output."""
    transcript = hybrid.build_transcript(b"x" * 32, b"c" * 1088)
    base = hybrid.derive_key(b"a" * 32, b"b" * 32, transcript)
    other_x = hybrid.derive_key(b"A" * 32, b"b" * 32, transcript)
    other_pq = hybrid.derive_key(b"a" * 32, b"B" * 32, transcript)
    other_tx = hybrid.derive_key(b"a" * 32, b"b" * 32, hybrid.build_transcript(b"y" * 32, b"c" * 1088))
    assert len({base, other_x, other_pq, other_tx}) == 4


def test_derive_key_rejects_missing_component():
    with pytest.raises(hybrid.HybridError):
        hybrid.derive_key(b"", b"b" * 32, b"t")
    with pytest.raises(hybrid.HybridError):
        hybrid.derive_key(b"a" * 32, b"", b"t")


def test_kem_component_is_length_prefixed():
    """Without length framing, ('a','bc') and ('ab','c') would collide."""
    t = b"transcript"
    a = hybrid.derive_key(b"a", b"bc", t)
    b = hybrid.derive_key(b"ab", b"c", t)
    assert a != b


@pytest.mark.parametrize("field", ["x25519_public", "mlkem_ciphertext"])
def test_tampered_encapsulation_yields_different_key(hybrid_keys, field):
    """Neither component errors on tampering; both yield a different key.

    X25519 accepts almost any 32-byte value as a point and ML-KEM rejects
    *implicitly*. So the hybrid layer's job is to produce a wrong key, and the
    envelope's AES-GCM tag is what converts that into a clean failure. Claiming
    otherwise would be dishonest -- the envelope test covers the actual rejection.
    """
    encap, sender_key = hybrid.encapsulate(hybrid.public_of(hybrid_keys))
    tampered = hybrid.HybridEncapsulation(
        x25519_public=flip_bit(encap.x25519_public) if field == "x25519_public" else encap.x25519_public,
        mlkem_ciphertext=flip_bit(encap.mlkem_ciphertext) if field == "mlkem_ciphertext" else encap.mlkem_ciphertext,
    )
    assert hybrid.decapsulate(hybrid_keys, tampered) != sender_key


def test_low_order_x25519_point_refused():
    """A zero public key would make the classical half contribute nothing."""
    pair = hybrid.generate_keypair()
    with pytest.raises(hybrid.HybridError):
        hybrid.decapsulate(
            pair,
            hybrid.HybridEncapsulation(
                x25519_public=b"\x00" * 32, mlkem_ciphertext=b"\x00" * 1088
            ),
        )


def test_wrong_length_x25519_key_refused():
    pair = hybrid.generate_keypair()
    with pytest.raises(hybrid.HybridError):
        hybrid.decapsulate(
            pair,
            hybrid.HybridEncapsulation(x25519_public=b"\x01" * 31, mlkem_ciphertext=b"\x00" * 1088),
        )


def test_repr_hides_secrets(hybrid_keys):
    assert hybrid_keys.x25519_secret.hex()[:16] not in repr(hybrid_keys)
    assert hybrid_keys.mlkem_secret.hex()[:16] not in repr(hybrid_keys)
    public = hybrid.public_of(hybrid_keys)
    assert "secret" not in repr(public)
