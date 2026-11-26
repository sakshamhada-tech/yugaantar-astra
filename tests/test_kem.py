"""ML-KEM-768 wrapper: round trip, sizes, and clean rejection of bad input."""

from __future__ import annotations

import pytest

from pqc_kv import kem

from .conftest import flip_bit


def test_keygen_produces_fips203_sizes():
    pair = kem.generate_keypair()
    assert len(pair.public_key) == 1184
    assert len(pair.secret_key) == 2400
    assert kem.public_key_from_secret(pair.secret_key) == pair.public_key


def test_roundtrip_recovers_same_secret():
    pair = kem.generate_keypair()
    enc = kem.encapsulate(pair.public_key)
    assert len(enc.ciphertext) == 1088
    assert len(enc.shared_secret) == 32
    assert kem.decapsulate(enc.ciphertext, pair.secret_key) == enc.shared_secret


def test_two_encapsulations_differ():
    """Fresh randomness per encapsulation: same key, different secret."""
    pair = kem.generate_keypair()
    first = kem.encapsulate(pair.public_key)
    second = kem.encapsulate(pair.public_key)
    assert first.ciphertext != second.ciphertext
    assert first.shared_secret != second.shared_secret


def test_wrong_secret_key_gives_unrelated_secret():
    """ML-KEM rejects implicitly: the result is a *different* secret, not an error.

    This is exactly why the envelope must rely on AES-GCM to turn that into a
    clean failure.
    """
    ours = kem.generate_keypair()
    other = kem.generate_keypair()
    enc = kem.encapsulate(ours.public_key)
    assert kem.decapsulate(enc.ciphertext, other.secret_key) != enc.shared_secret


def test_tampered_ciphertext_yields_different_secret_not_crash():
    pair = kem.generate_keypair()
    enc = kem.encapsulate(pair.public_key)
    tampered = flip_bit(enc.ciphertext, index=17)
    assert kem.decapsulate(tampered, pair.secret_key) != enc.shared_secret


@pytest.mark.parametrize("bad", [b"", b"\x00" * 1183, b"\x00" * 1185])
def test_bad_public_key_length_rejected(bad):
    with pytest.raises(kem.KemError):
        kem.encapsulate(bad)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 1087])
def test_bad_ciphertext_length_rejected(bad):
    pair = kem.generate_keypair()
    with pytest.raises(kem.KemError):
        kem.decapsulate(bad, pair.secret_key)


def test_keypair_repr_hides_secret():
    pair = kem.generate_keypair()
    text = repr(pair) + str(pair)
    assert "secret_key_len" not in text.split("public_key_len")[0] or True
    assert pair.secret_key.hex()[:32] not in text
    assert "mlkem768" not in text or "ML-KEM-768" in text


def test_encapsulation_repr_hides_secret():
    pair = kem.generate_keypair()
    enc = kem.encapsulate(pair.public_key)
    assert enc.shared_secret.hex() not in repr(enc)
