"""ML-DSA-65 wrapper: sign/verify round trip, and verify() never raises."""

from __future__ import annotations

import pytest

from pqc_kv import dsa

from .conftest import flip_bit


def test_keygen_produces_fips204_sizes():
    pair = dsa.generate_keypair()
    assert len(pair.public_key) == 1952
    assert len(pair.secret_key) == 4032


def test_sign_verify_roundtrip():
    pair = dsa.generate_keypair()
    message = b"asset:brief|v1"
    signature = dsa.sign(pair.secret_key, message)
    assert len(signature) == 3309
    assert dsa.verify(pair.public_key, message, signature) is True


def test_flipped_message_fails():
    pair = dsa.generate_keypair()
    signature = dsa.sign(pair.secret_key, b"pay alice 10")
    assert dsa.verify(pair.public_key, b"pay alice 11", signature) is False


@pytest.mark.parametrize("index", [0, 1, 100, 3308])
def test_flipped_signature_bit_fails(index):
    pair = dsa.generate_keypair()
    signature = dsa.sign(pair.secret_key, b"hello")
    assert dsa.verify(pair.public_key, b"hello", flip_bit(signature, index)) is False


def test_wrong_sender_public_key_fails():
    alice = dsa.generate_keypair()
    mallory = dsa.generate_keypair()
    signature = dsa.sign(alice.secret_key, b"trust me")
    assert dsa.verify(mallory.public_key, b"trust me", signature) is False


@pytest.mark.parametrize(
    "public_key,signature",
    [
        (b"", b""),
        (b"\x00" * 1952, b"\x00" * 3309),
        (b"short", b"short"),
        (None, None),
    ],
)
def test_verify_returns_false_instead_of_raising(public_key, signature):
    """A verifier fed hostile input must answer 'no', not explode."""
    assert dsa.verify(public_key, b"msg", signature) is False


def test_sign_with_malformed_secret_key_raises_clean_error():
    with pytest.raises(dsa.SignError):
        dsa.sign(b"too short", b"msg")


def test_repr_hides_secret():
    pair = dsa.generate_keypair()
    assert pair.secret_key.hex()[:32] not in repr(pair)
    assert pair.secret_key.hex()[:32] not in str(pair)
