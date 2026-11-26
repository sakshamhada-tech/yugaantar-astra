"""HKDF-SHA256 must agree across backends and with RFC 5869 test vectors."""

from __future__ import annotations

import pytest

from pqc_kv import deps, symmetric


def _stdlib(ikm, salt, info, length):
    return symmetric._hkdf_sha256_stdlib(ikm, salt, info, length)


# RFC 5869 Appendix A.1 (SHA-256)
RFC5869_IKM = bytes.fromhex("0b" * 22)
RFC5869_SALT = bytes.fromhex("000102030405060708090a0b0c")
RFC5869_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
RFC5869_OKM = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


def test_rfc5869_vector_matches_stdlib_path():
    assert _stdlib(RFC5869_IKM, RFC5869_SALT, RFC5869_INFO, 42) == RFC5869_OKM


def test_rfc5869_vector_matches_active_backend():
    assert (
        symmetric.hkdf_sha256(RFC5869_IKM, salt=RFC5869_SALT, info=RFC5869_INFO, length=42)
        == RFC5869_OKM
    )


@pytest.mark.skipif(deps.BACKEND.symmetric != "pycryptodome", reason="needs pycryptodome")
def test_pycryptodome_matches_stdlib():
    args = (b"secret" * 8, b"salt" * 8, b"ctx/label", 64)
    assert symmetric.hkdf_sha256(args[0], salt=args[1], info=args[2], length=args[3]) == _stdlib(*args)


def test_context_label_changes_output():
    """Same secret, different label -> different key. The whole point of `info`."""
    a = symmetric.hkdf_sha256(b"x" * 32, salt=b"s" * 32, info=b"ctx/one")
    b = symmetric.hkdf_sha256(b"x" * 32, salt=b"s" * 32, info=b"ctx/two")
    assert a != b


def test_salt_changes_output():
    a = symmetric.hkdf_sha256(b"x" * 32, salt=b"s" * 32, info=b"ctx")
    b = symmetric.hkdf_sha256(b"x" * 32, salt=b"t" * 32, info=b"ctx")
    assert a != b


def test_rejects_empty_inputs_and_bad_length():
    with pytest.raises(ValueError):
        symmetric.hkdf_sha256(b"", salt=b"s" * 32, info=b"ctx")
    with pytest.raises(ValueError):
        symmetric.hkdf_sha256(b"x", salt=b"s", info=b"ctx", length=0)
