"""Dependency gate: we must know, at runtime, which vetted backend is live."""

from __future__ import annotations

import pytest

from pqc_kv import deps, symmetric


def test_a_backend_was_detected():
    assert deps.BACKEND.symmetric in ("cryptography", "pycryptodome")
    assert deps.BACKEND.pqcrypto is not None


def test_capabilities_report_is_json_friendly():
    report = deps.BACKEND.describe()
    assert set(report) == {"symmetric", "aead", "x25519", "pqcrypto"}
    assert report["aead"] is True


def test_require_aead_raises_when_no_backend(monkeypatch):
    monkeypatch.setattr(deps, "BACKEND", deps.Backend(symmetric="none", pqcrypto="0.4.0"))
    with pytest.raises(deps.Unavailable):
        deps.require_aead()


def test_stdlib_hkdf_available_without_third_party(monkeypatch):
    """HKDF keeps working with no libraries: it is a hash/HMAC composition."""
    monkeypatch.setattr(deps, "BACKEND", deps.Backend(symmetric="none", pqcrypto=None))
    assert len(symmetric.hkdf_sha256(b"secret", salt=b"s", info=b"i")) == 32


def test_aead_refuses_to_invent_a_cipher(monkeypatch):
    monkeypatch.setattr(deps, "BACKEND", deps.Backend(symmetric="none", pqcrypto=None))
    with pytest.raises(deps.Unavailable):
        symmetric.aesgcm_encrypt(b"k" * 32, b"n" * 12, b"body", b"aad")
