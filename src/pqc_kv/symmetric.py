"""Symmetric primitives (HKDF-SHA256, AES-256-GCM) behind one vetted abstraction.

Nothing here is a hand-rolled cipher. Both backends below are audited libraries;
this module only normalises their small API differences so the rest of the code
has one shape to call.

What each piece is for, in plain language:

* **HKDF-SHA256**: takes one shared secret of uneven quality and stretches it into
  named, independent keys. The ``info``/context label means the *same* secret can
  produce a different key for a different purpose ("this key is only for asset
  bodies"), so a key leaking in one context does not automatically open another.
* **AES-256-GCM**: authenticated encryption. It keeps the data secret *and*
  detects tampering. The AAD (associated data) is not encrypted but is bound to
  the ciphertext: change it and decryption fails.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .deps import BACKEND, Unavailable, require_aead

KEY_LEN = 32  # AES-256 and HKDF output length
NONCE_LEN = 12  # 96-bit GCM nonce, the size GCM is designed for
TAG_LEN = 16


class TamperError(Exception):
    """Authentication failed: ciphertext, tag, nonce or AAD was altered.

    Deliberately carries no detail about *which* check failed, so callers cannot
    use error messages as an oracle.
    """


@dataclass(frozen=True)
class Sealed:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def hkdf_sha256(
    ikm: bytes,
    *,
    salt: bytes,
    info: bytes,
    length: int = KEY_LEN,
) -> bytes:
    """RFC 5869 HKDF with SHA-256.

    ``salt`` should be a fresh random value (or a stored random per-context salt).
    ``info`` is our context label; it must differ per purpose.
    """
    if not isinstance(ikm, (bytes, bytearray)) or not ikm:
        raise ValueError("ikm must be non-empty bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise ValueError("salt must be bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise ValueError("info must be bytes")
    if length <= 0 or length > 255 * 32:
        raise ValueError("invalid HKDF output length")

    if BACKEND.symmetric == "cryptography":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        return HKDF(
            algorithm=hashes.SHA256(), length=length, salt=bytes(salt), info=bytes(info)
        ).derive(bytes(ikm))

    if BACKEND.symmetric == "pycryptodome":
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import HKDF

        return HKDF(
            master=bytes(ikm),
            key_len=length,
            salt=bytes(salt),
            hashmod=SHA256,
            context=bytes(info),
            num_keys=1,
        )

    # No third-party backend: RFC 5869 in the standard library. This is a
    # composition of hash and HMAC (both stdlib, both constant-time in CPython's
    # C implementation), not a new primitive. Verified against both libraries in
    # tests/test_hkdf_backends.py.
    return _hkdf_sha256_stdlib(bytes(ikm), bytes(salt), bytes(info), length)


def _hkdf_sha256_stdlib(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def aesgcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, tag)``. Caller owns nonce generation (see aead.py)."""
    require_aead()
    _check_key(key)
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    if not isinstance(aad, bytes):
        raise ValueError("aad must be bytes")

    if BACKEND.symmetric == "cryptography":
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        combined = AESGCM(key).encrypt(nonce, plaintext, aad)
        return combined[:-TAG_LEN], combined[-TAG_LEN:]

    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def aesgcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes
) -> bytes:
    """Return plaintext, or raise :class:`TamperError` with no extra detail."""
    require_aead()
    _check_key(key)
    # On the *decrypt* path all of this is untrusted input, so a wrong length is
    # tampering, not a programming error: same opaque failure as a bad tag.
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
        raise TamperError("authentication failed")
    if not isinstance(tag, (bytes, bytearray)) or len(tag) != TAG_LEN:
        raise TamperError("authentication failed")
    if not isinstance(aad, (bytes, bytearray)):
        raise TamperError("authentication failed")

    try:
        if BACKEND.symmetric == "cryptography":
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            try:
                return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
            except InvalidTag:
                raise TamperError("authentication failed") from None

        from Crypto.Cipher import AES

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        cipher.update(aad)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise TamperError("authentication failed") from None
    except (ValueError, TypeError):
        # Malformed lengths / impossible inputs are tampering from the caller's
        # point of view. Collapse them so we never leak structure.
        raise TamperError("authentication failed") from None


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes")


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison, used for MAC/proof checks."""
    return hmac.compare_digest(a, b)


__all__ = [
    "KEY_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "Sealed",
    "TamperError",
    "aesgcm_decrypt",
    "aesgcm_encrypt",
    "constant_time_equal",
    "hkdf_sha256",
    "Unavailable",
]
