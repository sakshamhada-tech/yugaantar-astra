"""ML-KEM-768 key encapsulation, wrapped around ``pqcrypto``.

Plain-language model: a KEM lets two parties agree on a fresh random key
*without* that key ever travelling. The recipient publishes a public key. The
sender "encapsulates": gets (ciphertext, shared_secret). Only the holder of the
matching secret key can "decapsulate" the ciphertext back to the same secret.

ML-KEM-768 is the NIST post-quantum standard (FIPS 203) at the "medium" level:
128-bit classical / ~128-bit quantum-ish security, 1184-byte public keys.

The library is the only place primitives live. We add: type/length checks,
clean exceptions, and constant-time-safe usage patterns.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .deps import require_pq

PARAMETER_SET = "ML-KEM-768"
# Sizes are fixed by FIPS 203 for this parameter set. Kept as explicit constants
# so callers can validate untrusted input before handing it to the library.
PUBLIC_KEY_LEN = 1184
SECRET_KEY_LEN = 2400
CIPHERTEXT_LEN = 1088
SHARED_SECRET_LEN = 32


class KemError(Exception):
    """KEK operation failed. Never includes key material."""


@dataclass(frozen=True)
class KemKeyPair:
    public_key: bytes
    secret_key: bytes

    def __repr__(self) -> str:  # keep secret material out of logs/repr
        return f"KemKeyPair(algorithm={PARAMETER_SET!r}, public_key_len={len(self.public_key)})"

    __str__ = __repr__


@dataclass(frozen=True)
class Encapsulation:
    ciphertext: bytes
    shared_secret: bytes

    def __repr__(self) -> str:
        return f"Encapsulation(ciphertext_len={len(self.ciphertext)}, secret=<redacted>)"

    __str__ = __repr__


def _module():
    require_pq()
    from pqcrypto.kem import ml_kem_768

    return ml_kem_768


def generate_keypair() -> KemKeyPair:
    pk, sk = _module().generate_keypair()
    _sanity(pk, sk)
    return KemKeyPair(public_key=pk, secret_key=sk)


# FIPS 203 ML-KEM-768 decapsulation key layout (2400 bytes total):
#   dk_PKE (1152) || ek (1184) || H(ek) (32) || z (32)
# The public key therefore starts at byte 1152, NOT at byte 0. Getting this wrong
# is silent: you get 1184 plausible-looking bytes that are not the public key.
_PUBLIC_KEY_OFFSET = SECRET_KEY_LEN - PUBLIC_KEY_LEN - 64  # 1152


def public_key_from_secret(secret_key: bytes) -> bytes:
    """Recover the ML-KEM-768 public key embedded in its decapsulation key.

    Used only to avoid storing the public key twice. Never trust this for parsing
    keys from an untrusted source -- and note the offset constant above, which a
    regression test pins against a real keypair.
    """
    if len(secret_key) != SECRET_KEY_LEN:
        raise KemError("malformed ML-KEM-768 secret key")
    return secret_key[_PUBLIC_KEY_OFFSET : _PUBLIC_KEY_OFFSET + PUBLIC_KEY_LEN]


def encapsulate(public_key: bytes) -> Encapsulation:
    if not isinstance(public_key, (bytes, bytearray)):
        raise KemError("public key must be bytes")
    if len(public_key) != PUBLIC_KEY_LEN:
        raise KemError(f"ML-KEM-768 public key must be {PUBLIC_KEY_LEN} bytes")
    try:
        ciphertext, shared_secret = _module().encrypt(bytes(public_key))
    except Exception:  # library raises on malformed points
        raise KemError("encapsulation failed") from None
    if len(shared_secret) != SHARED_SECRET_LEN:
        raise KemError("unexpected shared secret length")
    return Encapsulation(ciphertext=ciphertext, shared_secret=shared_secret)


def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Return the shared secret or raise :class:`KemError`.

    ML-KEM is implicitly rejecting: a tampered ciphertext decapsulates to a
    *different*, unrelated secret rather than erroring. That is why the caller
    must never trust the result alone -- the AES-GCM tag in the envelope is what
    actually turns a wrong secret into a clean failure. We surface that property
    instead of pretending decapsulation detects tampering.
    """
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) != CIPHERTEXT_LEN:
        raise KemError(f"ML-KEM-768 ciphertext must be {CIPHERTEXT_LEN} bytes")
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != SECRET_KEY_LEN:
        raise KemError("malformed ML-KEM-768 secret key")
    try:
        shared_secret = _module().decrypt(bytes(secret_key), bytes(ciphertext))
    except Exception:
        raise KemError("decapsulation failed") from None
    if len(shared_secret) != SHARED_SECRET_LEN:
        raise KemError("unexpected shared secret length")
    return shared_secret


def _sanity(public_key: bytes, secret_key: bytes) -> None:
    if len(public_key) != PUBLIC_KEY_LEN or len(secret_key) != SECRET_KEY_LEN:
        raise KemError("pqcrypto returned unexpected ML-KEM-768 key sizes")


def _random_unused() -> bytes:  # pragma: no cover - documentation helper
    return os.urandom(SHARED_SECRET_LEN)
