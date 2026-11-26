"""ML-DSA-65 signatures, wrapped around ``pqcrypto``.

Plain-language model: a signature proves *who made* a message and that it has not
changed. You sign with your private key; anyone with your public key can verify.
Unlike a MAC, you do not need a shared secret to check it.

ML-DSA-65 is the NIST post-quantum signature standard (FIPS 204) at the
"medium" level. Public keys are 1952 bytes and signatures 3309 bytes.

Design rule from the brief: :func:`verify` NEVER raises on bad input. A truncated
signature, a wrong key, a flipped byte -- all return ``False``. That way a hostile
input cannot turn into an exception path that leaks timing or crashes the service.
"""

from __future__ import annotations

from dataclasses import dataclass

from .deps import require_pq

PARAMETER_SET = "ML-DSA-65"
PUBLIC_KEY_LEN = 1952
SECRET_KEY_LEN = 4032
SIGNATURE_LEN = 3309


class SignError(Exception):
    """Signing failed. Never includes key material."""


@dataclass(frozen=True)
class SigningKeyPair:
    public_key: bytes
    secret_key: bytes

    def __repr__(self) -> str:
        return f"SigningKeyPair(algorithm={PARAMETER_SET!r}, public_key_len={len(self.public_key)})"

    __str__ = __repr__


def _module():
    require_pq()
    from pqcrypto.sign import ml_dsa_65

    return ml_dsa_65


def generate_keypair() -> SigningKeyPair:
    public_key, secret_key = _module().generate_keypair()
    if len(public_key) != PUBLIC_KEY_LEN or len(secret_key) != SECRET_KEY_LEN:
        raise SignError("pqcrypto returned unexpected ML-DSA-65 key sizes")
    return SigningKeyPair(public_key=public_key, secret_key=secret_key)


def sign(secret_key: bytes, message: bytes) -> bytes:
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != SECRET_KEY_LEN:
        raise SignError("malformed ML-DSA-65 secret key")
    if not isinstance(message, (bytes, bytearray)):
        raise SignError("message must be bytes")
    try:
        signature = _module().sign(bytes(secret_key), bytes(message))
    except Exception:
        raise SignError("signing failed") from None
    if len(signature) != SIGNATURE_LEN:
        raise SignError("unexpected signature length")
    return signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True only for a valid signature. Never raises, never logs inputs."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_LEN:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_LEN:
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    try:
        return bool(_module().verify(bytes(public_key), bytes(message), bytes(signature)))
    except Exception:
        # pqcrypto raises on malformed input; a verifier must treat every failure
        # as "not verified" rather than an error.
        return False
