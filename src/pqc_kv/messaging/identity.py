"""Long-term identities and fingerprints.

An identity is two key pairs:

    ML-DSA-65   long-term signing key   -- proves "this is me"
    ML-KEM-768  long-term recipient key -- not used for session keys (the session
                                           uses ephemerals); used as the stable
                                           addressable anchor and for key
                                           confirmation in the handshake

A **fingerprint** is SHA-256 over a domain-separated, length-prefixed encoding of
*both* public keys. Length prefixes matter: without them, ``(aa, bbcc)`` and
``(aabb, cc)`` hash identically, which would let an attacker craft a second key
set with the same fingerprint (a collision they control, not a hash break).

Why fingerprints at all: raw public keys are 3 KB of base64, unusable for humans
and awkward in logs. A 256-bit fingerprint is safe to show, compare and log --
and it is derived, not secret.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .. import dsa, kem
from ..keystore import KeyStore, b64d, b64e

FINGERPRINT_CONTEXT = b"pqc-kv/v2/identity-fingerprint"
FINGERPRINT_LEN = 32  # bytes -> 64 hex chars


class IdentityError(Exception):
    """Identity problem. Messages never contain key material."""


@dataclass(frozen=True)
class PublicIdentity:
    """What you need to talk to someone. Public only -- safe to persist and log."""

    user_id: str
    signing_public: bytes
    kem_public: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.user_id, str) or not self.user_id:
            raise IdentityError("user id must be a non-empty string")
        if len(self.signing_public) != dsa.PUBLIC_KEY_LEN:
            raise IdentityError("malformed ML-DSA-65 public key")
        if len(self.kem_public) != kem.PUBLIC_KEY_LEN:
            raise IdentityError("malformed ML-KEM-768 public key")

    @property
    def fingerprint(self) -> str:
        """128-bit-truncated? No: full 256-bit hex. Cheap, and no reason to truncate."""
        return fingerprint_of(self.signing_public, self.kem_public)

    def __repr__(self) -> str:
        return f"PublicIdentity(user_id={self.user_id!r}, fp={self.fingerprint[:16]}…)"

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "signing_public": b64e(self.signing_public),
            "kem_public": b64e(self.kem_public),
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PublicIdentity":
        try:
            identity = cls(
                user_id=str(data["user_id"]),
                signing_public=b64d(data["signing_public"]),
                kem_public=b64d(data["kem_public"]),
            )
        except KeyError:
            raise IdentityError("malformed identity record") from None
        # If the record carries a fingerprint, it must agree with the keys.
        claimed = data.get("fingerprint")
        if claimed is not None and claimed != identity.fingerprint:
            raise IdentityError("identity fingerprint does not match its keys")
        return identity


@dataclass(frozen=True)
class PrivateIdentity:
    """A local identity: public half plus the long-term secrets.

    ``repr`` never includes secrets; the dataclass fields are excluded from it by
    the custom methods below.
    """

    public: PublicIdentity
    signing_secret: bytes
    kem_secret: bytes

    @property
    def user_id(self) -> str:
        return self.public.user_id

    @property
    def fingerprint(self) -> str:
        return self.public.fingerprint

    def __repr__(self) -> str:
        return f"PrivateIdentity(user_id={self.user_id!r}, fp={self.fingerprint[:16]}…, secret=<redacted>)"

    __str__ = __repr__

    def sign(self, message: bytes) -> bytes:
        return dsa.sign(self.signing_secret, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return dsa.verify(self.public.signing_public, message, signature)


def fingerprint_of(signing_public: bytes, kem_public: bytes) -> str:
    """SHA-256 over domain label + length-prefixed public keys, lowercase hex."""
    hasher = hashlib.sha256()
    hasher.update(FINGERPRINT_CONTEXT)
    for blob in (signing_public, kem_public):
        hasher.update(len(blob).to_bytes(4, "big"))
        hasher.update(blob)
    return hasher.hexdigest()


def generate(store: KeyStore, user_id: str) -> PrivateIdentity:
    """Create (or reload) the long-term identity for ``user_id``.

    Key material goes through the Phase 1 keystore, so files are 0600 in a 0700
    directory and written atomically. Nothing here invents storage.
    """
    if not isinstance(user_id, str) or not user_id:
        raise IdentityError("user id must be a non-empty string")
    signing = store.signing_keypair(f"identity-sign-{user_id}")
    recipient = store.kem_keypair(f"identity-kem-{user_id}")
    public = PublicIdentity(
        user_id=user_id,
        signing_public=signing.public_key,
        kem_public=recipient.public_key,
    )
    return PrivateIdentity(
        public=public, signing_secret=signing.secret_key, kem_secret=recipient.secret_key
    )


def public_from_record(record: dict) -> PublicIdentity:
    return PublicIdentity.from_dict(record)
