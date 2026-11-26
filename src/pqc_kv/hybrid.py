"""Hybrid key agreement: X25519 + ML-KEM-768, combined through HKDF.

Why bother: today X25519 (classical) is battle-tested and ML-KEM (post-quantum) is
new. An attacker has to break **both** to learn the shared secret:

* a classical attacker breaks X25519  -> ML-KEM still protects you;
* a future quantum attacker breaks ML-KEM -> X25519 still protects you;
* a bad parameter choice or implementation bug in one of them alone does not
  sink the whole key.

The combined key is HKDF over (transcript || X25519 secret || ML-KEM secret), and
the KEM component is length-prefixed before mixing. Removing, swapping or editing
either component therefore changes the final key -- that is what
``tests/test_hybrid.py`` asserts.

Transcript binding: the context string commits to both transmitted public values
in a fixed order. If an attacker substitutes their own X25519 public key or KEM
ciphertext, the transcript changes on one side only, so the derived keys differ
and the envelope's AES-GCM tag fails.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import kem
from .deps import BACKEND, Unavailable
from .symmetric import KEY_LEN, hkdf_sha256

HYBRID_CONTEXT = b"pqc-kv/v1/hybrid-x25519-mlkem768"
X25519_LEN = 32


class HybridError(Exception):
    """Hybrid agreement failed. Never includes secret material."""


@dataclass(frozen=True)
class HybridPublic:
    x25519_public: bytes
    mlkem_public: bytes

    def __repr__(self) -> str:
        return "HybridPublic(x25519_len=%d, mlkem_len=%d)" % (
            len(self.x25519_public),
            len(self.mlkem_public),
        )


@dataclass(frozen=True)
class HybridKeyPair(HybridPublic):
    """Key pair. Secret fields are hidden from repr/str on purpose."""

    x25519_secret: bytes = b""
    mlkem_secret: bytes = b""

    def __repr__(self) -> str:
        return "HybridKeyPair(x25519_public_len=%d, mlkem_public_len=%d, secret=<redacted>)" % (
            len(self.x25519_public),
            len(self.mlkem_public),
        )

    __str__ = __repr__


@dataclass(frozen=True)
class HybridEncapsulation:
    """What the sender transmits. The KEM field is a ciphertext, not a public key."""

    x25519_public: bytes
    mlkem_ciphertext: bytes

    def __repr__(self) -> str:
        return "HybridEncapsulation(x25519_len=%d, mlkem_ct_len=%d)" % (
            len(self.x25519_public),
            len(self.mlkem_ciphertext),
        )


def _x25519_backend():
    if BACKEND.symmetric == "cryptography":
        from cryptography.hazmat.primitives.asymmetric import x25519

        return "cryptography", x25519
    if BACKEND.symmetric == "pycryptodome":
        from Crypto.PublicKey import ECC

        return "pycryptodome", ECC
    raise Unavailable("No vetted X25519 backend (cryptography or pycryptodome) is installed.")


def _xp_new():
    """Fresh X25519 key pair -> (secret_hint, public_bytes)."""
    family, mod = _x25519_backend()
    if family == "cryptography":
        priv = mod.X25519PrivateKey.generate()
        return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()
    priv = mod.generate(curve="Curve25519")
    return (
        priv.export_key(format="PEM").encode("utf-8"),
        int(priv.pointQ.x).to_bytes(X25519_LEN, "little"),
    )


def _x25519_agree(secret: bytes, peer_public: bytes) -> bytes:
    family, mod = _x25519_backend()
    if not isinstance(peer_public, (bytes, bytearray)) or len(peer_public) != X25519_LEN:
        raise HybridError("X25519 public key must be 32 bytes")
    if bytes(peer_public) == b"\x00" * X25519_LEN:
        # Low-order point: the contribution is predictable. Refuse it.
        raise HybridError("refusing low-order X25519 public key")

    try:
        if family == "cryptography":
            priv = mod.X25519PrivateKey.from_private_bytes(secret)
            shared = priv.exchange(mod.X25519PublicKey.from_public_bytes(bytes(peer_public)))
        else:
            from Crypto.Protocol.DH import key_agreement

            priv = mod.import_key(secret.decode("utf-8"))
            peer = mod.construct(curve="Curve25519", point_x=int.from_bytes(bytes(peer_public), "little"))
            shared = key_agreement(static_priv=priv, static_pub=peer, kdf=lambda x: x)
    except HybridError:
        raise
    except Exception:
        raise HybridError("X25519 agreement failed") from None

    if shared == b"\x00" * X25519_LEN:
        raise HybridError("refusing all-zero X25519 shared secret")
    return shared


def generate_keypair() -> HybridKeyPair:
    x_secret, x_public = _xp_new()
    pq = kem.generate_keypair()
    return HybridKeyPair(
        x25519_public=x_public,
        mlkem_public=pq.public_key,
        x25519_secret=x_secret,
        mlkem_secret=pq.secret_key,
    )


def public_of(pair: HybridKeyPair) -> HybridPublic:
    return HybridPublic(x25519_public=pair.x25519_public, mlkem_public=pair.mlkem_public)


def encapsulate(recipient: HybridPublic) -> tuple[HybridEncapsulation, bytes]:
    """Sender side. Returns the public components to send, plus the 32-byte key."""
    ephemeral_secret, ephemeral_public = _xp_new()
    pq = kem.encapsulate(recipient.mlkem_public)
    transcript = build_transcript(ephemeral_public, pq.ciphertext)

    x_shared = _x25519_agree(ephemeral_secret, recipient.x25519_public)
    key = derive_key(x_shared, pq.shared_secret, transcript)
    return HybridEncapsulation(x25519_public=ephemeral_public, mlkem_ciphertext=pq.ciphertext), key


def decapsulate(recipient: HybridKeyPair, encapsulation: HybridEncapsulation) -> bytes:
    """Recipient side. Raises :class:`HybridError` on any invalid input."""
    transcript = build_transcript(
        encapsulation.x25519_public, encapsulation.mlkem_ciphertext
    )
    pq_shared = kem.decapsulate(encapsulation.mlkem_ciphertext, recipient.mlkem_secret)
    x_shared = _x25519_agree(recipient.x25519_secret, encapsulation.x25519_public)
    return derive_key(x_shared, pq_shared, transcript)


def build_transcript(x25519_public: bytes, mlkem_ciphertext: bytes) -> bytes:
    return (
        HYBRID_CONTEXT
        + b"|x25519:"
        + bytes(x25519_public)
        + b"|mlkem-ct:"
        + bytes(mlkem_ciphertext)
    )


def derive_key(x_shared: bytes, pq_shared: bytes, transcript: bytes) -> bytes:
    """Mix both component secrets into one key. Either one changing changes output."""
    if not x_shared or not pq_shared:
        raise HybridError("both hybrid components are required")
    ikm = (
        transcript
        + b"|x25519:"
        + x_shared
        + b"|mlkem(len=%d):" % len(pq_shared)
        + pq_shared
    )
    salt = hkdf_sha256(transcript, salt=b"", info=HYBRID_CONTEXT + b"/salt", length=32)
    return hkdf_sha256(ikm, salt=salt, info=HYBRID_CONTEXT + b"/key", length=KEY_LEN)
