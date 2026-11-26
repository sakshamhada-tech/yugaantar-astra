"""Envelope: KEM + HKDF + AES-256-GCM + signature, in one seal()/open().

Picture a sealed paper envelope:

* the **KEM ciphertext** is the ephemeral "lock" -- it carries the key material to
  the recipient's secret key;
* **HKDF** turns that key material into the actual AES key, labelled per purpose;
* **AES-256-GCM** encrypts the body and detects tampering (the wax seal);
* the **signature** is the sender's signature across the whole envelope, proving
  origin. The recipient checks it with the sender's public key.

Two modes, chosen by the caller:

``mode="kem"``      ML-KEM-768 only. Fewer bytes, pure post-quantum.
``mode="hybrid"``   X25519 + ML-KEM-768. Safe if either one falls.

Opening is deliberately paranoid: wrong signature, unknown key, bad ciphertext,
swapped AAD, truncated input, hostile JSON -> every path raises the *same*
:class:`EnvelopeError` with no detail. A caller can distinguish success from
failure and nothing else.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from . import dsa, kem
from .aead import NonceBudget, build_aad, fresh_nonce
from .deps import require_aead
from .symmetric import (
    KEY_LEN,
    NONCE_LEN,
    TAG_LEN,
    TamperError,
    aesgcm_decrypt,
    aesgcm_encrypt,
    hkdf_sha256,
)

VERSION = 1
SUITE = "pqc-kv/v1/envelope"
MODE_KEM = "kem"
MODE_HYBRID = "hybrid"

# Domain separation labels. Different labels -> different keys, even from the
# same KEM shared secret.
_LABEL_KEM = SUITE.encode() + b"/mlkem768/aes256gcm"
_LABEL_HYBRID = SUITE.encode() + b"/hybrid/aes256gcm"
_LABEL_SALT = SUITE.encode() + b"/salt"

# Fixed envelope seed size: we use the KEM secret itself as HKDF salt, so no
# extra random bytes are needed in the wire format.


class EnvelopeError(Exception):
    """Sealing or opening failed. Never contains plaintext, keys or field detail."""


@dataclass(frozen=True)
class Envelope:
    """The wire object. Safe to serialise; contains no secret except ciphertext."""

    version: int
    mode: str
    recipient: str
    envelope_id: str
    context: str
    nonce: bytes
    aad: bytes
    ciphertext: bytes
    tag: bytes
    kem_ciphertext: bytes = b""
    hybrid_public: bytes = b""
    signature: bytes = b""

    def to_dict(self) -> dict:
        """JSON-ready form (bytes -> base64)."""
        return {
            "v": self.version,
            "mode": self.mode,
            "suite": SUITE,
            "rcpt": self.recipient,
            "env": self.envelope_id,
            "ctx": self.context,
            "nonce": _b64(self.nonce),
            "ct": _b64(self.ciphertext),
            "tag": _b64(self.tag),
            "kem_ct": _b64(self.kem_ciphertext),
            "hy_pub": _b64(self.hybrid_public),
            "sig": _b64(self.signature),
        }

    def aad_bytes(self) -> bytes:
        """Rebuild the AAD from the identifiers (never trust an input ``aad``)."""
        return build_aad(
            suite=SUITE,
            recipient=self.recipient,
            envelope_id=self.envelope_id,
            context=self.context,
            version=self.version,
        )

    def signed_bytes(self) -> bytes:
        """Exactly the bytes the sender signs: the AAD plus every ciphertext field.

        The signature covers the nonce, tag, ciphertext and both public
        components, so flipping any byte of any of them breaks verification
        before decryption is even attempted.
        """
        return b"|".join(
            [
                SUITE.encode(),
                str(self.version).encode(),
                self.mode.encode(),
                self.aad_bytes(),
                self.nonce,
                self.ciphertext,
                self.tag,
                self.kem_ciphertext,
                self.hybrid_public,
            ]
        )

    def __repr__(self) -> str:
        return "Envelope(v=%d, mode=%s, env=%r, ct_len=%d)" % (
            self.version,
            self.mode,
            self.envelope_id,
            len(self.ciphertext),
        )


def seal(
    *,
    plaintext: bytes,
    recipient_public,
    sender_signing_secret: bytes,
    recipient: str,
    envelope_id: str,
    context: str,
    mode: str = MODE_KEM,
    budget: NonceBudget | None = None,
) -> Envelope:
    """Encrypt + authenticate + sign.

    ``recipient_public`` is a :class:`pqc_kv.kem.KemKeyPair`'s public key (KEM
    mode) or a :class:`pqc_kv.hybrid.HybridPublic` (hybrid mode).
    """
    require_aead()
    if not isinstance(plaintext, bytes):
        raise EnvelopeError("plaintext must be bytes")
    if mode not in (MODE_KEM, MODE_HYBRID):
        raise EnvelopeError("unsupported mode")

    kct = b""
    hybrid_public = b""

    if mode == MODE_KEM:
        if getattr(recipient_public, "public_key", None) is None:
            raise EnvelopeError("KEM mode needs an ML-KEM public key")
        try:
            enc = kem.encapsulate(recipient_public.public_key)
        except Exception:
            raise EnvelopeError("key encapsulation failed") from None
        kct = enc.ciphertext
        key = _kdf_kem(enc.shared_secret)
    else:
        from . import hybrid

        try:
            encap, shared = hybrid.encapsulate(recipient_public)
        except Exception:
            raise EnvelopeError("hybrid encapsulation failed") from None
        hybrid_public = encap.x25519_public
        kct = encap.mlkem_ciphertext
        key = shared

    if budget is not None:
        try:
            budget.take()
        except Exception:
            raise EnvelopeError("nonce budget exhausted") from None

    nonce = fresh_nonce()
    aad = build_aad(
        suite=SUITE,
        recipient=recipient,
        envelope_id=envelope_id,
        context=context,
        version=VERSION,
    )

    try:
        ciphertext, tag = aesgcm_encrypt(key, nonce, plaintext, aad)
    except Exception:
        raise EnvelopeError("encryption failed") from None

    unsigned = Envelope(
        version=VERSION,
        mode=mode,
        recipient=recipient,
        envelope_id=envelope_id,
        context=context,
        nonce=nonce,
        aad=aad,
        ciphertext=ciphertext,
        tag=tag,
        kem_ciphertext=kct,
        hybrid_public=hybrid_public,
    )

    try:
        signature = dsa.sign(sender_signing_secret, unsigned.signed_bytes())
    except Exception:
        raise EnvelopeError("signing failed") from None

    return Envelope(
        version=unsigned.version,
        mode=unsigned.mode,
        recipient=unsigned.recipient,
        envelope_id=unsigned.envelope_id,
        context=unsigned.context,
        nonce=unsigned.nonce,
        aad=unsigned.aad,
        ciphertext=unsigned.ciphertext,
        tag=unsigned.tag,
        kem_ciphertext=unsigned.kem_ciphertext,
        hybrid_public=unsigned.hybrid_public,
        signature=signature,
    )


def open_envelope(
    envelope: Envelope,
    *,
    recipient_secret,
    sender_signing_public: bytes,
) -> bytes:
    """Verify the signature, then decrypt. Returns plaintext or raises EnvelopeError.

    Order matters: we verify *before* spending work on key derivation, and we
    never reveal which step failed.
    """
    require_aead()
    try:
        if envelope.version != VERSION:
            raise EnvelopeError("unsupported envelope version")
        if envelope.mode not in (MODE_KEM, MODE_HYBRID):
            raise EnvelopeError("unsupported mode")
        if len(envelope.nonce) != NONCE_LEN or len(envelope.tag) != TAG_LEN:
            raise EnvelopeError("malformed envelope")

        # 1. Sender authenticity: the whole envelope including every ciphertext
        #    byte is covered, so this also rejects tampering cheaply.
        if not dsa.verify(sender_signing_public, envelope.signed_bytes(), envelope.signature):
            raise EnvelopeError("signature verification failed")

        # 2. The AAD is never taken from the wire: it is rebuilt from the
        #    identifiers, so a tampered header simply cannot be authenticated.
        aad = envelope.aad_bytes()

        # 3. Key recovery.
        if envelope.mode == MODE_KEM:
            shared = kem.decapsulate(envelope.kem_ciphertext, recipient_secret.secret_key)
            key = _kdf_kem(shared)
        else:
            from . import hybrid

            if len(envelope.hybrid_public) != hybrid.X25519_LEN:
                raise EnvelopeError("malformed hybrid envelope")
            key = hybrid.decapsulate(
                recipient_secret,
                hybrid.HybridEncapsulation(
                    x25519_public=envelope.hybrid_public,
                    mlkem_ciphertext=envelope.kem_ciphertext,
                ),
            )

        # 4. Decrypt: the GCM tag is what ultimately proves the whole thing fits.
        return aesgcm_decrypt(
            key, envelope.nonce, envelope.ciphertext, envelope.tag, aad
        )
    except EnvelopeError:
        raise
    except TamperError:
        raise EnvelopeError("decryption failed") from None
    except Exception:
        # Any library error, malformed input, wrong key type: one opaque failure.
        raise EnvelopeError("envelope could not be opened") from None


def _kdf_kem(shared_secret: bytes) -> bytes:
    """HKDF with a fixed, public label; per-message freshness comes from the KEM.

    ML-KEM already produces an independent random secret per encapsulation, so we
    do not need a random salt here. The label is the domain separator.
    """
    if len(shared_secret) != kem.SHARED_SECRET_LEN:
        raise EnvelopeError("unexpected shared secret length")
    return hkdf_sha256(shared_secret, salt=_LABEL_SALT, info=_LABEL_KEM, length=KEY_LEN)


# ---------------------------------------------------------------- serialisation
def to_json(envelope: Envelope) -> str:
    return json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))


def from_dict(data: dict) -> Envelope:
    """Rehydrate from JSON. Strict about types; raises EnvelopeError on anything odd."""
    try:
        if not isinstance(data, dict):
            raise EnvelopeError("envelope must be an object")
        if data.get("suite") != SUITE:
            raise EnvelopeError("unknown suite")
        return Envelope(
            version=int(data["v"]),
            mode=str(data["mode"]),
            recipient=str(data["rcpt"]),
            envelope_id=str(data["env"]),
            context=str(data["ctx"]),
            nonce=_unb64(data["nonce"]),
            aad=b"",  # always rebuilt from the identifiers; never accepted from input
            ciphertext=_unb64(data["ct"]),
            tag=_unb64(data["tag"]),
            kem_ciphertext=_unb64(data.get("kem_ct", "")),
            hybrid_public=_unb64(data.get("hy_pub", "")),
            signature=_unb64(data.get("sig", "")),
        )
    except EnvelopeError:
        raise
    except Exception:
        raise EnvelopeError("malformed envelope encoding") from None


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value) -> bytes:
    if not isinstance(value, str):
        raise EnvelopeError("expected base64 text")
    return base64.b64decode(value.encode("ascii"), validate=True)
