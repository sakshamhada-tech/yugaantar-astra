"""Wire format: authenticated, fragmentable messages.

Everything an attacker could try to redirect is inside the *signed* header and is
also bound into the AEAD's associated data:

    protocol version | suite | session id | sender fp + user id |
    recipient fp + user id | message id | sequence | fragment index | fragment total

Why both signature and AAD? They answer different questions:

* the **AAD** makes the ciphertext refuse to decrypt if the header changed --
  cheap, and it is what stops "re-address this fragment to another user";
* the **signature** proves *which long-term identity* produced it, including for
  fragments the recipient cannot yet decrypt (out-of-order arrivals), and it lets
  a recipient reject an injected fragment before spending anything on decryption.

Each fragment is independently authenticated, so a fragment that arrives alone is
still verifiable and still sortable. Reassembly only ever hands back a message
when *every* fragment is present and every fragment's tag checked out.

Fragmentation exists because the transport can drop, duplicate, shuffle, corrupt
and truncate. A truncated fragment is indistinguishable from a corrupt one at the
transport layer, so both end up as "authentication failed" -- deliberately opaque.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from .. import dsa
from ..aead import MAX_MESSAGES_PER_KEY  # reuse the Phase 1 constant, not a new policy

PROTOCOL_VERSION = 2
SUITE = "pqc-kv/v2/messaging"
HEADER_CONTEXT = b"pqc-kv/v2/messaging-fragment-header"

MAX_FRAGMENTS = 65535  # index and total travel as 2-byte fields
DEFAULT_FRAGMENT_BYTES = 1024


class WireError(Exception):
    """Any malformed, unauthenticated or unmappable message. Deliberately opaque.

    Callers get a reason *code* for the audit log (see ``FailureReason``), never a
    field-level explanation that could help an attacker probe the format.
    """


class FailureReason:
    """Stable, non-sensitive reason codes. No plaintext, no key material."""

    INVALID_FORMAT = "invalid_format"
    UNKNOWN_SESSION = "unknown_session"
    WRONG_RECIPIENT = "wrong_recipient"
    WRONG_SENDER = "wrong_sender"
    SIGNATURE_INVALID = "signature_invalid"
    REPLAY = "replay"
    NONCE_REUSE = "nonce_reuse"
    STALE_SEQUENCE = "stale_sequence"
    KEY_UNAVAILABLE = "key_unavailable"
    DECRYPT_FAILED = "decrypt_failed"
    INCOMPLETE = "incomplete"
    TOO_MANY_FRAGMENTS = "too_many_fragments"
    BUDGET_EXHAUSTED = "budget_exhausted"
    POLICY_DENIED = "policy_denied"


@dataclass(frozen=True)
class Header:
    """The signed, authenticated, canonical header for one fragment."""

    version: int
    suite: str
    session_id: str
    sender_fp: str
    sender_user: str
    recipient_fp: str
    recipient_user: str
    message_id: str
    sequence: int
    fragment_index: int
    fragment_total: int

    def __post_init__(self) -> None:
        if self.version != PROTOCOL_VERSION:
            raise WireError("unsupported protocol version")
        if self.suite != SUITE:
            raise WireError("unknown suite")
        for name in ("sender_fp", "recipient_fp"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise WireError("malformed fingerprint")
        for name in ("session_id", "sender_user", "recipient_user", "message_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise WireError("malformed identifier")
            if len(value) > 256:
                raise WireError("identifier too long")
        if not isinstance(self.sequence, int) or self.sequence < 0:
            raise WireError("malformed sequence")
        if self.fragment_total < 1 or self.fragment_total > MAX_FRAGMENTS:
            raise WireError("malformed fragment total")
        if not (0 <= self.fragment_index < self.fragment_total):
            raise WireError("fragment index out of range")

    # -- canonical encodings ------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "suite": self.suite,
            "sid": self.session_id,
            "sfp": self.sender_fp,
            "su": self.sender_user,
            "rfp": self.recipient_fp,
            "ru": self.recipient_user,
            "mid": self.message_id,
            "seq": self.sequence,
            "fi": self.fragment_index,
            "ft": self.fragment_total,
        }

    def canonical(self) -> bytes:
        """Deterministic bytes for signing and for the AAD.

        JSON with sorted keys and no whitespace: both sides rebuild identical
        bytes. Field *names* are short but the values are length-unambiguous
        because JSON quoting makes each field self-delimiting.
        """
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_dict(cls, data: dict) -> "Header":
        try:
            return cls(
                version=int(data["v"]),
                suite=str(data["suite"]),
                session_id=str(data["sid"]),
                sender_fp=str(data["sfp"]),
                sender_user=str(data["su"]),
                recipient_fp=str(data["rfp"]),
                recipient_user=str(data["ru"]),
                message_id=str(data["mid"]),
                sequence=int(data["seq"]),
                fragment_index=int(data["fi"]),
                fragment_total=int(data["ft"]),
            )
        except WireError:
            raise
        except Exception:
            raise WireError("malformed header") from None


@dataclass(frozen=True)
class Fragment:
    """One authenticated piece of a message, as it travels on the wire."""

    header: Header
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    signature: bytes

    # -- what gets signed / authenticated ----------------------------------
    def signed_bytes(self) -> bytes:
        """Header + nonce + ciphertext + tag.

        Nonce and tag are included so a signature cannot be replayed onto a
        different ciphertext body with the same header.
        """
        return b"|".join(
            [
                HEADER_CONTEXT,
                self.header.canonical(),
                self.nonce,
                self.ciphertext,
                self.tag,
            ]
        )

    def aad(self) -> bytes:
        """Associated data for AES-GCM: the canonical header.

        Same bytes as the signature's header section, so a fragment cannot be
        re-addressed without breaking *both* checks.
        """
        return self.header.canonical()

    def __repr__(self) -> str:
        return (
            "Fragment(mid=%r, seq=%d, frag=%d/%d, ct_len=%d)"
            % (
                self.header.message_id,
                self.header.sequence,
                self.header.fragment_index + 1,
                self.header.fragment_total,
                len(self.ciphertext),
            )
        )

    # -- serialisation ------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "h": self.header.to_dict(),
            "n": _b64(self.nonce),
            "c": _b64(self.ciphertext),
            "t": _b64(self.tag),
            "s": _b64(self.signature),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Fragment":
        try:
            return cls(
                header=Header.from_dict(data["h"]),
                nonce=_unb64(data["n"]),
                ciphertext=_unb64(data["c"]),
                tag=_unb64(data["t"]),
                signature=_unb64(data["s"]),
            )
        except WireError:
            raise
        except Exception:
            raise WireError("malformed fragment") from None

    def verify_signature(self, signing_public: bytes) -> bool:
        return dsa.verify(signing_public, self.signed_bytes(), self.signature)


@dataclass(frozen=True)
class Message:
    """A reassembled, fully authenticated message body (plaintext)."""

    message_id: str
    sender_user: str
    sender_fp: str
    recipient_user: str
    recipient_fp: str
    sequence: int
    body: bytes
    fragment_count: int

    def __repr__(self) -> str:
        # Never put the body in a repr: logs must not carry plaintext.
        return (
            "Message(mid=%r, from=%r, to=%r, seq=%d, len=%d, fragments=%d)"
            % (
                self.message_id,
                self.sender_user,
                self.recipient_user,
                self.sequence,
                len(self.body),
                self.fragment_count,
            )
        )


def split(
    body: bytes,
    *,
    header_for: "callable",
    encrypt_fragment: "callable",
    sign_fragment: "callable",
    fragment_bytes: int = DEFAULT_FRAGMENT_BYTES,
) -> list[Fragment]:
    """Split a body into authenticated fragments.

    ``header_for(index, total, plaintext_slice)`` builds a header; the caller owns
    identity/session data. ``encrypt_fragment(header, slice)`` returns
    ``(nonce, ciphertext, tag)``; ``sign_fragment(fragment)`` returns the
    signature. Kept injectable so ``wire`` holds format logic only, no key state.
    """
    if not isinstance(body, bytes):
        raise WireError("body must be bytes")
    if fragment_bytes < 1 or fragment_bytes > MAX_FRAGMENTS * 4096:
        raise WireError("invalid fragment size")

    if not body:
        chunks = [b""]
    else:
        chunks = [body[i : i + fragment_bytes] for i in range(0, len(body), fragment_bytes)]
    total = len(chunks)
    if total > MAX_FRAGMENTS:
        raise WireError("message requires too many fragments")

    fragments: list[Fragment] = []
    for index, chunk in enumerate(chunks):
        header = header_for(index, total, chunk)
        nonce, ciphertext, tag = encrypt_fragment(header, chunk)
        unsigned = Fragment(header=header, nonce=nonce, ciphertext=ciphertext, tag=tag, signature=b"")
        signature = sign_fragment(unsigned)
        fragments.append(
            Fragment(
                header=header, nonce=nonce, ciphertext=ciphertext, tag=tag, signature=signature
            )
        )
    return fragments


def message_digest(fragments: list[Fragment]) -> str:
    """Stable digest of a full fragment set, used in tests and audit records."""
    hasher = hashlib.sha256()
    for fragment in sorted(fragments, key=lambda f: f.header.fragment_index):
        hasher.update(fragment.signed_bytes())
    return hasher.hexdigest()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value) -> bytes:
    if not isinstance(value, str):
        raise WireError("expected base64 text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        raise WireError("malformed base64") from None


__all__ = [
    "Header",
    "Fragment",
    "Message",
    "WireError",
    "FailureReason",
    "PROTOCOL_VERSION",
    "SUITE",
    "MAX_FRAGMENTS",
    "DEFAULT_FRAGMENT_BYTES",
    "split",
    "message_digest",
    "MAX_MESSAGES_PER_KEY",
]
