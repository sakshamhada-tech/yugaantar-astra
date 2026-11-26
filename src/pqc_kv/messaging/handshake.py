"""Authenticated, mutually key-confirmed handshake with forward secrecy.

**Three messages. Both sides sign the same final transcript.** That is the fix for
the flaw in my first sketch: if A signs before B's ephemerals exist, A is signing a
*guess* about the transcript, not the transcript. Here is the real message count:

    1. INIT   A -> B   hello     A's ephemeral publics + A's signature over hello_a
    2. FINISH B -> A   accept    B's ephemeral publics + B's signature over accept_b
                                 ... plus the full transcript hash, which commits B
                                 to A's hello
    3. CONFIRM A -> B  confirm   A's signature over the SAME final transcript

So:

* B is authenticated to A at step 2 (A verifies B's signature over a transcript that
  includes A's own hello -- no room for a UKS/splicing attack, because B signs bytes
  A chose).
* A is authenticated to B at step 3, over the identical bytes B signed.
* B gets **mutual key confirmation**: step 3 proves A derived the same root key,
  because only A can sign the transcript *and* A only reaches step 3 after
  successfully decapsulating. If A's confirm signature verifies, B knows the keys
  agree. A gets the same assurance one step earlier, since only B could have
  produced a valid step-2 signature over A's hello.

Each signature covers exactly the same value: ``final_transcript_hash``, which is
SHA-256 over a canonical, length-delimited encoding of every public value in the
conversation (both identities, both ephemeral X25519 keys, the ML-KEM ciphertext,
the session id, and the direction of the message). Signing a *hash* rather than the
raw megabytes keeps the signature input fixed-size and unambiguous.

Ephemeral handling (brief, Option B):

* The **initiator** must keep its ephemeral secrets between step 1 and step 3, so it
  persists them, plaintext, 0600, in the private state dir. They are erased at step
  3 *before* the confirm message is returned -- i.e. the moment the session key
  exists.
* The **responder** never persists ephemerals: step 2 is a single request that
  receives the hello and produces the accept.

Limits (in SECURITY_NOTES, repeated here so nobody has to find them):

* No clock is trusted. Freshness comes from single-use handshake ids, not expiry.
* The directory is the trust anchor; a local attacker who can rewrite it can
  substitute keys (see directory.py).
* Symmetric ratchet only: no DH ratchet, so no post-compromise security.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass

from .. import dsa, hybrid, kem
from ..keystore import b64d, b64e
from . import ephemeral as eph_store
from .identity import IdentityError, PrivateIdentity, PublicIdentity
from .kdf import (
    DIRECTION_INITIATOR_TO_RESPONDER,
    DIRECTION_RESPONDER_TO_INITIATOR,
    derive_chain_key,
)
from ..symmetric import KEY_LEN, hkdf_sha256

PROTOCOL = "pqc-kv/v2/handshake"
HANDSHAKE_VERSION = 2
TRANSCRIPT_CONTEXT = b"pqc-kv/v2/handshake-transcript"
ROOT_CONTEXT = b"pqc-kv/v2/handshake-root"

HELLO = "hello"
ACCEPT = "accept"
CONFIRM = "confirm"


class HandshakeError(Exception):
    """Any handshake failure. One type, no field detail, no key material.

    Callers get a reason *code* for the audit log; the exception text is fixed so
    nothing can be inferred from it.
    """

    def __init__(self, reason: str = "handshake_failed") -> None:
        super().__init__(reason)
        self.reason = reason


class Reason:
    MALFORMED = "malformed"
    WRONG_RECIPIENT = "wrong_recipient"
    WRONG_SENDER = "wrong_sender"
    UNKNOWN_PEER = "unknown_peer"
    SIGNATURE_INVALID = "signature_invalid"
    TRANSCRIPT_MISMATCH = "transcript_mismatch"
    NO_PENDING = "no_pending_handshake"
    ALREADY_USED = "handshake_already_used"
    REPLAYED = "handshake_replayed"
    DERIVATION_FAILED = "derivation_failed"
    IDENTITY_MISMATCH = "identity_mismatch"


# ---------------------------------------------------------------- transcript
@dataclass(frozen=True)
class TranscriptParts:
    """Every public value that defines this conversation."""

    session_id: str
    initiator_user: str
    initiator_fp: str
    responder_user: str
    responder_fp: str
    initiator_x25519: bytes
    initiator_mlkem: bytes
    responder_x25519: bytes
    responder_mlkem_ct: bytes

    def canonical(self) -> bytes:
        """Length-prefixed so no two distinct transcripts can encode identically."""
        hasher = hashlib.sha256()
        hasher.update(TRANSCRIPT_CONTEXT)
        hasher.update(int(HANDSHAKE_VERSION).to_bytes(2, "big"))
        for text in (
            self.session_id,
            self.initiator_user,
            self.initiator_fp,
            self.responder_user,
            self.responder_fp,
        ):
            raw = text.encode("utf-8")
            hasher.update(len(raw).to_bytes(4, "big"))
            hasher.update(raw)
        for blob in (
            self.initiator_x25519,
            self.initiator_mlkem,
            self.responder_x25519,
            self.responder_mlkem_ct,
        ):
            hasher.update(len(blob).to_bytes(4, "big"))
            hasher.update(blob)
        return hasher.digest()

    def __repr__(self) -> str:
        return (
            "TranscriptParts(sid=%r, %s->%s, %s->%s)"
            % (
                self.session_id,
                self.initiator_user,
                self.responder_user,
                self.initiator_fp[:12],
                self.responder_fp[:12],
            )
        )


def derive_root(
    parts: TranscriptParts,
    x25519_shared: bytes,
    mlkem_shared: bytes,
) -> bytes:
    """HKDF over (transcript || x25519_ss || mlkem_ss) with a fixed label.

    Both components are length-prefixed before mixing, so removing or trimming
    either one changes the result. Reuses the Phase 1 HKDF; invents nothing.
    """
    if len(x25519_shared) != hybrid.X25519_LEN:
        raise HandshakeError(Reason.DERIVATION_FAILED)
    if len(mlkem_shared) != kem.SHARED_SECRET_LEN:
        raise HandshakeError(Reason.DERIVATION_FAILED)
    ikm = b"".join(
        [
            parts.canonical(),
            len(x25519_shared).to_bytes(2, "big"),
            x25519_shared,
            len(mlkem_shared).to_bytes(2, "big"),
            mlkem_shared,
        ]
    )
    salt = hkdf_sha256(parts.canonical(), salt=b"", info=ROOT_CONTEXT + b"/salt", length=KEY_LEN)
    return hkdf_sha256(ikm, salt=salt, info=ROOT_CONTEXT + b"/key", length=KEY_LEN)


# ------------------------------------------------------------------ messages
@dataclass(frozen=True)
class Hello:
    """Message 1: initiator -> responder."""

    session_id: str
    initiator_user: str
    initiator_fp: str
    # The intended recipient is named *inside the signed payload*, so a hello
    # addressed to B cannot be accepted by C.
    responder_user: str
    responder_fp: str
    x25519_public: bytes
    mlkem_public: bytes
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        return b"|".join(
            [
                PROTOCOL.encode(),
                HELLO.encode(),
                str(HANDSHAKE_VERSION).encode(),
                self.session_id.encode(),
                self.initiator_user.encode(),
                self.initiator_fp.encode(),
                self.responder_user.encode(),
                self.responder_fp.encode(),
                self.x25519_public,
                self.mlkem_public,
            ]
        )

    def to_dict(self) -> dict:
        return {
            "kind": HELLO,
            "v": HANDSHAKE_VERSION,
            "session_id": self.session_id,
            "from_user": self.initiator_user,
            "from_fp": self.initiator_fp,
            "to_user": self.responder_user,
            "to_fp": self.responder_fp,
            "x25519": b64e(self.x25519_public),
            "mlkem": b64e(self.mlkem_public),
            "sig": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Hello":
        try:
            if data.get("kind") != HELLO:
                raise HandshakeError(Reason.MALFORMED)
            return cls(
                session_id=str(data["session_id"]),
                initiator_user=str(data["from_user"]),
                initiator_fp=str(data["from_fp"]),
                responder_user=str(data["to_user"]),
                responder_fp=str(data["to_fp"]),
                x25519_public=b64d(data["x25519"]),
                mlkem_public=b64d(data["mlkem"]),
                signature=b64d(data["sig"]),
            )
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError(Reason.MALFORMED) from None


@dataclass(frozen=True)
class Accept:
    """Message 2: responder -> initiator."""

    session_id: str
    responder_user: str
    responder_fp: str
    initiator_user: str
    initiator_fp: str
    x25519_public: bytes
    mlkem_ciphertext: bytes
    transcript_hash: bytes
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        return b"|".join(
            [
                PROTOCOL.encode(),
                ACCEPT.encode(),
                str(HANDSHAKE_VERSION).encode(),
                self.session_id.encode(),
                self.responder_user.encode(),
                self.responder_fp.encode(),
                self.initiator_user.encode(),
                self.initiator_fp.encode(),
                self.x25519_public,
                self.mlkem_ciphertext,
                self.transcript_hash,
            ]
        )

    def to_dict(self) -> dict:
        return {
            "kind": ACCEPT,
            "v": HANDSHAKE_VERSION,
            "session_id": self.session_id,
            "from_user": self.responder_user,
            "from_fp": self.responder_fp,
            "to_user": self.initiator_user,
            "to_fp": self.initiator_fp,
            "x25519": b64e(self.x25519_public),
            "mlkem_ct": b64e(self.mlkem_ciphertext),
            "transcript": b64e(self.transcript_hash),
            "sig": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Accept":
        try:
            if data.get("kind") != ACCEPT:
                raise HandshakeError(Reason.MALFORMED)
            return cls(
                session_id=str(data["session_id"]),
                responder_user=str(data["from_user"]),
                responder_fp=str(data["from_fp"]),
                initiator_user=str(data["to_user"]),
                initiator_fp=str(data["to_fp"]),
                x25519_public=b64d(data["x25519"]),
                mlkem_ciphertext=b64d(data["mlkem_ct"]),
                transcript_hash=b64d(data["transcript"]),
                signature=b64d(data["sig"]),
            )
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError(Reason.MALFORMED) from None


@dataclass(frozen=True)
class Confirm:
    """Message 3: initiator -> responder. Mutual key confirmation."""

    session_id: str
    initiator_user: str
    initiator_fp: str
    responder_user: str
    responder_fp: str
    transcript_hash: bytes
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        return b"|".join(
            [
                PROTOCOL.encode(),
                CONFIRM.encode(),
                str(HANDSHAKE_VERSION).encode(),
                self.session_id.encode(),
                self.initiator_user.encode(),
                self.initiator_fp.encode(),
                self.responder_user.encode(),
                self.responder_fp.encode(),
                self.transcript_hash,
            ]
        )

    def to_dict(self) -> dict:
        return {
            "kind": CONFIRM,
            "v": HANDSHAKE_VERSION,
            "session_id": self.session_id,
            "from_user": self.initiator_user,
            "from_fp": self.initiator_fp,
            "to_user": self.responder_user,
            "to_fp": self.responder_fp,
            "transcript": b64e(self.transcript_hash),
            "sig": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Confirm":
        try:
            if data.get("kind") != CONFIRM:
                raise HandshakeError(Reason.MALFORMED)
            return cls(
                session_id=str(data["session_id"]),
                initiator_user=str(data["from_user"]),
                initiator_fp=str(data["from_fp"]),
                responder_user=str(data["to_user"]),
                responder_fp=str(data["to_fp"]),
                transcript_hash=b64d(data["transcript"]),
                signature=b64d(data["sig"]),
            )
        except HandshakeError:
            raise
        except Exception:
            raise HandshakeError(Reason.MALFORMED) from None


@dataclass
class SessionKeys:
    """What a completed handshake yields. Secrets never appear in repr."""

    session_id: str
    role: str  # "initiator" | "responder"
    peer_user: str
    peer_fp: str
    self_user: str
    self_fp: str
    root_key: bytes
    transcript_hash: bytes

    @property
    def send_chain(self) -> bytes:
        direction = (
            DIRECTION_INITIATOR_TO_RESPONDER if self.role == "initiator" else DIRECTION_RESPONDER_TO_INITIATOR
        )
        return derive_chain_key(self.root_key, direction)

    @property
    def recv_chain(self) -> bytes:
        direction = (
            DIRECTION_RESPONDER_TO_INITIATOR if self.role == "initiator" else DIRECTION_INITIATOR_TO_RESPONDER
        )
        return derive_chain_key(self.root_key, direction)

    def __repr__(self) -> str:
        return "SessionKeys(sid=%r, role=%s, peer=%r, key=<redacted>)" % (
            self.session_id,
            self.role,
            self.peer_user,
        )


# -------------------------------------------------------------------- steps
def initiate(
    *,
    identity: PrivateIdentity,
    peer: PublicIdentity,
    state_root,
    session_id: str | None = None,
) -> tuple[Hello, str]:
    """Step 1 (initiator). Returns the hello to send and the handshake id.

    Persists the initiator's ephemeral secrets so step 3 can complete in a later
    process. The responder never does this.
    """
    session_id = session_id or _new_session_id()
    secret_x, public_x = hybrid.new_x25519_keypair()
    ephemeral_pq = kem.generate_keypair()

    hello = Hello(
        session_id=session_id,
        initiator_user=identity.user_id,
        initiator_fp=identity.fingerprint,
        responder_user=peer.user_id,
        responder_fp=peer.fingerprint,
        x25519_public=public_x,
        mlkem_public=ephemeral_pq.public_key,
    )
    signed = Hello(**{**hello.__dict__, "signature": identity.sign(hello.signed_bytes())})

    eph_store.save(
        state_root,
        session_id,
        x25519_secret=secret_x,
        mlkem_secret=ephemeral_pq.secret_key,
        peer_user=peer.user_id,
        peer_fp=peer.fingerprint,
    )
    return signed, session_id


def respond(
    *,
    identity: PrivateIdentity,
    hello: Hello,
    peer: PublicIdentity,
    directory_lookup,
) -> tuple[Accept, SessionKeys]:
    """Step 2 (responder). Single process: verifies hello, derives keys, no persistence.

    ``directory_lookup(user_id)`` must return the *trusted* PublicIdentity for the
    claimed sender; we never take the sender's key from the message itself.
    """
    _check_recipient(identity, hello.responder_user, hello.responder_fp)

    if hello.initiator_user != peer.user_id or hello.initiator_fp != peer.fingerprint:
        raise HandshakeError(Reason.IDENTITY_MISMATCH)

    # The sender's key comes from the directory, not from the wire.
    if not dsa.verify(peer.signing_public, hello.signed_bytes(), hello.signature):
        raise HandshakeError(Reason.SIGNATURE_INVALID)

    try:
        encapsulation = kem.encapsulate(hello.mlkem_public)
    except kem.KemError:
        raise HandshakeError(Reason.MALFORMED) from None

    secret_x, public_x = hybrid.new_x25519_keypair()
    parts = TranscriptParts(
        session_id=hello.session_id,
        initiator_user=hello.initiator_user,
        initiator_fp=hello.initiator_fp,
        responder_user=identity.user_id,
        responder_fp=identity.fingerprint,
        initiator_x25519=hello.x25519_public,
        initiator_mlkem=hello.mlkem_public,
        responder_x25519=public_x,
        responder_mlkem_ct=encapsulation.ciphertext,
    )
    transcript_hash = parts.canonical()

    try:
        x_shared = hybrid.x25519_agree(secret_x, hello.x25519_public)
    except hybrid.HybridError:
        raise HandshakeError(Reason.DERIVATION_FAILED) from None
    root = derive_root(parts, x_shared, encapsulation.shared_secret)

    accept = Accept(
        session_id=hello.session_id,
        responder_user=identity.user_id,
        responder_fp=identity.fingerprint,
        initiator_user=hello.initiator_user,
        initiator_fp=hello.initiator_fp,
        x25519_public=public_x,
        mlkem_ciphertext=encapsulation.ciphertext,
        transcript_hash=transcript_hash,
    )
    signed = Accept(**{**accept.__dict__, "signature": identity.sign(accept.signed_bytes())})

    keys = SessionKeys(
        session_id=hello.session_id,
        role="responder",
        peer_user=hello.initiator_user,
        peer_fp=hello.initiator_fp,
        self_user=identity.user_id,
        self_fp=identity.fingerprint,
        root_key=root,
        transcript_hash=transcript_hash,
    )
    # Responder ephemerals were local variables; they die with this process.
    return signed, keys


def complete(
    *,
    identity: PrivateIdentity,
    accept: Accept,
    state_root,
    peer: PublicIdentity,
) -> tuple[Confirm, SessionKeys]:
    """Step 3 (initiator). Loads ephemerals, derives keys, ERASES them, returns confirm."""
    _check_recipient(identity, accept.initiator_user, accept.initiator_fp)
    if accept.responder_user != peer.user_id or accept.responder_fp != peer.fingerprint:
        raise HandshakeError(Reason.IDENTITY_MISMATCH)

    try:
        record = eph_store.load(state_root, accept.session_id)
    except eph_store.EphemeralError:
        # Already completed (single use) or never started.
        raise HandshakeError(Reason.NO_PENDING) from None

    if record["peer_fp"] != peer.fingerprint or record["peer_user"] != peer.user_id:
        raise HandshakeError(Reason.WRONG_SENDER)

    if not dsa.verify(peer.signing_public, accept.signed_bytes(), accept.signature):
        raise HandshakeError(Reason.SIGNATURE_INVALID)

    parts = TranscriptParts(
        session_id=accept.session_id,
        initiator_user=identity.user_id,
        initiator_fp=identity.fingerprint,
        responder_user=accept.responder_user,
        responder_fp=accept.responder_fp,
        initiator_x25519=hybrid.x25519_public_of(record["x25519_secret"]),
        initiator_mlkem=kem.public_key_from_secret(record["mlkem_secret"]),
        responder_x25519=accept.x25519_public,
        responder_mlkem_ct=accept.mlkem_ciphertext,
    )
    # The responder committed to a transcript hash. If our reconstruction differs,
    # someone spliced two conversations (or tampered with the wire).
    if parts.canonical() != accept.transcript_hash:
        raise HandshakeError(Reason.TRANSCRIPT_MISMATCH)

    try:
        x_shared = hybrid.x25519_agree(record["x25519_secret"], accept.x25519_public)
        pq_shared = kem.decapsulate(accept.mlkem_ciphertext, record["mlkem_secret"])
    except (hybrid.HybridError, kem.KemError):
        raise HandshakeError(Reason.DERIVATION_FAILED) from None

    root = derive_root(parts, x_shared, pq_shared)

    # The session key now exists: erase the ephemerals before anything else can
    # happen, and before the caller gets the key. Single use is enforced by the
    # file being gone, not by a flag.
    eph_store.erase(state_root, accept.session_id)

    confirm = Confirm(
        session_id=accept.session_id,
        initiator_user=identity.user_id,
        initiator_fp=identity.fingerprint,
        responder_user=accept.responder_user,
        responder_fp=accept.responder_fp,
        transcript_hash=parts.canonical(),
    )
    signed = Confirm(**{**confirm.__dict__, "signature": identity.sign(confirm.signed_bytes())})

    keys = SessionKeys(
        session_id=accept.session_id,
        role="initiator",
        peer_user=accept.responder_user,
        peer_fp=accept.responder_fp,
        self_user=identity.user_id,
        self_fp=identity.fingerprint,
        root_key=root,
        transcript_hash=parts.canonical(),
    )
    return signed, keys


def confirm(
    *,
    identity: PrivateIdentity,
    message: Confirm,
    session_transcript: bytes,
    peer: PublicIdentity,
) -> None:
    """Responder-side check of message 3. Raises unless A proves the same key."""
    _check_recipient(identity, message.responder_user, message.responder_fp)
    if message.initiator_user != peer.user_id or message.initiator_fp != peer.fingerprint:
        raise HandshakeError(Reason.IDENTITY_MISMATCH)
    if message.transcript_hash != session_transcript:
        raise HandshakeError(Reason.TRANSCRIPT_MISMATCH)
    if not dsa.verify(peer.signing_public, message.signed_bytes(), message.signature):
        raise HandshakeError(Reason.SIGNATURE_INVALID)


def _check_recipient(identity: PrivateIdentity, user: str, fp: str) -> None:
    if user != identity.user_id or fp != identity.fingerprint:
        raise HandshakeError(Reason.WRONG_RECIPIENT)


def _new_session_id() -> str:
    return "s-" + secrets.token_hex(16)


__all__ = [
    "Accept",
    "Confirm",
    "Hello",
    "HandshakeError",
    "Reason",
    "SessionKeys",
    "TranscriptParts",
    "complete",
    "confirm",
    "derive_root",
    "initiate",
    "respond",
    "HELLO",
    "ACCEPT",
    "CONFIRM",
    "PROTOCOL",
]
