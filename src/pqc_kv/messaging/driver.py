"""Sending and receiving: fragments, ratchet, replay defence, policy.

Two entry points, ``send_message`` and ``receive_fragments``, both of which take
the state root and an optional policy callback. Everything else here is
plumbing between those and the pieces built earlier (``wire``, ``kdf``,
``session``, ``identity``).

**Signature policy: sign once per message, not per fragment.** Measured on this
implementation (see docs/MESSAGING.md):

    body    frag     per-fragment          per-message
    1 KB    1 KB     5.96x, 3309 B sig     5.96x (single fragment, identical)
    8 KB    1 KB     5.96x, 26 472 B       2.19x, 3309 B
    64 KB   1 KB     5.96x, 211 776 B      1.72x, 3309 B   (60 ms vs 3.6 ms)

A 3309-byte ML-DSA signature per 1024-byte fragment is a 3.2x expansion *per
fragment*, i.e. 5.96x on the wire. So we sign a single **manifest** over every
fragment and carry that one signature in fragment 0. Fragments 1..n-1 have an
empty signature field and are *not* individually signed.

What that costs, stated plainly: a fragment arriving out of order cannot be
attributed to a sender until fragment 0 arrives. That is acceptable because
(a) each fragment is still AEAD-authenticated under a key only the two parties
hold, so an attacker cannot forge one, and (b) reassembly refuses to deliver
anything unless every fragment authenticated. The properties we keep are the ones
that matter: integrity, recipient binding, and no plaintext on failure.

**Delivery semantics: at-most-once.** The receive path advances the ratchet and
persists the new state *before* returning plaintext. If the process dies between
persisting and responding, the message is gone -- it cannot be re-read, because
its message key was consumed and never stored. We choose at-most-once because a
duplicate delivery would mean reusing an AES-GCM message key, which is the one
failure mode that breaks confidentiality outright. Losing a message is annoying;
replaying one is fatal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .. import dsa
from ..aead import fresh_nonce
from ..symmetric import TamperError, aesgcm_decrypt, aesgcm_encrypt
from . import wire
from .identity import PublicIdentity
from .kdf import RatchetError, RatchetFailure, ReceiveRatchet, SendRatchet
from .session import MAX_PARTIAL_MESSAGES, PartialMessage, SessionStore

DEFAULT_FRAGMENT_BYTES = wire.DEFAULT_FRAGMENT_BYTES


class DriverError(Exception):
    """Send/receive failure. Carries a reason code, never plaintext or keys."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------- send
def send_message(
    *,
    state_root: Path,
    session_id: str,
    session: dict,
    recipient: PublicIdentity,
    body: bytes,
    signer_public: bytes,
    signing_secret: bytes,
    fragment_bytes: int = DEFAULT_FRAGMENT_BYTES,
    policy=None,
) -> list[dict]:
    """Split, encrypt, sign-once, ratchet forward, persist. Returns wire fragments.

    ``policy(user_id, action) -> bool`` is the revocation hook: the caller wires
    StateStore in here so a revoked actor cannot send.
    """
    if policy is not None and not policy(session["self_user"], "send"):
        raise DriverError(wire.FailureReason.POLICY_DENIED)
    if recipient.user_id != session["peer_user"] or recipient.fingerprint != session["peer_fp"]:
        raise DriverError(wire.FailureReason.WRONG_RECIPIENT)

    try:
        send_ratchet = SendRatchet.from_dict(session["send"])
    except RatchetError:
        raise DriverError(wire.FailureReason.INVALID_FORMAT) from None

    sequence, message_key = send_ratchet.next_key()
    message_id = session["next_message_id"]

    if not body:
        chunks = [b""]
    else:
        chunks = [body[i : i + fragment_bytes] for i in range(0, len(body), fragment_bytes)]
    total = len(chunks)
    if total > wire.MAX_FRAGMENTS:
        raise DriverError(wire.FailureReason.TOO_MANY_FRAGMENTS)

    prepared: list[tuple[wire.Header, bytes, bytes, bytes]] = []
    for index, chunk in enumerate(chunks):
        header = wire.Header(
            version=wire.PROTOCOL_VERSION,
            suite=wire.SUITE,
            session_id=session_id,
            sender_fp=session["self_fp"],
            sender_user=session["self_user"],
            recipient_fp=recipient.fingerprint,
            recipient_user=recipient.user_id,
            message_id=message_id,
            sequence=sequence,
            fragment_index=index,
            fragment_total=total,
        )
        nonce = fresh_nonce()
        ciphertext, tag = aesgcm_encrypt(message_key, nonce, chunk, header.canonical())
        prepared.append((header, nonce, ciphertext, tag))

    # One signature over a manifest of every fragment.
    manifest = b"".join(_manifest_entry(h, n, c, t) for h, n, c, t in prepared)
    signature = dsa.sign(signing_secret, _manifest_prefix(session_id, message_id) + manifest)

    fragments = [
        wire.Fragment(
            header=h,
            nonce=n,
            ciphertext=c,
            tag=t,
            signature=signature if index == 0 else b"",
        )
        for index, (h, n, c, t) in enumerate(prepared)
    ]

    updated = dict(session)
    updated["send"] = send_ratchet.to_dict()
    updated["next_message_id"] = _next_id(message_id)
    updated["sent"] = int(updated.get("sent", 0)) + 1
    SessionStore(state_root).put(session_id, updated)
    session.clear()
    session.update(updated)

    return [f.to_dict() for f in fragments]


def _manifest_prefix(session_id: str, message_id: str) -> bytes:
    return b"|".join([wire.SUITE.encode(), b"manifest", session_id.encode(), message_id.encode()])


def _manifest_entry(header: wire.Header, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Length-prefixed so fragment boundaries are unambiguous."""
    parts = [header.canonical(), nonce, ciphertext, tag]
    out = bytearray()
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


# ------------------------------------------------------------------ receive
@dataclass
class ReceiveResult:
    delivered: list[wire.Message]
    failures: list[dict]  # {"reason": code, "message_id": id}
    duplicate_fragments: int = 0


def receive_fragments(
    *,
    state_root: Path,
    session_id: str,
    fragments: list[dict],
    peer: PublicIdentity,
    policy=None,
) -> ReceiveResult:
    """Accept any subset of fragments; deliver only complete, authentic messages.

    Order of checks per fragment, cheapest and most restrictive first:
      1. parse (opaque failure)
      2. addressee is us  -> recipient binding
      3. session matches
      4. sender fingerprint matches the trusted peer
      5. (fragment 0 only) manifest signature
    Then per message: ratchet key, decrypt each fragment, reassemble, persist.
    """
    store = SessionStore(state_root)
    delivered: list[wire.Message] = []
    failures: list[dict] = []
    duplicates = 0

    parsed: list[wire.Fragment] = []
    for raw in fragments:
        try:
            parsed.append(wire.Fragment.from_dict(raw))
        except wire.WireError:
            failures.append({"reason": wire.FailureReason.INVALID_FORMAT, "message_id": ""})
    if not parsed:
        return ReceiveResult(delivered=[], failures=failures)

    # Recipient binding is a property of every fragment, so check it once here.
    for fragment in parsed:
        if (
            fragment.header.recipient_fp != _self_fp(store, session_id)
            or fragment.header.recipient_user != _self_user(store, session_id)
        ):
            failures.append(
                {
                    "reason": wire.FailureReason.WRONG_RECIPIENT,
                    "message_id": fragment.header.message_id,
                }
            )
            return ReceiveResult(delivered=[], failures=failures)

    if policy is not None and not policy(_self_user(store, session_id), "receive"):
        return ReceiveResult(
            delivered=[], failures=[{"reason": wire.FailureReason.POLICY_DENIED, "message_id": ""}]
        )

    grouped: dict[str, list[wire.Fragment]] = {}
    for fragment in parsed:
        if fragment.header.session_id != session_id:
            failures.append(
                {
                    "reason": wire.FailureReason.UNKNOWN_SESSION,
                    "message_id": fragment.header.message_id,
                }
            )
            continue
        if fragment.header.sender_fp != peer.fingerprint or fragment.header.sender_user != peer.user_id:
            failures.append(
                {
                    "reason": wire.FailureReason.WRONG_SENDER,
                    "message_id": fragment.header.message_id,
                }
            )
            continue
        grouped.setdefault(fragment.header.message_id, []).append(fragment)

    for message_id, group in grouped.items():
        outcome = _receive_one(
            store=store,
            session_id=session_id,
            message_id=message_id,
            group=group,
            peer=peer,
        )
        if isinstance(outcome, dict):
            failures.append(outcome)
        elif outcome == "duplicate":
            duplicates += len(group)
        else:
            delivered.append(outcome)

    return ReceiveResult(delivered=delivered, failures=failures, duplicate_fragments=duplicates)


def _receive_one(*, store: SessionStore, session_id: str, message_id: str, group, peer):
    """Handle one message id. Returns a Message, a failure dict, or "duplicate"."""
    try:
        session = store.get(session_id)
    except Exception:
        return {"reason": wire.FailureReason.UNKNOWN_SESSION, "message_id": message_id}

    total = group[0].header.fragment_total
    if any(f.header.fragment_total != total for f in group):
        return {"reason": wire.FailureReason.INVALID_FORMAT, "message_id": message_id}

    # Already-completed message: count as duplicate, never decrypt again.
    if message_id in session.get("seen_ids", []):
        return "duplicate"

    partial = SessionStore.load_partial(session, message_id) or PartialMessage(
        message_id=message_id, total=total
    )
    for fragment in group:
        partial.add(fragment.header.fragment_index, fragment.to_dict())

    if not partial.complete:
        store.mutate(
            session_id, lambda s: (SessionStore.store_partial(s, partial), s)[1]
        )
        return {"reason": wire.FailureReason.INCOMPLETE, "message_id": message_id}

    # Manifest signature: carried in fragment 0, covers all fragments.
    first = wire.Fragment.from_dict(partial.fragments[0])
    manifest_input = (
        _manifest_prefix(session_id, message_id)
        + b"".join(
            _manifest_entry(
                wire.Fragment.from_dict(partial.fragments[i]).header,
                wire.Fragment.from_dict(partial.fragments[i]).nonce,
                wire.Fragment.from_dict(partial.fragments[i]).ciphertext,
                wire.Fragment.from_dict(partial.fragments[i]).tag,
            )
            for i in range(total)
        )
    )
    if not dsa.verify(peer.signing_public, manifest_input, first.signature):
        store.mutate(session_id, lambda s: (SessionStore.drop_partial(s, message_id), s)[1])
        return {"reason": wire.FailureReason.SIGNATURE_INVALID, "message_id": message_id}

    sequence = first.header.sequence
    ratchet = ReceiveRatchet.from_dict(session["recv"])
    try:
        message_key = ratchet.take_key(sequence)
    except RatchetError as error:
        store.mutate(session_id, lambda s: (SessionStore.drop_partial(s, message_id), s)[1])
        code = {
            RatchetFailure.ALREADY_USED: wire.FailureReason.REPLAY,
            RatchetFailure.STALE: wire.FailureReason.STALE_SEQUENCE,
        }.get(str(error), wire.FailureReason.STALE_SEQUENCE)
        return {"reason": code, "message_id": message_id}

    chunks = []
    for index in range(total):
        fragment = wire.Fragment.from_dict(partial.fragments[index])
        try:
            chunks.append(
                aesgcm_decrypt(
                    message_key,
                    fragment.nonce,
                    fragment.ciphertext,
                    fragment.tag,
                    fragment.header.canonical(),
                )
            )
        except TamperError:
            store.mutate(
                session_id,
                lambda s: (SessionStore.drop_partial(s, message_id), s)[1],
            )
            return {"reason": wire.FailureReason.DECRYPT_FAILED, "message_id": message_id}

    body = b"".join(chunks)

    # Persist FIRST: ratchet advance + replay record, atomically, before the
    # plaintext leaves this function. Crash here loses the message (at-most-once)
    # rather than enabling a replay.
    def commit(state: dict) -> dict:
        state["recv"] = ratchet.to_dict()
        SessionStore.remember_id(state, message_id)
        SessionStore.drop_partial(state, message_id)
        state["received"] = int(state.get("received", 0)) + 1
        return state

    store.mutate(session_id, commit)

    return wire.Message(
        message_id=message_id,
        sender_user=first.header.sender_user,
        sender_fp=first.header.sender_fp,
        recipient_user=first.header.recipient_user,
        recipient_fp=first.header.recipient_fp,
        sequence=sequence,
        body=body,
        fragment_count=total,
    )


def _self_fp(store: SessionStore, session_id: str) -> str:
    try:
        return store.get(session_id)["self_fp"]
    except Exception:
        raise DriverError(wire.FailureReason.UNKNOWN_SESSION) from None


def _self_user(store: SessionStore, session_id: str) -> str:
    try:
        return store.get(session_id)["self_user"]
    except Exception:
        raise DriverError(wire.FailureReason.UNKNOWN_SESSION) from None


def _next_id(current: str) -> str:
    """Deterministic, collision-free successor without trusting text format."""
    prefix, _, tail = str(current).rpartition("-")
    if tail.isdigit():
        return f"{prefix}-{int(tail) + 1:08d}"
    return current + "-1"


__all__ = [
    "DriverError",
    "ReceiveResult",
    "DEFAULT_FRAGMENT_BYTES",
    "MAX_PARTIAL_MESSAGES",
    "receive_fragments",
    "send_message",
]
