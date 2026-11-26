"""The symmetric ratchet, built only from HKDF-SHA256.

Shape::

    root_key                       (from the handshake)
      ├── chain_key(send)          HKDF(root, "chain/send")      <- advances per message
      └── chain_key(recv)          HKDF(root, "chain/recv")

    per message:
      message_key  = HKDF(chain_key, "msgkey", 32)
      next_chain   = HKDF(chain_key, "chain-next", 32)

Both directions get independent chains, so a compromise of one direction's chain
does not hand over the other direction. The chain advances *irreversibly*: HKDF is
one-way, so a stolen current chain key does not reveal earlier message keys. That
is the forward-secrecy property for messages within a session.

Two things this deliberately is NOT:

1. **No DH ratchet.** We never mix a fresh DH into the chain, so if an attacker
   steals the current chain key they can read *all future* messages until the
   session is re-established. Forward secrecy yes, post-compromise security no.
   Written down in SECURITY_NOTES.
2. **No home-made construction.** Every step is one HKDF call with a distinct,
   length-prefixed context label. No XOR, no "hash the counter", no truncation of
   anything we did not derive.

Skipped / out-of-order messages: a receiver may get sequence 7 before 5 and 6
(fragments arrive shuffled, messages can overtake each other). Ratcheting forward
would destroy the ability to read 5 and 6, so we derive them eagerly and park
them in a **bounded** cache. The bound matters: an unbounded cache is a memory
exhaustion vector once an attacker can claim arbitrary sequence numbers, so we
cap (a) how far ahead a single message may jump and (b) how many parked keys we
retain, evicting oldest first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import OrderedDict

from ..symmetric import KEY_LEN, hkdf_sha256

RATCHET_CONTEXT = b"pqc-kv/v2/ratchet"

# Bounded skip window. Both limits are policy, not crypto: they exist so a hostile
# sequence number cannot make us derive forever or hoard keys.
MAX_SKIP_AHEAD = 512  # refuse a sequence more than this far past the expected one
MAX_SKIPPED_KEYS = 512  # total parked message keys per session, per direction


class RatchetError(Exception):
    """Ratchet refused to advance. No key material, no sequence detail beyond a code."""


class RatchetFailure:
    TOO_FAR_AHEAD = "too_far_ahead"
    ALREADY_USED = "already_used"
    STALE = "stale"
    EXHAUSTED = "exhausted"


# Direction labels are agreed by *both* peers, not chosen per role. The initiator
# encrypts on "i2r" and decrypts on "r2i"; the responder does the mirror image.
# Using "send"/"recv" here would be a silent bug: each side would derive a
# different chain and nothing would ever decrypt.
DIRECTION_INITIATOR_TO_RESPONDER = "i2r"
DIRECTION_RESPONDER_TO_INITIATOR = "r2i"
DIRECTIONS = (DIRECTION_INITIATOR_TO_RESPONDER, DIRECTION_RESPONDER_TO_INITIATOR)


def derive_chain_key(root_key: bytes, direction: str) -> bytes:
    """Initial chain key for an agreed ``direction`` (``i2r`` or ``r2i``)."""
    if direction not in DIRECTIONS:
        raise RatchetError("unknown direction")
    if len(root_key) != KEY_LEN:
        raise RatchetError("malformed root key")
    return hkdf_sha256(
        root_key,
        salt=b"",
        info=RATCHET_CONTEXT + b"/chain/" + direction.encode(),
        length=KEY_LEN,
    )


def derive_message_key(chain_key: bytes) -> bytes:
    """Per-message AEAD key. Same chain key always yields the same message key."""
    return hkdf_sha256(
        chain_key, salt=b"", info=RATCHET_CONTEXT + b"/msgkey", length=KEY_LEN
    )


def derive_next_chain_key(chain_key: bytes) -> bytes:
    """Advance the chain irreversibly."""
    return hkdf_sha256(
        chain_key, salt=b"", info=RATCHET_CONTEXT + b"/chain-next", length=KEY_LEN
    )


@dataclass
class ReceiveRatchet:
    """Receiver-side chain with a bounded cache of skipped message keys.

    Invariants:
      * ``next_sequence`` is the lowest sequence we have not yet *derived*.
      * ``skipped`` holds keys for sequences below ``next_sequence`` that have not
        been consumed. A key is removed the moment it is used (single use).
      * every operation is idempotent in the sense that a second use of the same
        sequence raises ``ALREADY_USED`` rather than silently decrypting twice.
    """

    chain_key: bytes
    next_sequence: int = 0
    skipped: "OrderedDict[int, bytes]" = field(default_factory=OrderedDict)
    max_skip_ahead: int = MAX_SKIP_AHEAD
    max_skipped: int = MAX_SKIPPED_KEYS

    def __post_init__(self) -> None:
        if len(self.chain_key) != KEY_LEN:
            raise RatchetError("malformed chain key")
        if self.next_sequence < 0:
            raise RatchetError("malformed sequence")

    # -- the interesting call ----------------------------------------------
    def take_key(self, sequence: int) -> bytes:
        """Return the message key for ``sequence``, advancing the chain as needed.

        Either returns a key that has never been returned before, or raises. It
        never returns the same key twice, which is what makes nonce reuse
        impossible at this layer even under replay.
        """
        if not isinstance(sequence, int) or sequence < 0:
            raise RatchetError("malformed sequence")

        if sequence < self.next_sequence:
            parked = self.skipped.pop(sequence, None)
            if parked is None:
                raise RatchetError(RatchetFailure.ALREADY_USED)
            return parked

        ahead = sequence - self.next_sequence
        if ahead > self.max_skip_ahead:
            raise RatchetError(RatchetFailure.TOO_FAR_AHEAD)

        # Derive every intervening key and park it. Bounded on both axes: we only
        # get here when ahead <= max_skip_ahead, and we evict the oldest parked
        # keys once the cache is full.
        key = self.chain_key
        for _ in range(ahead):
            self.skipped[self.next_sequence] = derive_message_key(key)
            self._evict()
            key = derive_next_chain_key(key)
            self.next_sequence += 1

        message_key = derive_message_key(key)
        self.chain_key = derive_next_chain_key(key)
        self.next_sequence += 1
        return message_key

    def _evict(self) -> None:
        while len(self.skipped) > self.max_skipped:
            self.skipped.popitem(last=False)  # oldest first

    # -- persistence --------------------------------------------------------
    def to_dict(self) -> dict:
        from ..keystore import b64e

        return {
            "chain_key": b64e(self.chain_key),
            "next_sequence": self.next_sequence,
            "skipped": [
                {"seq": seq, "key": b64e(key)} for seq, key in self.skipped.items()
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ReceiveRatchet":
        from ..keystore import b64d

        try:
            skipped: OrderedDict[int, bytes] = OrderedDict()
            for item in data["skipped"]:
                skipped[int(item["seq"])] = b64d(item["key"])
            return cls(
                chain_key=b64d(data["chain_key"]),
                next_sequence=int(data["next_sequence"]),
                skipped=skipped,
            )
        except Exception:
            raise RatchetError("malformed ratchet state") from None

    def __repr__(self) -> str:
        return "ReceiveRatchet(next_sequence=%d, skipped=%d, key=<redacted>)" % (
            self.next_sequence,
            len(self.skipped),
        )


@dataclass
class SendRatchet:
    """Sender-side chain. Only moves forward, one step per message."""

    chain_key: bytes
    next_sequence: int = 0

    def __post_init__(self) -> None:
        if len(self.chain_key) != KEY_LEN:
            raise RatchetError("malformed chain key")

    def next_key(self) -> tuple[int, bytes]:
        sequence = self.next_sequence
        message_key = derive_message_key(self.chain_key)
        self.chain_key = derive_next_chain_key(self.chain_key)
        self.next_sequence += 1
        return sequence, message_key

    def to_dict(self) -> dict:
        from ..keystore import b64e

        return {"chain_key": b64e(self.chain_key), "next_sequence": self.next_sequence}

    @classmethod
    def from_dict(cls, data: dict) -> "SendRatchet":
        from ..keystore import b64d

        try:
            return cls(chain_key=b64d(data["chain_key"]), next_sequence=int(data["next_sequence"]))
        except Exception:
            raise RatchetError("malformed ratchet state") from None

    def __repr__(self) -> str:
        return "SendRatchet(next_sequence=%d, key=<redacted>)" % self.next_sequence


__all__ = [
    "RatchetError",
    "RatchetFailure",
    "ReceiveRatchet",
    "SendRatchet",
    "derive_chain_key",
    "DIRECTIONS",
    "DIRECTION_INITIATOR_TO_RESPONDER",
    "DIRECTION_RESPONDER_TO_INITIATOR",
    "derive_message_key",
    "derive_next_chain_key",
    "RATCHET_CONTEXT",
    "MAX_SKIP_AHEAD",
    "MAX_SKIPPED_KEYS",
]
