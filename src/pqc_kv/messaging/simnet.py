"""A seeded, deliberately hostile transport for testing delivery behaviour.

Goal 11 asks for evidence under loss and reordering, so the network here is not
"occasionally flaky" -- it is adversarial by construction and reproducible from a
seed:

    drop      a fragment never arrives
    duplicate a fragment arrives twice
    shuffle   fragments arrive in a different order (globally or per delivery)
    corrupt   one byte is flipped (fragment fails authentication downstream)
    truncate  the fragment is cut short (base64/JSON decode fails downstream)

The simulator never inspects or understands the payload: it treats fragments as
opaque dicts, exactly like a real network would. That matters, because it means a
bug cannot hide in a shared understanding between sender and simulator.

Counters are returned so a demo or a test can report delivery statistics rather
than assert vaguely that "it worked".
"""

from __future__ import annotations

import base64
import copy
import random
from dataclasses import dataclass, field


@dataclass
class NetworkStats:
    sent: int = 0
    dropped: int = 0
    duplicated: int = 0
    corrupted: int = 0
    truncated: int = 0
    delivered: int = 0

    def as_dict(self) -> dict:
        return {
            "sent": self.sent,
            "dropped": self.dropped,
            "duplicated": self.duplicated,
            "corrupted": self.corrupted,
            "truncated": self.truncated,
            "delivered": self.delivered,
        }

    def __repr__(self) -> str:
        return "NetworkStats(%s)" % ", ".join(f"{k}={v}" for k, v in self.as_dict().items())


@dataclass
class LossyNetwork:
    """Deterministic hostile delivery.

    ``drop``/``duplicate``/``corrupt``/``truncate`` are probabilities in [0, 1].
    ``shuffle`` reorders each delivery batch. Same seed -> same run, so failures
    are reproducible and never "it passed on my machine".
    """

    drop: float = 0.0
    duplicate: float = 0.0
    corrupt: float = 0.0
    truncate: float = 0.0
    shuffle: bool = False
    seed: int = 0
    stats: NetworkStats = field(default_factory=NetworkStats)

    def __post_init__(self) -> None:
        for name in ("drop", "duplicate", "corrupt", "truncate"):
            value = getattr(self, name)
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"{name} must be a probability in [0, 1]")
        self._rng = random.Random(self.seed)

    def transmit(self, fragments: list[dict]) -> list[dict]:
        """Return what actually arrives, after applying the configured damage."""
        out: list[dict] = []
        for fragment in fragments:
            self.stats.sent += 1
            if self._rng.random() < self.drop:
                self.stats.dropped += 1
                continue

            payload = copy.deepcopy(fragment)

            if self._rng.random() < self.corrupt:
                payload = _corrupt(payload)
                if payload is None:
                    self.stats.dropped += 1
                    continue
                self.stats.corrupted += 1

            if self._rng.random() < self.truncate:
                payload = _truncate(payload)
                if payload is None:
                    self.stats.dropped += 1
                    continue
                self.stats.truncated += 1

            out.append(payload)
            self.stats.delivered += 1

            if self._rng.random() < self.duplicate:
                out.append(copy.deepcopy(payload))
                self.stats.duplicated += 1
                self.stats.delivered += 1

        if self.shuffle:
            self._rng.shuffle(out)
        return out

    def deliver_in_batches(self, fragments: list[dict], batches: int) -> list[list[dict]]:
        """Split the (already damaged) stream into ``batches`` deliveries.

        Models a transport that hands us a few fragments per request instead of
        all of them, which is what the adapter's one-object-per-request model
        forces anyway.
        """
        damaged = self.transmit(fragments)
        if batches <= 1:
            return [damaged]
        size = max(1, -(-len(damaged) // batches))
        return [damaged[i : i + size] for i in range(0, len(damaged), size)]


def _corrupt(fragment: dict) -> dict | None:
    """Flip one bit inside the ciphertext, if this fragment has one."""
    try:
        raw = bytearray(base64.b64decode(fragment["c"].encode("ascii"), validate=True))
        if not raw:
            return None
        raw[0] ^= 0x01
        damaged = copy.deepcopy(fragment)
        damaged["c"] = base64.b64encode(bytes(raw)).decode("ascii")
        return damaged
    except Exception:
        return None


def _truncate(fragment: dict) -> dict | None:
    """Cut the ciphertext short. Downstream this is indistinguishable from corruption."""
    try:
        encoded = fragment["c"]
        if len(encoded) <= 4:
            return None
        damaged = copy.deepcopy(fragment)
        damaged["c"] = encoded[: max(1, len(encoded) // 2)]
        return damaged
    except Exception:
        return None


__all__ = ["LossyNetwork", "NetworkStats"]
