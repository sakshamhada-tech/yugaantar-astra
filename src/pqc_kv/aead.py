"""Nonce policy + associated-data builder.

AES-GCM breaks catastrophically if a (key, nonce) pair is ever reused: you leak
the XOR of two plaintexts and, in some cases, the authentication key. Two
defences, both used here:

1. **Fresh random 96-bit nonce** for every message, from the OS CSPRNG.
   With a random nonce the birthday bound is 2^32 messages per key.
2. **A nonce budget per key.** We count encryptions under each derived key and
   stop before the safe limit, so a long-lived key degrades into an explicit
   error instead of silent nonce risk.

Note what is *not* here: "random nonce + hope". We refuse to encrypt when the
budget is exhausted, and the store rotates the key at that point.

The AAD (associated data) is the unencrypted but *authenticated* header: it binds
algorithm choice, recipient label, envelope id and context label to the
ciphertext. Change any of it and decryption fails, so an attacker cannot move a
ciphertext to a different asset or recipient.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field

from .symmetric import NONCE_LEN

# NIST SP 800-38D recommends limiting a single key to 2^32 messages when random
# 96-bit nonces are used. We stay far below that.
MAX_MESSAGES_PER_KEY = 1 << 20  # 1,048,576


class NonceBudgetExhausted(Exception):
    """This key has produced too many nonces to stay inside the safe bound."""


@dataclass
class NonceBudget:
    """Per-key encryption counter, in-memory only.

    We deliberately do not persist it: the store rotates keys well before the
    limit, so a process restart cannot silently resume an over-used key. Starting
    the count at zero after a restart is safe *because* rotation happens at
    `MAX_MESSAGES_PER_KEY / 4` in the store layer.
    """

    limit: int = MAX_MESSAGES_PER_KEY
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def take(self) -> int:
        with self._lock:
            if self.used >= self.limit:
                raise NonceBudgetExhausted("key nonce budget exhausted; rotate the key")
            self.used += 1
            return self.used


def fresh_nonce() -> bytes:
    """96-bit nonce from the OS CSPRNG. Never derived from a counter or time."""
    nonce = os.urandom(NONCE_LEN)
    if len(nonce) != NONCE_LEN:  # pragma: no cover - os.urandom contract
        raise RuntimeError("OS randomness unavailable")
    return nonce


def build_aad(
    *,
    suite: str,
    recipient: str,
    envelope_id: str,
    context: str,
    version: int,
) -> bytes:
    """Canonical, unambiguous AAD.

    JSON with sorted keys and no whitespace: deterministic, so both sides rebuild
    exactly the same bytes. Fields are opaque strings; identifiers are never
    interpreted, only bound.
    """
    payload = {
        "ctx": context,
        "env": envelope_id,
        "rcpt": recipient,
        "suite": suite,
        "v": version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
