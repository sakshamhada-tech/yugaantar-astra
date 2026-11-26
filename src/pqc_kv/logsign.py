"""Signed, strictly-encoded key-event log.

Two separate problems live under "log integrity", and they need different fixes.

1. A value must never be able to *become* a record
-------------------------------------------------
The Phase 1 log is JSON Lines: one JSON object per line. JSON escaping already means
an actor named ``maya","decision":"allow`` cannot split the line into two records, so
that particular attack fails for the right reason. But "the escaper happens to handle
it" is a thin guarantee to rest on, and it says nothing about what a *reader* does
with the value later, nor about values that are absurdly long or contain control
characters and look-alike scripts. So this layer is deliberately paranoid:

* **Identifiers are validated, not sanitised.** An actor, request id or asset name is
  accepted only if it matches a conservative charset and length. Anything else is
  rejected at the boundary -- refusing is safer than rewriting, because a rewrite
  silently changes who the record is about.
* **Records are encoded with length-prefixed fields** before hashing, so the bytes
  that are hashed are unambiguous by construction rather than by trusting an escaper.
* **The line itself is still canonical JSON** with ``ensure_ascii`` off but every
  control character escaped, so the file remains a normal JSONL file an operator can
  read with ``jq``.

2. The chain must be signed, and its head exportable
---------------------------------------------------
An unkeyed hash chain catches edits but not a full rewrite: recompute every hash and
it verifies cleanly. Measured on the Phase 2 code, a forged 4-record chain verified
``(True, 4)`` and a truncated one verified ``(True, 1)``.

* **Every append is signed** with ML-DSA-65 over the new head, and the signature is
  stored in the same record. Rewriting history now requires the signing key.
* **The head digest can be exported** (``log_head``) for an operator to keep outside
  the state directory. Verifying against a remembered head is what catches
  *truncation* and whole-file rewrite -- the chain alone cannot, because a shorter
  valid chain is still a valid chain.
* **Blunt limit:** someone who can rewrite the file **and** read the signing key
  sitting in the same directory is undetectable by any of this. There is no external
  anchor by default, no append-only remote sink, and no transparency log. A deployment
  that needs that property must ship the head somewhere the attacker cannot write.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from . import dsa

LOG_MAGIC = "pqc-kv-eventlog"
LOG_VERSION = 1
GENESIS = "0" * 64

#: Conservative identifier policy. Deliberately excludes newlines, quotes, control
#: characters, and every non-ASCII script -- including Cyrillic/Greek look-alikes,
#: which are the classic way to make "maya" in a log look like a different actor.
MAX_ID_LEN = 96
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:#-]*$")

ALLOWED_ACTIONS = frozenset({
    "read", "revoke", "rotate", "recover", "restore", "backup",
    "enrol", "policy", "setup", "message",
})


class LogError(Exception):
    """One failure type for log problems. Never carries the offending value back."""

    def __init__(self, reason: str = "log_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


class Reason:
    BAD_IDENTIFIER = "identifier_rejected"
    BAD_ACTION = "action_rejected"
    MALFORMED = "record_malformed"
    BROKEN_CHAIN = "chain_broken"
    BAD_SIGNATURE = "record_bad_signature"


def validate_identifier(value, *, field: str = "identifier") -> str:
    """Accept or refuse. Never rewrites, never truncates, never normalises.

    Returning a cleaned-up value would be worse than failing: two distinct callers
    could collapse into one name, and the log would be quietly wrong.
    """
    if not isinstance(value, str):
        # None, 0, [] and friends are refused rather than treated as "absent":
        # a missing actor is spelled "" deliberately, and guessing is how a
        # malformed request becomes a record about nobody in particular.
        raise LogError(Reason.BAD_IDENTIFIER)
    # An empty string means "absent", which real system events need: a rotation has
    # no actor. It is a distinct case from a malformed value, and it cannot smuggle
    # anything because there is nothing in it.
    if value == "":
        return ""
    if len(value) > MAX_ID_LEN:
        raise LogError(Reason.BAD_IDENTIFIER)
    if not _ID_RE.match(value):
        raise LogError(Reason.BAD_IDENTIFIER)
    return value


def classify(text: str) -> str:
    """Answer 'would this be accepted?' without raising. Used by the fuzz tests."""
    try:
        validate_identifier(text)
    except LogError:
        return "rejected"
    return "accepted"


def validate_action(action) -> str:
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        raise LogError(Reason.BAD_ACTION)
    return action


# --------------------------------------------------------------- encoding
def _length_prefixed(fields: dict) -> bytes:
    """Unambiguous bytes for hashing: every key and value length-prefixed.

    This is what makes the hash independent of any escaping scheme. Two different
    field layouts can never produce the same byte string, so no value can impersonate
    a boundary even in principle.
    """
    out = []
    for key in sorted(fields):
        raw_key = str(key).encode("utf-8")
        raw_val = str(fields[key]).encode("utf-8", "surrogatepass")
        out.append(len(raw_key).to_bytes(4, "big") + raw_key)
        out.append(len(raw_val).to_bytes(4, "big") + raw_val)
    return b"".join(out)


def encode_line(record: dict) -> str:
    """One canonical JSON line. Control characters escaped; no bare newlines."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_hash(record: dict) -> str:
    """Hash of the record's signed content. `hash` and `sig` are not part of it."""
    body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return hashlib.sha256(_length_prefixed(body)).hexdigest()


class EventLog:
    """Append-only, hash-chained, per-record signed event log."""

    def __init__(self, path: Path, signing_key, signing_public: bytes) -> None:
        self.path = Path(path)
        self.signing_key = signing_key
        self.signing_public = signing_public
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- read
    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                raise LogError(Reason.MALFORMED) from None
        return out

    def head(self) -> tuple[str, int]:
        records = self.records()
        if not records:
            return GENESIS, 0
        return records[-1]["hash"], len(records)

    # --------------------------------------------------------------- write
    def append(self, *, action: str, actor: str, detail: str = "") -> dict:
        """Append one signed record. Validates every caller-supplied string first."""
        validate_action(action)
        # Always validate. `""` is the documented way to say "no actor"; anything
        # non-string -- including None -- is refused by validate_identifier. Using
        # truthiness here would have let 0 and [] through as "absent".
        actor = validate_identifier(actor, field="actor")
        detail = validate_identifier(detail, field="detail")

        prev, seq = self.head()
        fields = {
            "magic": LOG_MAGIC,
            "version": LOG_VERSION,
            "seq": seq + 1,
            "prev": prev,
            "action": action,
            "actor": actor,
            "detail": detail,
        }
        digest = hashlib.sha256(_length_prefixed(fields)).hexdigest()
        signature = dsa.sign(self.signing_key, _length_prefixed(fields))

        record = dict(fields, hash=digest, sig=_b64(signature))
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(encode_line(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    # -------------------------------------------------------------- verify
    def verify(self, *, expected_head: str | None = None) -> dict:
        """Walk the chain, recheck every hash and signature.

        Returns ``{"ok": bool, "records": n, "first_bad": index|None,
        "reason": str|None}``. ``first_bad`` is 1-based so it lines up with `seq`.
        """
        try:
            records = self.records()
        except LogError:
            return {"ok": False, "records": 0, "first_bad": 1, "reason": Reason.MALFORMED}

        prev = GENESIS
        for index, record in enumerate(records, start=1):
            try:
                claimed_hash = record["hash"]
                claimed_sig = _unb64(record["sig"])
                body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
            except (KeyError, TypeError):
                return {"ok": False, "records": len(records), "first_bad": index,
                        "reason": Reason.MALFORMED}

            if record.get("seq") != index:
                return {"ok": False, "records": len(records), "first_bad": index,
                        "reason": Reason.BROKEN_CHAIN}
            if record.get("prev") != prev:
                return {"ok": False, "records": len(records), "first_bad": index,
                        "reason": Reason.BROKEN_CHAIN}

            expected_hash = hashlib.sha256(_length_prefixed(body)).hexdigest()
            if expected_hash != claimed_hash:
                return {"ok": False, "records": len(records), "first_bad": index,
                        "reason": Reason.BROKEN_CHAIN}

            if not dsa.verify(self.signing_public, _length_prefixed(body), claimed_sig):
                return {"ok": False, "records": len(records), "first_bad": index,
                        "reason": Reason.BAD_SIGNATURE}

            prev = claimed_hash

        if expected_head is not None and prev != expected_head:
            # The chain is internally perfect but does not end where the operator
            # remembers: this is truncation (or a rewrite by the key holder).
            return {"ok": False, "records": len(records), "first_bad": len(records) + 1,
                    "reason": "head_mismatch", "actual_head": prev}

        return {"ok": True, "records": len(records), "first_bad": None, "reason": None}


def _b64(value: bytes) -> str:
    import base64

    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    import base64

    return base64.b64decode(str(value).encode("ascii"), validate=True)


def atomic_write_text(path: Path, text: str) -> None:
    fd, name = tempfile.mkstemp(dir=str(Path(path).parent), prefix=".log-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        name = None
    finally:
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass


__all__ = [
    "ALLOWED_ACTIONS", "EventLog", "GENESIS", "LogError", "Reason",
    "atomic_write_text", "classify", "encode_line", "record_hash",
    "validate_action", "validate_identifier",
]
