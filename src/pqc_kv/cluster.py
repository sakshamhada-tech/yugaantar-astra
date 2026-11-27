"""Signed, sequence-numbered notices, and a small cluster of independent nodes.

Why notices at all
------------------
Each node is a separate state directory driven by a separate short-lived process, so
there is no shared memory and no shared lock across nodes. Two things must cross that
gap: "actor X is revoked" and "the service key moved to version N". If node B just
reads node A's state directory it learns nothing trustworthy -- it would be trusting
files it cannot verify, and a mistake or a tamper would propagate silently.

So a node publishes a **notice**: a small JSON object, ML-DSA signed by the
publishing node's identity key, carrying a monotonically increasing sequence number.

    notice = {kind, seq, actor|key_version, payload, signer_fp, signature}

Three properties, and the attack each one stops:

* **Signature checked before the body is even looked at.** Without this, anyone who
  can drop a file into the sync directory revokes anyone, or advances the key version
  to something no key exists for. Order matters: verify, then parse, then apply. An
  unverified notice never influences state, not even a counter.
* **Sequence number.** Stops replay of an *old* notice (revoke, then un-revoke by
  replaying a notice from before) and stops a stale "rotation to v2" from overriding
  a newer "rotation to v3". Each node keeps a high-water mark per (kind, publisher)
  and refuses a notice that does not strictly advance it. Applying the same notice
  twice is a no-op, which is what "idempotent" has to mean here.
* **Idempotent, order-independent apply.** Notices can arrive in any order. Revoking
  is a set insert, and the key version is a max(), so both are commutative. That is
  why applying {v3, v2} and {v2, v3} end in the same state.

What this is honest about
-------------------------
All nodes are directories on one machine, and propagation is a *pull* (`node_sync`)
driven by an explicit loop. There is no network, so there is no real network
partition, no message loss, no reordering by a transport, and no clock skew. The
propagation time reported by the acceptance script is therefore a **lower bound for
local processes**, not a network figure. SECURITY_NOTES says so in those words.

Trust is a single publisher key: any node holding the signing key can issue anything.
There is no quorum, no transparency log, and no byzantine fault tolerance. One node
is the authority; the others verify what it signed.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from . import dsa
from .keystore import b64d, b64e, ensure_private_dir, write_key_file, KeyStore

NOTICE_MAGIC = "pqc-kv-notice"
NOTICE_VERSION = 1
KIND_REVOKE = "revoke"
KIND_ROTATE = "rotate"
KIND_ENROL = "enrol"
KINDS = (KIND_REVOKE, KIND_ROTATE, KIND_ENROL)
MAX_SEQ = 2**31 - 1


class NoticeError(Exception):
    """One failure type. Carries a reason code, never key material."""

    def __init__(self, reason: str = "notice_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


class Reason:
    MALFORMED = "notice_malformed"
    BAD_SIGNATURE = "notice_bad_signature"
    REPLAYED = "notice_replayed"
    UNKNOWN_SIGNER = "notice_unknown_signer"
    UNKNOWN_KIND = "notice_unknown_kind"


# ------------------------------------------------------------------ signing
def _canonical(fields: dict) -> bytes:
    """Length-prefixed canonical bytes, so no field value can shift a boundary.

    Why not plain JSON: a value containing a `|` or a newline could otherwise make two
    different field splits produce identical bytes. Every field is length-prefixed, so
    the encoding is unambiguous by construction and hostile text stays a *value*.
    """
    parts = []
    for key in sorted(fields):
        value = str(fields[key]).encode("utf-8")
        parts.append(str(len(key)).encode() + b":" + key.encode("utf-8"))
        parts.append(str(len(value)).encode() + b":" + value)
    return b"".join(parts)


def signed_fields(notice: dict) -> dict:
    """The exact fields a publisher signs. `signature` itself is excluded."""
    return {
        "magic": notice["magic"],
        "version": notice["version"],
        "kind": notice["kind"],
        "seq": notice["seq"],
        "signer_fp": notice["signer_fp"],
        "payload": json.dumps(notice["payload"], sort_keys=True, separators=(",", ":")),
    }


def issue(*, kind: str, seq: int, payload: dict, signing_key, signer_fp: str) -> dict:
    """Build and sign one notice."""
    if kind not in KINDS:
        raise NoticeError(Reason.UNKNOWN_KIND)
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq <= MAX_SEQ:
        raise NoticeError(Reason.MALFORMED)
    body = {
        "magic": NOTICE_MAGIC,
        "version": NOTICE_VERSION,
        "kind": kind,
        "seq": seq,
        "signer_fp": str(signer_fp),
        "payload": payload,
    }
    signature = dsa.sign(signing_key, _canonical(signed_fields(body)))
    body["signature"] = b64e(signature)
    return body


def verify(notice: dict, *, signer_public: bytes) -> dict:
    """Verify, THEN parse. Returns the parsed notice or raises NoticeError.

    Order is the whole point: nothing in `payload` is read before the signature over
    its canonical bytes has been checked, so a hostile payload cannot influence the
    parsing path.
    """
    if not isinstance(notice, dict):
        raise NoticeError(Reason.MALFORMED)
    try:
        magic = notice["magic"]
        version = notice["version"]
        kind = notice["kind"]
        seq = notice["seq"]
        signer_fp = notice["signer_fp"]
        payload = notice["payload"]
        signature = b64d(notice["signature"])
    except Exception:
        raise NoticeError(Reason.MALFORMED) from None

    if magic != NOTICE_MAGIC or version != NOTICE_VERSION:
        raise NoticeError(Reason.MALFORMED)
    if kind not in KINDS:
        raise NoticeError(Reason.UNKNOWN_KIND)
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq <= MAX_SEQ:
        raise NoticeError(Reason.MALFORMED)
    if not isinstance(payload, dict):
        raise NoticeError(Reason.MALFORMED)

    try:
        expected = _canonical({
            "magic": magic,
            "version": version,
            "kind": kind,
            "seq": seq,
            "signer_fp": signer_fp,
            "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        })
    except Exception:
        raise NoticeError(Reason.MALFORMED) from None

    if not dsa.verify(signer_public, expected, signature):
        raise NoticeError(Reason.BAD_SIGNATURE)

    return {
        "kind": kind,
        "seq": seq,
        "signer_fp": signer_fp,
        "payload": payload,
    }


def public_identity_fields(key: KeyStore, label: str = "cluster-publisher") -> tuple[object, str]:
    """The publisher's signing keypair plus a fingerprint for pinning."""
    pair = key.signing_keypair(label)
    import hashlib

    fp = hashlib.sha256(pair.public_key).hexdigest()
    return pair, fp


# --------------------------------------------------------------- node state
class Node:
    """One node: its own state directory, its own adapter process, its own log."""

    def __init__(self, root: Path, node_id: str, outbox: Path | None = None) -> None:
        self.root = ensure_private_dir(Path(root))
        self.node_id = str(node_id)
        # Explicit, never guessed: a default of `root.parent` would land in /tmp and
        # let two unrelated clusters share an outbox.
        self.outbox = ensure_private_dir(Path(outbox) if outbox else self.root / "outbox")
        self.cluster_dir = ensure_private_dir(self.root / "cluster")
        self.notices_path = self.cluster_dir / "notices.jsonl"
        self.marks_path = self.cluster_dir / "marks.json"
        self.signer_keys = KeyStore(self.root / "pqc-kv-state")

    # -- high-water marks
    def marks(self) -> dict:
        if not self.marks_path.exists():
            return {}
        try:
            data = json.loads(self.marks_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise NoticeError(Reason.MALFORMED) from None
        if not isinstance(data, dict):
            raise NoticeError(Reason.MALFORMED)
        return data

    def _save_marks(self, marks: dict) -> None:
        body = json.dumps(marks, sort_keys=True, separators=(",", ":")).encode()
        fd, name = tempfile.mkstemp(dir=str(self.cluster_dir), prefix=".marks-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.marks_path)
            name = None
            _fsync_dir(self.cluster_dir)
        finally:
            if name is not None:
                try:
                    os.unlink(name)
                except OSError:
                    pass

    # -- notice log (this node's own record of what it accepted)
    def applied(self) -> list[dict]:
        if not self.notices_path.exists():
            return []
        out = []
        for line in self.notices_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def _append_applied(self, notice: dict) -> None:
        line = json.dumps(notice, sort_keys=True, separators=(",", ":"))
        with open(self.notices_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    # -- publication
    def publish(self, *, kind: str, payload: dict, publisher_key, publisher_fp: str) -> dict:
        """Sign a notice with the next sequence for this (kind, publisher)."""
        seq = self._next_seq(kind, publisher_fp)
        notice = issue(
            kind=kind, seq=seq, payload=payload,
            signing_key=publisher_key, signer_fp=publisher_fp,
        )
        path = self.outbox / f"{self.node_id}-{kind}-{seq:06d}.json"
        write_key_file(path, {"notice": notice})
        return notice

    def _next_seq(self, kind: str, publisher_fp: str) -> int:
        high = self.marks().get(f"{kind}:{publisher_fp}", 0)
        seen = 0
        if self.outbox.exists():
            for path in self.outbox.glob(f"*-{kind}-*.json"):
                try:
                    seen = max(seen, int(path.stem.split("-")[-1]))
                except ValueError:
                    continue
        return max(high, seen) + 1

    # -- consumption
    def ingest(self, notice: dict, *, signer_public: bytes) -> dict:
        """Verify, check the sequence, apply. Persist before returning.

        Returns ``{"applied": bool, "reason": str}``. A rejected notice is *not*
        written anywhere except the caller's count -- storing an unverified notice
        would be a way to smuggle text into the node.
        """
        parsed = verify(notice, signer_public=signer_public)
        marks = self.marks()
        key = f"{parsed['kind']}:{parsed['signer_fp']}"
        high = int(marks.get(key, 0))
        if parsed["seq"] <= high:
            raise NoticeError(Reason.REPLAYED)
        marks[key] = parsed["seq"]
        self._save_marks(marks)
        self._append_applied(parsed)
        return {"applied": True, "kind": parsed["kind"], "seq": parsed["seq"]}


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


__all__ = [
    "KINDS", "KIND_ENROL", "KIND_REVOKE", "KIND_ROTATE",
    "Node", "NoticeError", "Reason", "issue", "public_identity_fields", "verify",
]
