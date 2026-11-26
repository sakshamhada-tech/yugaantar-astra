"""Handshake ephemeral secrets: initiator-only, single-use, erased at the end.

Why this file exists at all: the adapter runs **one process per request**, so a
multi-step handshake needs the initiator's ephemeral secrets to outlive the
process that generated them. The responder does not: it finishes the handshake
inside the one request that receives the hello, so it never writes an ephemeral
secret to disk.

Design rules, from the brief and from the adapter contract:

* **Only the initiator persists.** The responder keeps its ephemerals in local
  variables and lets them die with the process.
* **Plaintext, 0600, in the private state dir.** We do not wrap them under the
  long-term key. Wrapping would protect nothing against the only attacker who can
  reach them (someone with read access to the state dir, who can also read the
  long-term key) while implying a protection we do not have.
* **Single use.** Records are keyed by handshake id and consumed exactly once;
  consuming unlinks the file.
* **Erased the moment the session key exists**: overwrite the bytes, unlink, then
  fsync the directory so the removal is durable.
* **Bounded**: a cap on pending handshakes, and stale ones are pruned at the next
  handshake. No clock is trusted, so "stale" means "oldest by creation order",
  not "older than N seconds".

The honest limit, which belongs in SECURITY_NOTES verbatim: overwriting a file
does not erase it from the underlying device. On journaling filesystems
(ext4, APFS) and SSDs with wear levelling, the old blocks can survive. We delete
the *reference*, not the *history*.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..keystore import (
    b64d,
    b64e,
    ensure_private_dir,
    read_key_file,
    write_key_file,
)
from .. import hybrid

MAX_PENDING_HANDSHAKES = 32  # bound: the initiator cannot accumulate open attempts
EPHEMERAL_MAGIC = "pqc-kv-ephemeral"
EPHEMERAL_VERSION = 1


class EphemeralError(Exception):
    """Ephemeral record problem. Never contains secret bytes."""


def _dir(root: Path) -> Path:
    return ensure_private_dir(Path(root) / "pqc-kv-messaging" / "ephemeral")


def _path(root: Path, handshake_id: str) -> Path:
    return _dir(root) / f"hs-{_safe(handshake_id)}.json"


def _safe(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value))
    if not cleaned:
        raise EphemeralError("malformed handshake id")
    return cleaned[:80]


def save(
    root: Path,
    handshake_id: str,
    *,
    x25519_secret: bytes,
    mlkem_secret: bytes,
    peer_user: str,
    peer_fp: str,
) -> None:
    """Persist the initiator's ephemeral secrets for the second handshake step.

    Creates the file with 0600 via the Phase 1 keystore writer (atomic + fsync),
    so a crash mid-write cannot leave a half-record that looks usable.
    """
    payload = {
        # NOTE: keystore.write_key_file stamps its own "magic"/"key_version"; our
        # own marker lives in a distinct field so neither clobbers the other.
        "record": EPHEMERAL_MAGIC,
        "record_version": EPHEMERAL_VERSION,
        "handshake_id": str(handshake_id),
        "peer_user": str(peer_user),
        "peer_fp": str(peer_fp),
        # The X25519 secret is stored in the backend-native form hybrid uses
        # (raw bytes for `cryptography`, PEM bytes for pycryptodome).
        "x25519_secret": b64e(x25519_secret),
        "mlkem_secret": b64e(mlkem_secret),
    }
    write_key_file(_path(root, handshake_id), payload)
    # Prune *after* writing: the cap applies to the set we just grew. Pruning
    # before each save would evict one extra record per call.
    prune(root)


def load(root: Path, handshake_id: str) -> dict:
    path = _path(root, handshake_id)
    if not path.exists():
        raise EphemeralError("no pending handshake")
    try:
        data = read_key_file(path)
    except Exception:
        # keystore raises KeyStoreError for corrupt/permission problems; callers of
        # this module must only need to handle one failure type.
        raise EphemeralError("ephemeral record unreadable") from None
    if data.get("record") != EPHEMERAL_MAGIC or data.get("record_version") != EPHEMERAL_VERSION:
        raise EphemeralError("ephemeral record not recognised")
    try:
        return {
            "handshake_id": data["handshake_id"],
            "peer_user": data["peer_user"],
            "peer_fp": data["peer_fp"],
            "x25519_secret": b64d(data["x25519_secret"]),
            "mlkem_secret": b64d(data["mlkem_secret"]),
        }
    except Exception:
        raise EphemeralError("ephemeral record corrupt") from None


def erase(root: Path, handshake_id: str) -> bool:
    """Overwrite, unlink, fsync the directory. Returns True if a file was removed.

    Best effort by design: the residual-copy limit is documented, not hidden.
    """
    try:
        path = _path(root, handshake_id)
    except EphemeralError:
        return False
    if not path.exists():
        return False
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass  # overwrite is best effort; unlinking below is what matters
    try:
        path.unlink()
    except OSError:
        raise EphemeralError("cannot remove ephemeral record") from None
    _fsync_dir(path.parent)
    return True


def pending(root: Path) -> list[str]:
    """Handshake ids currently waiting for their second step."""
    directory = _dir(root)
    return sorted(p.stem[3:] for p in directory.glob("hs-*.json"))


def pending_count(root: Path) -> int:
    return len(pending(root))


def prune(root: Path, keep: int = MAX_PENDING_HANDSHAKES) -> None:
    """Drop the oldest pending handshakes beyond ``keep``.

    No clock: ordering is by filesystem mtime *only* to pick a victim among
    records we already consider abandonable, and ties fall back to name order.
    Being wrong here costs a retried handshake, never a leaked key.
    """
    directory = _dir(root)
    records = list(directory.glob("hs-*.json"))
    if len(records) <= keep:
        return
    # (mtime, name) keeps this deterministic: sequential ids tie-break by name,
    # which is creation order. Being wrong costs a retried handshake, never a key.
    records.sort(key=lambda p: (p.stat().st_mtime, p.name))
    for stale in records[: len(records) - keep]:
        try:
            erase(root, stale.stem[3:])
        except EphemeralError:
            pass


def purge_all(root: Path) -> int:
    """Erase every pending handshake. Used by setup and by tests."""
    removed = 0
    for handshake_id in pending(root):
        if erase(root, handshake_id):
            removed += 1
    return removed


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


def self_check() -> dict:
    """Describe the state dir this module would use. No secrets, for diagnostics."""
    return {
        "max_pending": MAX_PENDING_HANDSHAKES,
        "initiator_only": True,
        "x25519_len": hybrid.X25519_LEN,
    }


__all__ = [
    "EphemeralError",
    "MAX_PENDING_HANDSHAKES",
    "erase",
    "load",
    "pending",
    "pending_count",
    "prune",
    "purge_all",
    "save",
    "self_check",
]
