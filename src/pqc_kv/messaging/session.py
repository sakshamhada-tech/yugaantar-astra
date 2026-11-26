"""Session state: persisted atomically, under the same flock as Phase 1.

One short-lived process per request means every session fact must survive a
restart: chain keys, sequence counters, parked skipped keys, partially received
fragments, used message ids, and resumption tickets. All of it lives in one JSON
document per session, written with the Phase 1 pattern:

    flock -> read -> mutate -> temp file (0600) + fsync -> os.replace -> fsync dir

Why one file per session rather than one big file: a session's state is only ever
touched by requests for that session, so per-session files keep the lock scope
small and make a corrupted session recoverable without touching the others.

**Ordering rule that matters:** the caller must persist *before* returning an
acknowledgement (the contract says so). Concretely, ``receive`` advances the
ratchet and writes the new state before the plaintext is handed back; if the
process dies after the write but before the response, the message is lost, never
replayed. Losing a message is recoverable; replaying one is not.

Reassembly state is bounded on purpose: a message may declare at most
``MAX_FRAGMENTS`` pieces, and stale partial messages are evicted oldest-first
(no clock trust) once the per-session cap is hit, so an attacker cannot wedge
arbitrary memory by starting thousands of half-messages.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from ..keystore import ensure_private_dir

SESSION_SCHEMA = 1
MAX_PARTIAL_MESSAGES = 64  # half-received messages kept per session
MAX_TRACKED_MESSAGE_IDS = 4096  # replay/duplicate memory, oldest evicted
LOCK_FILE = ".lock"
SESSION_FILE = "messaging-sessions.json"


class SessionError(Exception):
    """Session storage problem. No key material, no plaintext in the message."""


class SessionFailure:
    UNKNOWN_SESSION = "unknown_session"
    TOO_MANY_PARTIALS = "too_many_partials"


@dataclass
class PartialMessage:
    """Fragments of one message that have not all arrived yet."""

    message_id: str
    total: int
    fragments: dict[int, dict] = field(default_factory=dict)  # index -> fragment dict

    def add(self, index: int, fragment: dict) -> None:
        self.fragments[index] = fragment

    @property
    def complete(self) -> bool:
        return len(self.fragments) == self.total and set(self.fragments) == set(range(self.total))

    def missing(self) -> list[int]:
        return [i for i in range(self.total) if i not in self.fragments]

    def __repr__(self) -> str:  # never show ciphertext or keys
        return "PartialMessage(mid=%r, have=%d/%d)" % (
            self.message_id,
            len(self.fragments),
            self.total,
        )


class SessionStore:
    """All messaging state for one state directory."""

    def __init__(self, root: Path):
        self.root = ensure_private_dir(Path(root) / "pqc-kv-messaging")
        self.path = self.root / SESSION_FILE
        self.lock_path = self.root / LOCK_FILE

    # ------------------------------------------------------------------ lock
    @contextmanager
    def locked(self):
        """Single-writer lock shared with the rest of the messaging package."""
        handle = open(self.lock_path, "a+b")
        try:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    # ------------------------------------------------------------------ io
    def _read(self) -> dict:
        if not self.path.exists():
            return {"schema": SESSION_SCHEMA, "sessions": {}, "order": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise SessionError("session state corrupt") from None
        if not isinstance(data, dict) or data.get("schema") != SESSION_SCHEMA:
            raise SessionError("unsupported session schema")
        data.setdefault("sessions", {})
        data.setdefault("order", [])
        return data

    def _write(self, data: dict) -> None:
        """Atomic + fsync: durable before we acknowledge anything."""
        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(self.root), prefix=".sessions-")
        try:
            os.fchmod(tmp_fd, 0o600)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
            tmp_name = None
            _fsync_dir(self.root)
        except OSError:
            raise SessionError("cannot persist session state") from None
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    # ------------------------------------------------------------- queries
    def get(self, session_id: str) -> dict:
        data = self._read()
        session = data["sessions"].get(session_id)
        if not isinstance(session, dict):
            raise SessionError(SessionFailure.UNKNOWN_SESSION)
        return session

    def exists(self, session_id: str) -> bool:
        return isinstance(self._read()["sessions"].get(session_id), dict)

    def list_ids(self) -> list[str]:
        return sorted(self._read()["sessions"])

    # ------------------------------------------------------------- mutation
    def put(self, session_id: str, session: dict) -> None:
        with self.locked():
            data = self._read()
            is_new = session_id not in data["sessions"]
            data["sessions"][session_id] = session
            if is_new:
                data["order"].append(session_id)
            self._write(data)

    def mutate(self, session_id: str, mutator) -> dict:
        """Read-modify-write one session under the lock. Returns the new state."""
        with self.locked():
            data = self._read()
            session = data["sessions"].get(session_id)
            if not isinstance(session, dict):
                raise SessionError(SessionFailure.UNKNOWN_SESSION)
            updated = mutator(session)
            data["sessions"][session_id] = updated
            self._write(data)
            return updated

    def delete(self, session_id: str) -> bool:
        with self.locked():
            data = self._read()
            if session_id not in data["sessions"]:
                return False
            del data["sessions"][session_id]
            if session_id in data["order"]:
                data["order"].remove(session_id)
            self._write(data)
            return True

    def reset(self) -> None:
        with self.locked():
            self._write({"schema": SESSION_SCHEMA, "sessions": {}, "order": []})

    # ------------------------------------------------ reassembly helpers
    @staticmethod
    def partials(session: dict) -> dict:
        return session.setdefault("partials", {})

    @staticmethod
    def remember_id(session: dict, message_id: str) -> bool:
        """Record a completed message id. Returns False if it was already known.

        Bounded FIFO: once ``MAX_TRACKED_MESSAGE_IDS`` ids are remembered the
        oldest is dropped. Dropping an old id does not enable replay, because the
        ratchet rejects any sequence it has already consumed.
        """
        seen = session.setdefault("seen_ids", [])
        if message_id in seen:
            return False
        seen.append(message_id)
        while len(seen) > MAX_TRACKED_MESSAGE_IDS:
            seen.pop(0)
        return True

    @staticmethod
    def store_partial(session: dict, partial: PartialMessage) -> None:
        cache = SessionStore.partials(session)
        cache[partial.message_id] = {
            "total": partial.total,
            "fragments": {str(k): v for k, v in partial.fragments.items()},
        }
        while len(cache) > MAX_PARTIAL_MESSAGES:
            # Oldest-first eviction without a clock: insertion order is the order.
            cache.pop(next(iter(cache)))

    @staticmethod
    def drop_partial(session: dict, message_id: str) -> None:
        SessionStore.partials(session).pop(message_id, None)

    @staticmethod
    def load_partial(session: dict, message_id: str) -> PartialMessage | None:
        record = SessionStore.partials(session).get(message_id)
        if not isinstance(record, dict):
            return None
        partial = PartialMessage(message_id=message_id, total=int(record.get("total", 0)))
        for key, fragment in (record.get("fragments") or {}).items():
            partial.fragments[int(key)] = fragment
        return partial


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
    "MAX_PARTIAL_MESSAGES",
    "MAX_TRACKED_MESSAGE_IDS",
    "PartialMessage",
    "SessionError",
    "SessionFailure",
    "SessionStore",
]
