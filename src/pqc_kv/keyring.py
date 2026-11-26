"""Versioned service key ring with a documented, clock-free cutoff.

What this replaces
------------------
Phase 1's ``setup()`` deleted every key and re-sealed everything: a demolition, not
a rotation. That is fine for a one-shot demo and useless for goal 1, which asks for
a rotation where authorized reads keep working *during and after* the change.

The picture
-----------
A key ring is a numbered list of service keys. Each entry has:

    version   an integer, monotonically increasing, never reused
    state     active | retiring | retired | revoked
    kem/dsa   the actual ML-KEM-768 and ML-DSA-65 keypair files for that version

    active    new writes seal under this version
    retiring  still accepted for reads; no new writes; grace budget counting down
    retired   rejected outright
    revoked   rejected outright, and treated as compromised

Why a *ring* and not "the key"
-----------------------------
Data that was sealed under version 1 must stay readable after we start sealing under
version 2. So the ring keeps the old key material around until it is explicitly
retired, and every asset records which version sealed it. An asset is re-wrapped
(decrypt with its recorded version, re-seal with the active version) during
rotation, so the ring never has to hold key material indefinitely.

The cutoff, expressed without a clock
-------------------------------------
Hard rule for this project: wall-clock time never decides access. So the grace
period after a rotation is **a count of accepted requests**, not seconds:

    epoch   integer, increments every time a request is *authorized* against a
            retiring version (i.e. the ring served a read using the old key)
    grace   a small configured integer (default 2)

    epoch <  grace   old-version request ACCEPTED   (in-flight work finishes)
    epoch >= grace   old-version request REJECTED, version flips to retired

Both sides of that boundary are tested. The counter lives in the ring file and is
incremented under the store's flock, so two concurrent processes cannot both
observe ``epoch = grace - 1`` and both be accepted.

A blunt note on persistence
---------------------------
The epoch is per node and stored in the state directory. An attacker who can write
the state directory can reset it, just as they can reset the revocation high-water
mark. That is the documented trust boundary, not an oversight -- see SECURITY_NOTES.

Device keys vs service keys
---------------------------
These are deliberately **separate key sets**. Service keys are rotated and retired;
device keys are revoked and re-enrolled. They share this versioning code
(``VersionedKeys``) but never share a file namespace or a state list, so retiring a
service key can never look like revoking a device. See ``keysets.py``.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from . import dsa, kem
from .keystore import b64d, b64e, ensure_private_dir, read_key_file, write_key_file

RING_MAGIC = "pqc-kv-keyring"
RING_VERSION = 1
DEFAULT_GRACE = 2
MAX_VERSION = 1_000_000

ACTIVE = "active"
RETIRING = "retiring"
RETIRED = "retired"
REVOKED = "revoked"
STATES = (ACTIVE, RETIRING, RETIRED, REVOKED)


class KeyRingError(Exception):
    """One failure type. Never contains key material."""


@dataclass(frozen=True)
class KeyEntry:
    version: int
    state: str
    epoch: int = 0
    grace: int = DEFAULT_GRACE
    kem_file: str = ""
    dsa_file: str = ""

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "state": self.state,
            "epoch": self.epoch,
            "grace": self.grace,
            "kem_file": self.kem_file,
            "dsa_file": self.dsa_file,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KeyEntry":
        try:
            entry = cls(
                version=int(data["version"]),
                state=str(data["state"]),
                epoch=int(data["epoch"]),
                grace=int(data["grace"]),
                kem_file=str(data["kem_file"]),
                dsa_file=str(data["dsa_file"]),
            )
        except (KeyError, TypeError, ValueError):
            raise KeyRingError("key ring entry malformed") from None
        if entry.state not in STATES:
            raise KeyRingError("key ring entry has an unknown state")
        if not 1 <= entry.version <= MAX_VERSION:
            raise KeyRingError("key ring version out of range")
        return entry

    def accepts_reads(self) -> bool:
        """active and retiring can serve reads; retired and revoked cannot."""
        return self.state in (ACTIVE, RETIRING)

    def is_in_grace(self) -> bool:
        return self.state == RETIRING and self.epoch < self.grace


class KeyRing:
    """The on-disk ring plus the key material it points at.

    All mutations go through :meth:`mutate`, which takes the caller's lock (the
    store's flock) so read-modify-write cannot interleave across processes.
    """

    def __init__(self, root: Path) -> None:
        self.root = ensure_private_dir(Path(root))
        self.keys_dir = ensure_private_dir(self.root / "keys")
        self.path = self.root / "keyring.json"

    # ------------------------------------------------------------------ state
    def load(self) -> dict:
        if not self.path.exists():
            return {
                "magic": RING_MAGIC,
                "version": RING_VERSION,
                "entries": [],
            }
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise KeyRingError("key ring unreadable") from None
        if not isinstance(data, dict) or data.get("magic") != RING_MAGIC:
            raise KeyRingError("key ring is not a pqc-kv key ring")
        if data.get("version") != RING_VERSION:
            raise KeyRingError("unsupported key ring version")
        entries = []
        for raw in data.get("entries") or []:
            entries.append(KeyEntry.from_dict(raw))
        if not isinstance(entries, list):
            raise KeyRingError("key ring entries malformed")
        return {"magic": RING_MAGIC, "version": RING_VERSION, "entries": entries}

    def save(self, ring: dict) -> None:
        payload = {
            "magic": RING_MAGIC,
            "version": RING_VERSION,
            "entries": [entry.to_dict() for entry in ring["entries"]],
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        fd, name = tempfile.mkstemp(dir=str(self.root), prefix=".keyring-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.path)
            name = None
            _fsync_dir(self.root)
        except OSError:
            raise KeyRingError("cannot write key ring") from None
        finally:
            if name is not None:
                try:
                    os.unlink(name)
                except OSError:
                    pass

    # -------------------------------------------------------------- selection
    def active(self, ring: dict | None = None) -> KeyEntry:
        ring = ring if ring is not None else self.load()
        for entry in ring["entries"]:
            if entry.state == ACTIVE:
                return entry
        raise KeyRingError("key ring has no active version")

    def by_version(self, ring: dict, version: int) -> KeyEntry:
        for entry in ring["entries"]:
            if entry.version == version:
                return entry
        raise KeyRingError("unknown key version")

    def latest(self, ring: dict | None = None) -> KeyEntry:
        ring = ring if ring is not None else self.load()
        if not ring["entries"]:
            raise KeyRingError("key ring is empty")
        return max(ring["entries"], key=lambda entry: entry.version)

    # ------------------------------------------------------------------ create
    def create_initial(self, grace: int = DEFAULT_GRACE) -> KeyEntry:
        """Make version 1. Used by ``setup`` and by first upgrade from Phase 1."""
        ring = self.load()
        if ring["entries"]:
            raise KeyRingError("key ring already initialised")
        entry = self._make_entry(version=1, state=ACTIVE, grace=grace)
        ring["entries"].append(entry)
        self.save(ring)
        return entry

    def rotate(self, grace: int = DEFAULT_GRACE) -> tuple[KeyEntry, KeyEntry]:
        """Create version N+1 and put N into ``retiring`` with a grace budget.

        Returns ``(old_entry, new_entry)``. The caller is responsible for re-wrapping
        asset data; that ordering (seal the new version first, then flip the old one)
        is what makes an interrupted rotation recoverable.
        """
        ring = self.load()
        old = self.active(ring)
        version = self.latest(ring).version + 1
        if version > MAX_VERSION:
            raise KeyRingError("key ring exhausted")
        new = self._make_entry(version=version, state=ACTIVE, grace=0)
        retiring = replace(old, state=RETIRING, epoch=0, grace=grace)
        entries = [retiring if e.version == old.version else e for e in ring["entries"]]
        entries.append(new)
        ring["entries"] = entries
        self.save(ring)
        return retiring, new

    def _make_entry(self, *, version: int, state: str, grace: int) -> KeyEntry:
        kem_file = f"kem-service-v{version}.key"
        dsa_file = f"dsa-service-v{version}.key"
        self._ensure_kem(version)
        self._ensure_dsa(version)
        return KeyEntry(
            version=version, state=state, epoch=0, grace=grace,
            kem_file=kem_file, dsa_file=dsa_file,
        )

    # ------------------------------------------------------------ key material
    def kem_pair(self, version: int):
        path = self.keys_dir / f"kem-service-v{version}.key"
        data = read_key_file(path)
        return kem.KemKeyPair(public_key=b64d(data["public_key"]), secret_key=b64d(data["secret_key"]))

    def dsa_pair(self, version: int):
        path = self.keys_dir / f"dsa-service-v{version}.key"
        data = read_key_file(path)
        return dsa.SigningKeyPair(
            public_key=b64d(data["public_key"]), secret_key=b64d(data["secret_key"])
        )

    def _ensure_kem(self, version: int) -> None:
        path = self.keys_dir / f"kem-service-v{version}.key"
        if path.exists():
            return
        pair = kem.generate_keypair()
        write_key_file(path, {
            "kind": "ml-kem-768",
            "label": f"service-v{version}",
            # NOT `key_version`: write_key_file stamps that field with the file
            # *format* version and would clobber ours. Use a distinct name.
            "ring_version": version,
            "public_key": b64e(pair.public_key),
            "secret_key": b64e(pair.secret_key),
        })

    def _ensure_dsa(self, version: int) -> None:
        path = self.keys_dir / f"dsa-service-v{version}.key"
        if path.exists():
            return
        pair = dsa.generate_keypair()
        write_key_file(path, {
            "kind": "ml-dsa-65",
            "label": f"service-v{version}",
            "ring_version": version,
            "public_key": b64e(pair.public_key),
            "secret_key": b64e(pair.secret_key),
        })

    def key_files(self) -> list[str]:
        return sorted(p.name for p in self.keys_dir.glob("*.key"))

    # ------------------------------------------------------------------ cutoff
    def admit_read(self, version: int) -> tuple[bool, dict]:
        """Decide whether a read may use ``version``, and charge the grace budget.

        Returns ``(allowed, ring_after)`` so the caller can persist the updated ring
        inside the same lock. Charging happens only on acceptance, so a rejected
        request cannot exhaust another caller's grace.
        """
        ring = self.load()
        entry = self.by_version(ring, version)
        if entry.state == ACTIVE:
            return True, ring
        if entry.state in (RETIRED, REVOKED):
            return False, ring
        # retiring
        if entry.epoch >= entry.grace:
            # Budget was already spent: refuse and make the retirement permanent.
            ring = self._set_state(ring, version, RETIRED)
            return False, ring
        aged = replace(entry, epoch=entry.epoch + 1)
        ring["entries"] = [
            aged if e.version == version else e for e in ring["entries"]
        ]
        return True, ring

    def _set_state(self, ring: dict, version: int, state: str) -> dict:
        ring["entries"] = [
            replace(e, state=state) if e.version == version else e for e in ring["entries"]
        ]
        return ring

    def retire(self, version: int) -> dict:
        ring = self.load()
        self.by_version(ring, version)
        ring = self._set_state(ring, version, RETIRED)
        self.save(ring)
        return ring

    def revoke_version(self, version: int) -> dict:
        ring = self.load()
        self.by_version(ring, version)
        ring = self._set_state(ring, version, REVOKED)
        self.save(ring)
        return ring

    def summary(self) -> dict:
        """Public description of the ring. No key material, ever."""
        ring = self.load()
        return {
            "active_version": self.active(ring).version if ring["entries"] else 0,
            "versions": [
                {
                    "version": e.version,
                    "state": e.state,
                    "epoch": e.epoch,
                    "grace": e.grace,
                }
                for e in sorted(ring["entries"], key=lambda e: e.version)
            ],
        }


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
    "ACTIVE", "DEFAULT_GRACE", "KeyEntry", "KeyRing", "KeyRingError",
    "RETIRED", "RETIRING", "REVOKED", "STATES",
]
