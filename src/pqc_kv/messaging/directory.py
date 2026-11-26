"""The directory: user ID -> public identity. This is the trust anchor.

**Read this before trusting anything the messaging layer proves.**

A fingerprint proves "the holder of private key X signed this". It says nothing
about *who* X is. That binding -- user ID to key -- lives in exactly one place:
this directory. Therefore:

* if an attacker can write the directory, they can substitute their own keys and
  every signature we verify afterwards will be valid *for them*;
* the directory is a local file in the same state directory as the keys, so its
  integrity is exactly the integrity of that state directory (see
  SECURITY_NOTES: the state directory *is* the trust boundary);
* there is no PKI, no transparency log, no key pinning to an external root.

What we do to make the limit explicit rather than accidental:

1. Each entry stores the fingerprint it was created with, and
   :meth:`Directory.lookup` re-derives it on every read. Editing a public key
   without also editing the fingerprint is detected.
2. :meth:`Directory.fingerprint` gives the caller a single digest over the whole
   directory, so a caller that remembers it earlier can detect swaps later
   (tested in test_messaging_directory).
3. Lookups are by exact opaque string. No pattern matching, no case folding, no
   "closest match" fallback that could route to the wrong peer.

Known limits, stated plainly: the directory is not authenticated against a
remote party. A sophisticated local attacker who rewrites both keys *and*
fingerprint consistently succeeds. Mitigating that needs an out-of-band channel
(compare fingerprints verbally) or a signed transparency log -- out of scope for
Phase 2.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..keystore import b64e, ensure_private_dir, read_key_file, write_key_file
from .identity import IdentityError, PublicIdentity

DIRECTORY_MAGIC = "pqc-kv-directory"
DIRECTORY_VERSION = 1
DIRECTORY_FILE = "messaging-directory.json"


class DirectoryError(Exception):
    """Directory problem. Never contains key material."""


class Directory:
    """A local, trusted map from user ID to public identity."""

    def __init__(self, root: Path):
        self.root = ensure_private_dir(Path(root) / "pqc-kv-messaging")
        self.path = self.root / DIRECTORY_FILE

    # ------------------------------------------------------------------ read
    def _load(self) -> dict:
        if not self.path.exists():
            return {"magic": DIRECTORY_MAGIC, "version": DIRECTORY_VERSION, "entries": {}}
        try:
            data = read_key_file(self.path)
        except Exception:
            raise DirectoryError("directory unreadable") from None
        if data.get("magic") != DIRECTORY_MAGIC:
            raise DirectoryError("not a directory file")
        if data.get("version") != DIRECTORY_VERSION:
            raise DirectoryError("unsupported directory version")
        entries = data.get("entries")
        if not isinstance(entries, dict):
            raise DirectoryError("directory entries malformed")
        return data

    def lookup(self, user_id: str) -> PublicIdentity:
        """Exact-match lookup. Raises ``DirectoryError`` if absent or inconsistent."""
        entries = self._load()["entries"]
        record = entries.get(user_id)
        if not isinstance(record, dict):
            raise DirectoryError("unknown user")
        try:
            return PublicIdentity.from_dict(record)
        except IdentityError:
            # A record whose keys no longer match its fingerprint is corruption or
            # tampering. Fail closed; never fall back to the raw keys.
            raise DirectoryError("directory entry failed integrity check") from None

    def contains(self, user_id: str) -> bool:
        return isinstance(self._load()["entries"].get(user_id), dict)

    def known_users(self) -> list[str]:
        return sorted(self._load()["entries"])

    def fingerprint(self) -> str:
        """Digest over the whole directory, stable under key order.

        A caller can remember this value and later check it has not changed,
        which is the only tamper detection available without an external anchor.
        """
        entries = self._load()["entries"]
        canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(b"pqc-kv/v2/directory" + canonical).hexdigest()

    # ----------------------------------------------------------------- write
    def add(self, identity: PublicIdentity) -> None:
        """Insert or replace one entry (replace is needed for key rotation)."""
        data = self._load()
        data["entries"][identity.user_id] = identity.to_dict()
        write_key_file(self.path, data)

    def remove(self, user_id: str) -> None:
        data = self._load()
        if user_id in data["entries"]:
            del data["entries"][user_id]
            write_key_file(self.path, data)

    def bulk_add(self, identities: list[PublicIdentity]) -> None:
        data = self._load()
        for identity in identities:
            data["entries"][identity.user_id] = identity.to_dict()
        write_key_file(self.path, data)


def build_from_identities(root: Path, identities: list[PublicIdentity]) -> Directory:
    directory = Directory(root)
    directory.bulk_add(identities)
    return directory


__all__ = ["Directory", "DirectoryError", "DIRECTORY_FILE", "build_from_identities", "b64e"]
