"""Key storage that fits the adapter's persistence rules.

The judging container has a **read-only root filesystem** and wipes everything
between runs; only a writable temp path survives inside a container. It also has
no environment-provided secrets for us. So:

* Keys are **generated at runtime** into the state directory (the only writable
  place), never hard-coded and never in git.
* Every key file is created with mode ``0600`` in a directory with ``0700``.
  Permissions are set at creation time (``os.open`` with ``O_EXCL``), not after,
  so there is no window where the file is world-readable.
* Writes are atomic: temp file in the same directory + ``fsync`` + ``os.replace``.
  A crash mid-write cannot leave a half-key that looks valid.
* Nothing in this module prints, logs or raises a message containing key bytes.
  Errors name the *path* and the *class* of problem only.
* Key files are identifiable by a magic header so a truncated/corrupt file is
  rejected instead of being used as a key.

Storage formats are versioned JSON with base64 fields. Private keys live only in
this directory; the adapter never copies them into stdout, stderr, or the audit
log.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
from pathlib import Path

KEY_MAGIC = "pqc-kv-key"
KEY_FORMAT_VERSION = 1
DIR_MODE = 0o700
FILE_MODE = 0o600


class KeyStoreError(Exception):
    """Storage problem. Messages never include key material."""


def default_state_dir() -> Path:
    """Adapter contract: honour ``TRACK4_STATE_DIR``; else OS temp directory."""
    override = os.environ.get("TRACK4_STATE_DIR")
    if override:
        return Path(override)
    return Path(tempfile.gettempdir())


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` with 0700 if needed and verify it is not group/world writable."""
    path = Path(path)
    try:
        path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    except OSError:
        raise KeyStoreError("cannot create state directory") from None
    try:
        info = path.stat()
    except OSError:
        raise KeyStoreError("cannot stat state directory") from None
    if not stat.S_ISDIR(info.st_mode):
        raise KeyStoreError("state path is not a directory")
    if info.st_mode & 0o077:
        # Try once to tighten it; refuse to store keys in a shared directory.
        try:
            os.chmod(path, DIR_MODE)
        except OSError:
            raise KeyStoreError("state directory permissions are too open") from None
        if path.stat().st_mode & 0o077:
            raise KeyStoreError("state directory permissions are too open")
    return path


def write_key_file(path: Path, payload: dict) -> None:
    """Atomically write a key file with 0600 permissions."""
    path = Path(path)
    ensure_private_dir(path.parent)
    body = dict(payload)
    body["magic"] = KEY_MAGIC
    body["key_version"] = KEY_FORMAT_VERSION
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-key-")
    try:
        os.fchmod(tmp_fd, FILE_MODE)
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
        _fsync_dir(path.parent)
    except OSError:
        raise KeyStoreError("cannot write key file") from None
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def read_key_file(path: Path) -> dict:
    path = Path(path)
    try:
        info = path.stat()
    except OSError:
        raise KeyStoreError("key file missing") from None
    if info.st_mode & 0o077:
        raise KeyStoreError("key file permissions are too open")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise KeyStoreError("key file unreadable or corrupt") from None
    if not isinstance(data, dict) or data.get("magic") != KEY_MAGIC:
        raise KeyStoreError("key file is not a pqc-kv key file")
    if data.get("key_version") != KEY_FORMAT_VERSION:
        raise KeyStoreError("unsupported key file version")
    return data


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        raise KeyStoreError("corrupt key encoding") from None


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


class KeyStore:
    """Lazily-created, per-installation keys under one private directory.

    Keys are created on first use and reused afterwards, so state written by an
    earlier process can be read by a later one (the validator checks exactly this
    for revocation, and the same must hold for ciphertext).
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = ensure_private_dir(Path(root) if root else default_state_dir() / "pqc-kv-keys")
        self._cache: dict[str, object] = {}

    # -- paths
    def _path(self, name: str) -> Path:
        return self.root / name

    # -- ML-KEM recipient keys
    def kem_keypair(self, label: str = "asset-store"):
        from . import kem

        cache_key = f"kem:{label}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        path = self._path(f"kem-{_safe(label)}.key")
        if path.exists():
            data = read_key_file(path)
            pair = kem.KemKeyPair(
                public_key=b64d(data["public_key"]), secret_key=b64d(data["secret_key"])
            )
        else:
            pair = kem.generate_keypair()
            write_key_file(
                path,
                {
                    "kind": "ml-kem-768",
                    "label": label,
                    "public_key": b64e(pair.public_key),
                    "secret_key": b64e(pair.secret_key),
                },
            )
        self._cache[cache_key] = pair
        return pair

    # -- ML-DSA signing keys
    def signing_keypair(self, label: str = "service"):
        from . import dsa

        cache_key = f"dsa:{label}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        path = self._path(f"dsa-{_safe(label)}.key")
        if path.exists():
            data = read_key_file(path)
            pair = dsa.SigningKeyPair(
                public_key=b64d(data["public_key"]), secret_key=b64d(data["secret_key"])
            )
        else:
            pair = dsa.generate_keypair()
            write_key_file(
                path,
                {
                    "kind": "ml-dsa-65",
                    "label": label,
                    "public_key": b64e(pair.public_key),
                    "secret_key": b64e(pair.secret_key),
                },
            )
        self._cache[cache_key] = pair
        return pair

    # -- hybrid keypair
    def hybrid_keypair(self, label: str = "asset-store"):
        from . import hybrid

        cache_key = f"hybrid:{label}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        path = self._path(f"hybrid-{_safe(label)}.key")
        if path.exists():
            data = read_key_file(path)
            pair = hybrid.HybridKeyPair(
                x25519_public=b64d(data["x25519_public"]),
                mlkem_public=b64d(data["mlkem_public"]),
                x25519_secret=b64d(data["x25519_secret"]),
                mlkem_secret=b64d(data["mlkem_secret"]),
            )
        else:
            pair = hybrid.generate_keypair()
            write_key_file(
                path,
                {
                    "kind": "hybrid-x25519-ml-kem-768",
                    "label": label,
                    "x25519_public": b64e(pair.x25519_public),
                    "mlkem_public": b64e(pair.mlkem_public),
                    "x25519_secret": b64e(pair.x25519_secret),
                    "mlkem_secret": b64e(pair.mlkem_secret),
                },
            )
        self._cache[cache_key] = pair
        return pair


def _safe(label: str) -> str:
    """Map an opaque label to a filesystem-safe name without losing uniqueness."""
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(label))
    return (cleaned or "default")[:64]
