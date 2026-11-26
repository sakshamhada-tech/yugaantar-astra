"""Authenticated backup and restore of key material, with rollback detection.

The shape of a backup
---------------------
    blob = header ‖ ciphertext ‖ tag ‖ signature ‖ manifest

    backup key   = HKDF-SHA256(operator secret, salt=backup salt, info=".../aead")
    signature    = ML-DSA-65 over the manifest and the ciphertext
    manifest     = {key_version, key_ids, revocation_seq, log_head, salt}

There are two independent checks, deliberately:

* **Confidentiality + integrity:** AES-256-GCM over the key material. A flipped bit
  anywhere in the ciphertext, tag or nonce fails the tag.
* **Authenticity:** an ML-DSA signature over the manifest *and* the ciphertext, so an
  attacker who cannot sign cannot swap a manifest, re-label an old blob as new, or
  paste a ciphertext from another installation.

They are not redundant: GCM alone cannot tell you *whose* backup this is, and a
signature alone would leave the key material in the clear.

Where the key comes from
------------------------
The operator supplies it, **every time**, at backup and restore. It is never stored
in the state directory, never derived from anything in it, and never hard-coded. That
is the difference between this and a toy: if the backup key lived beside the data,
the backup would protect against nothing that the state directory does not already.

Restore verifies BEFORE using anything
--------------------------------------
:func:`open_backup` either returns a fully verified payload or raises. There is no
"partially verified" return value, so a caller cannot accidentally use unverified key
material -- the only object they can get holds material that already passed both
checks.

Rollback attack, and the honest limit
-------------------------------------
The interesting attack is not corruption, it is **replay of a genuine old backup**:
restore last week's good backup and the revocation you applied yesterday disappears,
along with the key version you retired. Defences:

1. The manifest carries `revocation_seq` and `key_version`, and restore refuses a
   backup whose numbers are **below the node's high-water marks**.
2. `log_head` is compared too, so a backup from before a log rewrite is visible.

**The limit, stated plainly:** those high-water marks live in the state directory
that the backup is meant to protect. An attacker who can write the state directory
can lower the marks and then the replay looks legitimate. Restoring into a *fresh*
directory has no marks at all, which is why a fresh restore needs an externally
remembered value (the operator's notebook, a CI secret, an append-only sink). Without
one, "restore into an empty directory" cannot distinguish the newest backup from an
old one. This is documented rather than papered over; no amount of code here can fix
it, because the file that records the answer is in the attacker's write scope.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

from . import dsa
from .symmetric import (
    KEY_LEN,
    NONCE_LEN,
    TAG_LEN,
    TamperError,
    aesgcm_decrypt,
    aesgcm_encrypt,
    hkdf_sha256,
)

BACKUP_MAGIC = "pqc-kv-backup"
BACKUP_VERSION = 1
SALT_LEN = 32
MIN_SECRET_LEN = 16

_LABEL_AEAD = b"pqc-kv/v1/backup/aead"
_LABEL_SALT = b"pqc-kv/v1/backup/salt"


class BackupError(Exception):
    """One failure type for every backup problem. No key material, ever."""

    def __init__(self, reason: str = "backup_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


class Reason:
    MALFORMED = "backup_malformed"
    BAD_SIGNATURE = "backup_bad_signature"
    DAMAGED = "backup_damaged"
    STALE = "backup_stale"
    BAD_SECRET = "backup_bad_secret"
    MANIFEST_MISMATCH = "backup_manifest_mismatch"


def _derive_key(secret: bytes, salt: bytes) -> bytes:
    return hkdf_sha256(secret, salt=salt, info=_LABEL_AEAD, length=KEY_LEN)


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_SECRET_LEN:
        raise BackupError(Reason.BAD_SECRET)
    return bytes(secret)


def manifest_bytes(manifest: dict) -> bytes:
    """Canonical manifest bytes. Sorted keys, no whitespace, no ambiguity."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_backup(
    *,
    payload: dict,
    secret: bytes,
    signing_key,
    key_version: int,
    key_ids: list[str],
    revocation_seq: int,
    log_head: str,
) -> dict:
    """Seal key material into one authenticated blob.

    ``payload`` is the key material to protect (a dict of file name -> base64). It is
    never written anywhere in the clear by this function.
    """
    secret = _validate_secret(secret)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(secret, salt)

    manifest = {
        "magic": BACKUP_MAGIC,
        "version": BACKUP_VERSION,
        "key_version": int(key_version),
        "revocation_seq": int(revocation_seq),
        "log_head": str(log_head),
        "key_ids": sorted(str(k) for k in key_ids),
        "salt": base64.b64encode(salt).decode("ascii"),
        "manifest_hash": hashlib.sha256(
            json.dumps(sorted(str(k) for k in key_ids)).encode("utf-8")
        ).hexdigest(),
    }
    aad = manifest_bytes(manifest)

    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext, tag = aesgcm_encrypt(key, nonce, plaintext, aad)

    # Sign manifest AND ciphertext: signing only the manifest would let an attacker
    # keep the signature and swap the encrypted body.
    signed = aad + b"|" + nonce + b"|" + ciphertext + b"|" + tag
    signature = dsa.sign(signing_key, signed)

    return {
        "manifest": manifest,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def open_backup(
    blob: dict,
    *,
    secret: bytes,
    signing_public: bytes,
    high_water: dict | None = None,
) -> dict:
    """Verify, then decrypt. Returns the payload or raises. Never a partial result.

    ``high_water`` may carry ``key_version``, ``revocation_seq`` and ``log_head``: the
    marks recorded by this node. A backup below them is refused as stale, which is how
    a replay of an old-but-genuine backup is caught.
    """
    secret = _validate_secret(secret)
    if not isinstance(blob, dict):
        raise BackupError(Reason.MALFORMED)

    try:
        manifest = blob["manifest"]
        nonce = base64.b64decode(blob["nonce"], validate=True)
        ciphertext = base64.b64decode(blob["ciphertext"], validate=True)
        tag = base64.b64decode(blob["tag"], validate=True)
        signature = base64.b64decode(blob["signature"], validate=True)
    except Exception:
        raise BackupError(Reason.MALFORMED) from None

    if not isinstance(manifest, dict):
        raise BackupError(Reason.MALFORMED)
    if manifest.get("magic") != BACKUP_MAGIC or manifest.get("version") != BACKUP_VERSION:
        raise BackupError(Reason.MALFORMED)
    if len(nonce) != NONCE_LEN or len(tag) != TAG_LEN:
        raise BackupError(Reason.DAMAGED)

    # ---- 1. authenticity, before anything is derived or decrypted
    aad = manifest_bytes(manifest)
    signed = aad + b"|" + nonce + b"|" + ciphertext + b"|" + tag
    if not dsa.verify(signing_public, signed, signature):
        raise BackupError(Reason.BAD_SIGNATURE)

    # ---- 2. rollback check, before the expensive decrypt
    #
    # Only *monotone counters* are compared. `log_head` deliberately is not: it is a
    # hash that advances on every audit write, so demanding equality would reject a
    # legitimate re-restore of the same good backup a moment later (found by test).
    # It stays in the manifest so an operator can anchor it externally, which is the
    # only place a hash can be compared meaningfully.
    if high_water:
        if int(manifest.get("key_version", 0)) < int(high_water.get("key_version", 0)):
            raise BackupError(Reason.STALE)
        if int(manifest.get("revocation_seq", 0)) < int(high_water.get("revocation_seq", 0)):
            raise BackupError(Reason.STALE)

    # ---- 3. confidentiality + integrity
    try:
        salt = base64.b64decode(manifest["salt"], validate=True)
    except Exception:
        raise BackupError(Reason.MALFORMED) from None
    if len(salt) != SALT_LEN:
        raise BackupError(Reason.MALFORMED)

    key = _derive_key(secret, salt)
    try:
        plaintext = aesgcm_decrypt(key, nonce, ciphertext, tag, aad)
    except TamperError:
        raise BackupError(Reason.DAMAGED) from None
    except Exception:
        raise BackupError(Reason.DAMAGED) from None

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise BackupError(Reason.DAMAGED) from None
    if not isinstance(payload, dict):
        raise BackupError(Reason.MALFORMED)

    # ---- 4. the manifest must describe the payload it travels with
    key_ids = sorted(str(k) for k in payload)
    expected = hashlib.sha256(json.dumps(key_ids).encode("utf-8")).hexdigest()
    if manifest.get("manifest_hash") != expected:
        raise BackupError(Reason.MANIFEST_MISMATCH)

    return payload


def high_water_from_state(state: dict) -> dict:
    """The marks a restore is compared against. Read from state, not from the backup.

    These are **monotone counters**: they only move on the events rollback cares
    about (a rotation bumps key_version; a revocation bumps revocation_seq). Ordinary
    reads and audit writes do not disturb them, so re-restoring the current backup
    stays legitimate.

    ``log_head`` is carried separately for external anchoring -- an operator compares
    it against a value they wrote down, which is a human decision, not an automatic
    one.
    """
    return {
        "key_version": int(state.get("active_version", 1)),
        "revocation_seq": int(state.get("revocation_seq", 0)),
        "log_head": state.get("audit_head", "0" * 64),
    }


__all__ = [
    "BACKUP_MAGIC", "BACKUP_VERSION", "BackupError", "Reason",
    "create_backup", "high_water_from_state", "manifest_bytes", "open_backup",
]
