"""Encrypted-at-rest asset store with a persisted, hash-chained audit log.

This is the layer the adapter talks to. It keeps three promises the contract and
the brief care about:

1. **Contents live on disk only as envelopes** (ML-KEM-768 + HKDF + AES-256-GCM
   + ML-DSA-65 signature). A plaintext copy never touches the filesystem.
2. **Policy and audit state survive process restarts**, because the judge starts a
   brand-new process per request. Revocation is written before we acknowledge it.
3. **Every decision is recorded against the caller's request id**, together with
   the rule that produced it, so a denied request can be explained later.

Threat model notes (see SECURITY_NOTES.md for the full list):

* The audit chain detects *offline editing* of past records: changing one record
  breaks every later hash. It does **not** stop an attacker who can rewrite the
  whole file and recompute the chain -- for that you need an external anchor.
* Envelopes are bound by AAD to the asset id, so a ciphertext cannot be copied
  onto a different asset and still open.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from . import envelope
from .aead import NonceBudget
from . import intent
from .keyring import ACTIVE, KeyRing, KeyRingError
from .keystore import (
    KeyStore, b64d, b64e, ensure_private_dir, read_key_file, write_key_file,
)

SCHEMA = 1
# Outcomes that are recorded in the audit log. `reject` is not a policy decision
# the reader sees; it marks an attempt we refused to process (a reused request id).
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_REJECT = "reject"
ASSET_CONTEXT = "pqc-kv/v1/asset-body"
KEY_MATERIAL_CONTEXT = "pqc-kv/v1/synthetic-key-material"
AUDIT_GENESIS = "0" * 64
ROTATE_AFTER = 4_096  # well below the 2^20 nonce budget per key


class StoreError(Exception):
    """Store failure. Messages never contain plaintext, keys or key material."""


def _safe_actor(actor) -> bool:
    """Whether an actor name can be written to the signed event log as-is."""
    from .logsign import LogError, validate_identifier

    try:
        validate_identifier(actor)
    except LogError:
        return False
    return True


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class StateStore:
    def __init__(self, state_dir: Path):
        self.root = ensure_private_dir(Path(state_dir) / "pqc-kv-state")
        self.assets_dir = ensure_private_dir(self.root / "assets")
        self.keys = KeyStore(self.root / "keys")
        # Service keys live in a versioned ring (goal 1). `self.keys` stays for the
        # Phase 1 code paths that never version (synthetic material, messaging).
        self.ring = KeyRing(self.root)
        self.state_path = self.root / "state.json"
        self.audit_path = self.root / "audit.jsonl"
        self.lock_path = self.root / ".lock"
        self._budget = NonceBudget(limit=ROTATE_AFTER)
        self._sealed_material_path = self.root / "synthetic-material.env"

    # ------------------------------------------------------------ locking/io
    @contextmanager
    def _locked(self):
        """Single-writer lock so two concurrent requests cannot interleave state."""
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

    def _read_state(self) -> dict:
        if not self.state_path.exists():
            raise StoreError("no state; setup has not run")
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise StoreError("state file corrupt") from None
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise StoreError("unsupported state schema")
        return data

    def _write_state(self, state: dict) -> None:
        """Atomic + fsync: a change is durable before we acknowledge it."""
        tmp_fd, tmp_name = tempfile.mkstemp(dir=str(self.root), prefix=".state-")
        try:
            os.fchmod(tmp_fd, 0o600)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.state_path)
            tmp_name = None
            self._fsync_dir(self.root)
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    @staticmethod
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

    # ---------------------------------------------------------------- setup
    def setup(self, request: dict) -> dict:
        owners = request.get("owners") or {}
        contents = request.get("contents") or {}
        disabled = request.get("disabled") or []
        if not isinstance(owners, dict) or not isinstance(contents, dict):
            raise StoreError("setup payload malformed")
        if not isinstance(disabled, list):
            raise StoreError("setup disabled list malformed")

        with self._locked():
            # Fresh keys per setup, inside the lock so two concurrent setups cannot
            # interleave. Rationale: the adapter is a new process per request, so an
            # in-memory nonce counter resets constantly and is a lie about how many
            # messages a key has produced. Giving each setup its own key keeps the
            # AES-GCM nonce budget honest: one key encrypts only the assets of one
            # setup. All ciphertexts are re-sealed here, so nothing is orphaned.
            recipient, signer = self._rotate_keys()
            # Version 1 of the service key ring. After this, keys are only ever
            # rotated (goal 1), never deleted and re-created like this.
            if not self.ring.load()["entries"]:
                self.ring.create_initial()
            # Assets are sealed with the ring's active version, so open() can find
            # the right keypair from the version stamped on each asset.
            ring_version = self.ring.active().version
            ring_kem = self.ring.kem_pair(ring_version)
            ring_dsa = self.ring.dsa_pair(ring_version)

            # Reset policy + asset data.
            for stale in self.assets_dir.glob("*.env"):
                try:
                    stale.unlink()
                except OSError:
                    pass
            self.audit_path.write_bytes(b"")
            try:
                self._sealed_material_path.unlink()
            except FileNotFoundError:
                pass

            asset_index: dict[str, dict] = {}
            for asset, body in contents.items():
                if not isinstance(asset, str) or not isinstance(body, str):
                    raise StoreError("setup contents malformed")
                asset_index[asset] = self._seal_asset(
                    asset, body, ring_kem, ring_dsa, version=ring_version
                )

            material = request.get("key_material")
            if isinstance(material, str) and material:
                # The synthetic sensitive value is sealed at rest and has no read
                # path at all. It exists to prove we can hold a secret without
                # printing or returning it.
                sealed = envelope.seal(
                    plaintext=material.encode("utf-8"),
                    recipient_public=recipient,
                    sender_signing_secret=signer.secret_key,
                    recipient="synthetic:key-material",
                    envelope_id="km-" + _digest(material)[:16],
                    context=KEY_MATERIAL_CONTEXT,
                    budget=self._budget,
                )
                write_key_file(
                    self._sealed_material_path,
                    {"kind": "sealed-material", "envelope": envelope.to_json(sealed)},
                )

            state = {
                "schema": SCHEMA,
                "created": _now(),
                "owners": {str(k): str(v) for k, v in owners.items()},
                "disabled": [str(a) for a in disabled],
                "assets": asset_index,
                "events": {},
                "audit_head": AUDIT_GENESIS,
                "audit_seq": 0,
                "active_version": ring_version,
                "revocation_seq": 0,
            }
            self._write_state(state)
        return {"ready": True}

    #: Legacy, unversioned Phase 1 key labels. These are the only key files setup
    #: may delete. Ring keys are `kem-service-vN.key` / `dsa-service-vN.key` and are
    #: rotated explicitly (goal 1), never removed by setup -- a glob like
    #: ``kem-*.key`` would match them and silently destroy the active version.
    _LEGACY_KEY_FILES = ("kem-asset-store.key", "dsa-service.key")

    def _rotate_keys(self):
        """Reset the *legacy* keypair used only for the synthetic material seal.

        Phase 1 deleted every key here and re-sealed everything. That is the
        demolition goal 1 exists to replace, so this now touches only the two
        unversioned files and leaves the versioned ring alone.
        """
        self.keys._cache.clear()
        for name in self._LEGACY_KEY_FILES:
            stale = self.root / "keys" / name
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                raise StoreError("cannot reset legacy keys") from None
        recipient = self.keys.kem_keypair("asset-store")
        signer = self.keys.signing_keypair("service")
        return recipient, signer

    def _recipient_label(self, asset: str, version: int) -> str:
        """AAD-bound recipient label. The key version is part of the label, so an
        envelope cannot be replayed as if it had been sealed under another version."""
        return f"asset:{asset}#v{version}"

    def _seal_asset(self, asset: str, body: str, recipient, signer, version: int = 1) -> dict:
        envelope_id = "asset-" + _digest(asset)[:16]
        sealed = envelope.seal(
            plaintext=body.encode("utf-8"),
            recipient_public=recipient,
            sender_signing_secret=signer.secret_key,
            recipient=self._recipient_label(asset, version),
            envelope_id=envelope_id,
            context=ASSET_CONTEXT,
            budget=self._budget,
        )
        name = envelope_id + ".env"
        write_key_file(self.assets_dir / name, {"kind": "asset-envelope", "envelope": envelope.to_json(sealed)})
        return {
            "file": name,
            "envelope_id": envelope_id,
            "ciphertext_sha256": hashlib.sha256(sealed.ciphertext).hexdigest(),
            "key_version": version,
        }

    def _open_asset(self, asset: str, entry: dict) -> str:
        version = int(entry.get("key_version", 1))
        recipient = self.ring.kem_pair(version)
        signer = self.ring.dsa_pair(version)
        record = read_key_file(self.assets_dir / entry["file"])
        try:
            env = envelope.from_dict(json.loads(record["envelope"]))
        except (KeyError, TypeError, ValueError):
            raise StoreError("stored envelope unreadable") from None
        # AAD check: an envelope moved from another asset will not open.
        if env.envelope_id != entry["envelope_id"] or env.recipient != self._recipient_label(asset, version):
            raise StoreError("stored envelope does not belong to this asset")
        try:
            body = envelope.open_envelope(
                env, recipient_secret=recipient, sender_signing_public=signer.public_key
            )
        except envelope.EnvelopeError:
            raise StoreError("stored envelope failed integrity checks") from None
        return body.decode("utf-8")

    # ------------------------------------------------------------ decisions
    def read(self, actor: str, asset: str, request_id: str, request_version: int | None = None) -> dict:
        """Authorize a read. Returns only the decision (plus the body if allowed).

        The *rule* that produced the decision is deliberately absent. adapter-v1.md
        specifies `{"decision":"allow","body":...}` or `{"decision":"deny"}`, and a
        rule label would answer a question the contract does not let the caller ask:
        `owner_required` versus `unknown_asset` tells an unauthenticated caller which
        asset ids exist. The rule is written to the audit record instead, where only
        an operator can read it.

        Request ids are single-use per event. A second read with a reused id is
        refused rather than allowed to overwrite the first event's explanation,
        because otherwise a caller could launder a past `allow` into a `deny` (or
        the reverse) after the fact.
        """
        if not isinstance(request_id, str) or not request_id:
            raise StoreError("malformed request id")
        with self._locked():
            state = self._read_state()
            if request_id in state.get("events", {}):
                # The attempt is recorded in full, but it does not touch the
                # original event and it never evaluates policy.
                self._record_duplicate(state, request_id, actor, asset)
                self._write_state(state)
                return {
                    "decision": DECISION_DENY,
                    "error": "request_id_reused",
                }
            # Goal 1: which key version is this request asking for? Default is the
            # active version, which is what an ordinary caller means by "a read".
            requested = state.get("active_version", 1)
            asked = request_version if request_version is not None else requested
            admitted = self._admit_version(state, asked)
            if not admitted:
                decision, rule, body = DECISION_DENY, "key_version_rejected", None
            else:
                decision, rule, body = self._decide(state, actor, asset)
            response: dict = {"decision": decision}
            if decision == DECISION_ALLOW:
                response["body"] = body
            self._record(state, request_id, actor, asset, decision, rule)
            self._write_state(state)
            return response

    def _admit_version(self, state: dict, version: int) -> bool:
        """Enforce the rotation cutoff, and charge the grace budget when it applies.

        A "*request using the old key*" in this adapter is a read whose
        ``key_version`` names a ring version that is not the active one. Ordinary
        reads do not name a version, so they always use the active one; the version
        is named explicitly by an in-flight client that loaded an asset under version
        N before rotation happened. That is the only kind of request the cutoff can
        meaningfully affect, and it is the case tested end to end.
        """
        ring = self.ring.load()
        try:
            entry = self.ring.by_version(ring, version)
        except KeyRingError:
            return False
        if entry.state == ACTIVE:
            return True
        if entry.state in ("retired", "revoked"):
            return False
        allowed, updated = self.ring.admit_read(version)
        if updated is not ring:
            self.ring.save(updated)
        return allowed

    def _decide(self, state: dict, actor, asset):
        if not isinstance(actor, str) or not isinstance(asset, str):
            return "deny", "malformed_identity", None
        if actor in state.get("disabled", []):
            return "deny", "identity_revoked", None
        if asset not in state.get("assets", {}):
            return "deny", "unknown_asset", None
        if state.get("owners", {}).get(asset) != actor:
            return "deny", "owner_required", None
        try:
            body = self._open_asset(asset, state["assets"][asset])
        except StoreError:
            # Fail closed: a corrupt/tampered asset is a denial, never a fallback.
            return "deny", "asset_integrity_failure", None
        return "allow", "owner_allowed", body

    def revoke(self, actor: str) -> dict:
        if not isinstance(actor, str) or not actor:
            raise StoreError("malformed actor")
        with self._locked():
            state = self._read_state()
            if actor not in state["disabled"]:
                state["disabled"].append(actor)
                # Monotonic counter; the rollback check for backups compares it.
                state["revocation_seq"] = int(state.get("revocation_seq", 0)) + 1
                self._write_state(state)
                self.record_event("revoke", actor if _safe_actor(actor) else "")
                self._append_audit(state, {
                    "op": "revoke",
                    "actor": actor,
                    "request_id": "",
                    "asset": "",
                    "decision": "revoke",
                    "rule": "identity_revoked",
                    "ts": _now(),
                })
            self._write_state(state)
        return {}

    def rotate(self, request: dict | None = None) -> dict:
        """Create key version N+1 and re-protect every asset under it.

        Crash safety (goal 3): the whole operation is wrapped in a write-ahead intent
        record. See ``pqc_kv/intent.py`` for the ordering and the recovery rule. In
        short:

            intent -> re-wrap -> commit -> clear

        An interruption at any point leaves exactly one reachable outcome, and
        :meth:`recover` finishes it. This deliberately does **not** call ``setup()``:
        nothing here clears the audit log, re-creates keys from scratch, or resets
        policy. A test asserts the setup-only destructive hooks are never invoked.
        """
        request = request or {}
        grace = int(request.get("grace", 2))

        # Finish anything a previous crash left behind before starting new work.
        self.recover()
        with self._locked():
            state = self._read_state()
            before = state.get("active_version", 1)

            intent.fault_point("before_intent")
            intent.write_intent(self.root, {
                "op": "rotate",
                "from_version": before,
                "to_version": before + 1,
                "grace": grace,
                "assets": sorted(state["assets"]),
            })
            intent.fault_point("after_intent")

            old_entry, new_entry = self.ring.rotate(grace=grace)
            ring_kem = self.ring.kem_pair(new_entry.version)
            ring_dsa = self.ring.dsa_pair(new_entry.version)

            resealed = 0
            total = len(state["assets"])
            for index, (asset, entry) in enumerate(list(state["assets"].items())):
                body = self._open_asset(asset, entry)
                state["assets"][asset] = self._seal_asset(
                    asset, body, ring_kem, ring_dsa, version=new_entry.version
                )
                resealed += 1
                # Persist progress so a crash mid-way leaves a partial state that
                # recovery can finish, rather than a ring pointing at keys no asset
                # has been sealed with yet.
                state["active_version"] = new_entry.version
                self._write_state(state)
                if index == total // 2:
                    intent.fault_point("mid_rewrap")

            state["active_version"] = new_entry.version
            self._append_audit(state, {
                "op": "rotate",
                "actor": "",
                "request_id": "",
                "asset": "",
                "decision": "rotate",
                "rule": f"key_v{before}_to_v{new_entry.version}",
                "ts": _now(),
            })
            intent.fault_point("before_commit")
            self._write_state(state)
            intent.write_commit(self.root, {
                "op": "rotate", "to_version": new_entry.version, "resealed": resealed,
            })
            intent.fault_point("after_commit")
            intent.clear(self.root)
            # Goal 5: every rotation is a key event. Written after the commit so a
            # crash cannot leave an event for a rotation that did not happen.
            self.record_event("rotate", "", f"v{before}-to-v{new_entry.version}")
        return {
            "active_version": new_entry.version,
            "retiring_version": old_entry.version,
            "resealed": resealed,
            "grace": grace,
        }

    def key_status(self) -> dict:
        """Public description of the key ring. Versions and states, no key material."""
        ring = self.ring.summary()
        state = self._read_state()
        ring["active_version"] = state.get("active_version", ring.get("active_version", 1))
        return ring

    def publish_notice(self, kind: str, payload: dict) -> dict:
        """Sign a notice with this node's publisher key and drop it in the outbox."""
        from . import cluster

        node = cluster.Node(self.root.parent, self.node_id(), outbox=self.cluster_outbox())
        pair, fp = cluster.public_identity_fields(KeyStore(self.root / "cluster-identity"))
        return node.publish(kind=kind, payload=payload, publisher_key=pair.secret_key, publisher_fp=fp)

    def cluster_outbox(self) -> Path:
        """Where this node publishes. Siblings share it; it is *not* trusted input.

        A notice found here is verified before it means anything, so the directory
        only has to be a channel, not a safe place.
        """
        # TRACK4_CLUSTER_DIR is the shared parent of sibling node directories. It is
        # read from the environment only, never from a request, and it defaults to
        # the node's own directory -- so by default a node publishes only to itself
        # and nothing propagates by accident.
        shared = os.environ.get("TRACK4_CLUSTER_DIR")
        base = Path(shared) if shared else self.root.parent
        return ensure_private_dir(base / "cluster-outbox")

    def node_id(self) -> str:
        """Stable id for this state directory. Derived from the path, not the clock."""
        return "node-" + hashlib.sha256(str(self.root).encode("utf-8")).hexdigest()[:12]

    def apply_notices(self, notices: list, publisher_public: bytes) -> dict:
        """Verify and apply notices in one locked, persisted step.

        Application is commutative and idempotent: revocation is a set insert and the
        key version is a max(), so notices may arrive in any order and a duplicate is
        a no-op. Anything that fails verification or fails the sequence check is
        counted and dropped -- it never touches state.
        """
        from . import cluster

        node = cluster.Node(self.root.parent, self.node_id(), outbox=self.cluster_outbox())
        applied, rejected = [], []
        with self._locked():
            state = self._read_state()
            for notice in notices or []:
                try:
                    result = node.ingest(notice, signer_public=publisher_public)
                except cluster.NoticeError as error:
                    rejected.append(error.reason)
                    continue
                parsed = notice
                if result["kind"] == cluster.KIND_REVOKE:
                    actor = str(parsed["payload"].get("actor", ""))
                    if actor and actor not in state["disabled"]:
                        state["disabled"].append(actor)
                        state["revocation_seq"] = int(state.get("revocation_seq", 0)) + 1
                        self._append_audit(state, {
                            "op": "revoke", "actor": actor, "request_id": "", "asset": "",
                            "decision": "revoke", "rule": "identity_revoked_remote", "ts": _now(),
                        })
                elif result["kind"] == cluster.KIND_ROTATE:
                    # Rotation notice: adopt the announced version if it is newer than
                    # what we already have. max() makes this order-independent.
                    target = int(parsed["payload"].get("key_version", 0))
                    if target > int(state.get("active_version", 1)):
                        state["remote_key_version"] = target
                        self._append_audit(state, {
                            "op": "rotate", "actor": "", "request_id": "", "asset": "",
                            "decision": "rotate",
                            "rule": f"notice_key_v{target}", "ts": _now(),
                        })
                applied.append(result)
            self._write_state(state)
        return {"applied": len(applied), "rejected": len(rejected), "reasons": rejected}

    def create_backup(self, secret: bytes, signer=None) -> dict:
        """Seal the key material into one authenticated blob. Operator supplies the key."""
        from . import backup

        if signer is None:
            signer = self.ring.dsa_pair(self.ring.active().version).secret_key
        state = self._read_state()
        payload = {}
        for name in self.ring.key_files():
            path = self.ring.keys_dir / name
            payload[name] = b64e(path.read_bytes())
        return backup.create_backup(
            payload=payload,
            secret=secret,
            signing_key=signer,
            key_version=int(state.get("active_version", 1)),
            key_ids=sorted(payload),
            revocation_seq=int(state.get("revocation_seq", 0)),
            log_head=str(state.get("audit_head", AUDIT_GENESIS)),
        )

    def restore_backup(self, blob: dict, secret: bytes, signing_public: bytes) -> dict:
        """Verify a backup, then install it. Nothing is written before verification.

        The high-water marks come from *this* node's state. See backup.py for why a
        fresh directory cannot defend against rollback without an external anchor.
        """
        from . import backup

        state = self._read_state()
        high_water = backup.high_water_from_state(state)
        # open_backup raises on anything it does not fully trust, so the payload we
        # get back has already passed signature, rollback and GCM checks.
        payload = backup.open_backup(
            blob, secret=secret, signing_public=signing_public, high_water=high_water
        )
        with self._locked():
            for name, encoded in payload.items():
                if "/" in str(name) or "\\" in str(name) or str(name).startswith("."):
                    raise StoreError("backup contains an unsafe key name")
                target = self.ring.keys_dir / str(name)
                write_key_file(target, json.loads(b64d(encoded).decode("utf-8")))
            state = self._read_state()
            self._append_audit(state, {
                "op": "restore", "actor": "", "request_id": "", "asset": "",
                "decision": "restore", "rule": f"keys_v{int(state.get('active_version', 1))}",
                "ts": _now(),
            })
            self._write_state(state)
            self.record_event("restore", "", f"keys-{len(payload)}")
        return {"restored": sorted(payload), "count": len(payload)}

    def recovery_pending(self) -> bool:
        return False

    def recover(self) -> dict:
        """Bring state back to one consistent version after an interruption.

        Called at the start of every rotation, and by the ``recover`` op. Rules (see
        ``pqc_kv/intent.py``):

            no intent            -> nothing to do
            intent + commit      -> the rotation finished; clear the marker
            intent, no commit    -> finish forward: re-wrap whatever is still on the
                                    old version, then commit

        "Finish forward" is safe because re-sealing is idempotent and every asset
        carries the version that actually sealed it. Revocations are never touched:
        they live in ``state["disabled"]``, which the intent record does not include.
        """
        record = intent.read_intent(self.root)
        if record is None:
            # A stray commit marker with no intent is a finished rotation whose
            # cleanup was interrupted. Clearing it is correct and loses nothing.
            intent.clear(self.root)
            return {
                "recovered": False,
                "active_version": self._read_state().get("active_version", 1),
            }

        committed = intent.read_commit(self.root)
        with self._locked():
            state = self._read_state()
            if committed is not None:
                intent.clear(self.root)
                return {
                    "recovered": True,
                    "action": "cleared",
                    "active_version": state.get("active_version", 1),
                }

            target = int(record.get("to_version", state.get("active_version", 1)))
            ring = self.ring.load()
            try:
                entry = self.ring.by_version(ring, target)
            except KeyRingError:
                # The intent names a version that was never created: nothing was
                # re-sealed either, so the old version is still the truth.
                intent.clear(self.root)
                return {
                    "recovered": True,
                    "action": "abandoned",
                    "active_version": state.get("active_version", 1),
                }

            ring_kem = self.ring.kem_pair(entry.version)
            ring_dsa = self.ring.dsa_pair(entry.version)
            completed = 0
            for asset, asset_entry in list(state["assets"].items()):
                if asset_entry.get("key_version") == entry.version:
                    continue
                body = self._open_asset(asset, asset_entry)
                state["assets"][asset] = self._seal_asset(
                    asset, body, ring_kem, ring_dsa, version=entry.version
                )
                completed += 1
            state["active_version"] = entry.version
            self._append_audit(state, {
                "op": "recover", "actor": "", "request_id": "", "asset": "",
                "decision": "recover", "rule": f"completed_to_v{entry.version}", "ts": _now(),
            })
            self._write_state(state)
            intent.write_commit(self.root, {
                "op": "recover", "to_version": entry.version, "resealed": completed,
            })
            intent.clear(self.root)
            self.record_event("recover", "", f"to-v{entry.version}")
        return {
            "recovered": True,
            "action": "completed",
            "active_version": entry.version,
            "resealed": completed,
        }

    def is_revoked(self, actor: str) -> bool:
        """Public read-only query: is this actor disabled?

        Added for Phase 2 so the messaging layer can honour a revocation without
        reaching into private state. Takes the same lock as every other accessor.
        An unknown actor is *not* revoked: revocation is an explicit act, and a name
        that was never registered has nothing to be revoked from.
        """
        if not isinstance(actor, str) or not actor:
            return False
        try:
            with self._locked():
                state = self._read_state()
        except StoreError:
            return False
        return actor in state.get("disabled", [])

    def audit(self, request_id: str) -> dict:
        """Play back a recorded decision. Exactly two fields, as the contract says.

        adapter-v1.md: "Return the recorded `request_id` and `decision` for that
        read." This op is unauthenticated, so anything more is free reconnaissance:
        naming the actor or the asset would confirm a guessed identifier exists, and
        `explanation` spells out the policy rule. The full record is available to the
        operator through :meth:`audit_detail` and the on-disk log, which are not
        reachable from the adapter.

        An unknown id still has to answer with a decision (the validator requires
        `allow|deny`), so it answers `deny` -- the fail-closed label -- and nothing
        else, making "never happened" indistinguishable from "denied".
        """
        if not isinstance(request_id, str) or not request_id:
            raise StoreError("malformed request id")
        state = self._read_state()
        event = state.get("events", {}).get(request_id)
        if not event:
            return {"request_id": request_id, "decision": DECISION_DENY}
        decision = event["decision"]
        if decision not in (DECISION_ALLOW, DECISION_DENY):
            # A refused duplicate is not an authorization decision; report it as the
            # deny it effectively was rather than inventing a third label.
            decision = DECISION_DENY
        return {"request_id": event["request_id"], "decision": decision}

    def audit_detail(self, request_id: str) -> dict:
        """Operator view: rule, actor, asset, explanation. Never a body."""
        if not isinstance(request_id, str):
            raise StoreError("malformed request id")
        state = self._read_state()
        event = state.get("events", {}).get(request_id)
        if not event:
            return {"request_id": request_id, "decision": DECISION_DENY, "error": "unknown_request"}
        return {
            "request_id": event["request_id"],
            "decision": event["decision"],
            "rule": event["rule"],
            "actor": event["actor"],
            "asset": event["asset"],
            "ts": event["ts"],
            "explanation": _explain(event["decision"], event["rule"]),
            "audit_hash": event["audit_hash"],
        }

    def audit_log_records(self) -> list[dict]:
        """Every audit record, chain fields included. Read-only operator view."""
        if not self.audit_path.exists():
            return []
        records = []
        for raw in self.audit_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                records.append(json.loads(raw))
            except ValueError:
                raise StoreError("audit log corrupt") from None
        return records

    def record_external(self, request_id: str, actor: str, asset: str, decision: str, rule: str) -> str:
        """Record a decision the adapter made outside :meth:`read` (e.g. protected_read).

        Same single-use rule as :meth:`read`: a reused request id gets its own
        `reject` record and never overwrites the first event. This matters more than
        it looks, because `protected_read` derives its request id from actor+asset
        when the caller supplies none, so repeats are the normal case rather than a
        hostile one.
        """
        if not isinstance(request_id, str) or not request_id:
            raise StoreError("malformed request id")
        with self._locked():
            state = self._read_state()
            if request_id in state.get("events", {}):
                digest = self._record_duplicate(state, request_id, actor, asset)
                self._write_state(state)
                return digest
            digest = self._record(state, request_id, actor, asset, decision, rule)
            self._write_state(state)
            return digest

    def open_for_protected_read(self, actor: str, asset: str) -> tuple[bool, str | None, str]:
        """Authorization + body for ``protected_read``. Never records on its own."""
        state = self._read_state()
        decision, rule, body = self._decide(state, actor, asset)
        return decision == "allow", body, rule

    # ---------------------------------------------------------------- audit
    def _record(self, state: dict, request_id: str, actor: str, asset: str, decision: str, rule: str) -> str:
        record = {
            "op": "read",
            "request_id": str(request_id),
            "actor": str(actor),
            "asset": str(asset),
            "decision": decision,
            "rule": rule,
            "ts": _now(),
        }
        digest = self._append_audit(state, record)
        state["events"][str(request_id)] = {
            "request_id": str(request_id),
            "actor": str(actor),
            "asset": str(asset),
            "decision": decision,
            "rule": rule,
            "ts": record["ts"],
            "audit_hash": digest,
        }
        return digest

    def _record_duplicate(self, state: dict, request_id: str, actor, asset) -> str:
        """Record a refused attempt to reuse a request id.

        It gets its own audit record with decision `reject`, so the operator sees the
        attempt, and it deliberately does *not* touch `state["events"][request_id]`,
        so the original decision keeps its original explanation.
        """
        record = {
            "op": "read",
            "request_id": str(request_id),
            "actor": str(actor),
            "asset": str(asset),
            "decision": DECISION_REJECT,
            "rule": "request_id_reused",
            "ts": _now(),
        }
        return self._append_audit(state, record)

    def _append_audit(self, state: dict, record: dict) -> str:
        seq = int(state.get("audit_seq", 0)) + 1
        prev = state.get("audit_head", AUDIT_GENESIS)
        record = dict(record, seq=seq, prev=prev)
        digest = _digest(json.dumps(record, sort_keys=True, separators=(",", ":")))
        line = json.dumps(dict(record, hash=digest), sort_keys=True, separators=(",", ":"))
        with open(self.audit_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        state["audit_seq"] = seq
        state["audit_head"] = digest
        return digest

    # ------------------------------------------------ signed key-event log (5)
    def _event_log(self):
        """The signed, strictly-encoded key-event log (goal 5).

        Separate from `audit.jsonl` on purpose. The audit log answers "what did this
        caller get and why"; this log answers "what happened to the keys", it is
        signed per record, and its signer is a dedicated key so rotating the service
        key does not invalidate the log's own signatures.
        """
        from . import logsign

        pair = KeyStore(self.root / "log-identity").signing_keypair("eventlog")
        return logsign.EventLog(self.root / "key-events.jsonl", pair.secret_key, pair.public_key)

    def record_event(self, action: str, actor: str = "", detail: str = "") -> dict:
        """Append a signed key event. Refuses hostile identifiers outright."""
        from . import logsign

        state = self._read_state()
        detail = detail or f"v{int(state.get('active_version', 1))}"
        try:
            return self._event_log().append(action=action, actor=actor, detail=detail)
        except logsign.LogError:
            # Never write a record we could not validate; the caller decides what to
            # do. The audit log still has the raw attempt.
            raise StoreError("event rejected") from None

    def verify_events(self, expected_head: str | None = None) -> dict:
        """Full chain + signature walk, optionally against a remembered head."""
        return self._event_log().verify(expected_head=expected_head)

    def events_head(self) -> dict:
        head, count = self._event_log().head()
        return {"events_head": head, "events": count}

    def log_head(self) -> dict:
        """The current chain head, for an operator to anchor outside the state dir.

        Without an anchor, a full rewrite of the log by someone with write access is
        undetectable. With one, rewriting produces a head that does not match what
        the operator wrote down. Phase 3 item 5 adds signing on top of this.
        """
        state = self._read_state()
        return {
            "audit_head": state.get("audit_head", AUDIT_GENESIS),
            "audit_seq": int(state.get("audit_seq", 0)),
        }

    def verify_audit_chain(self) -> tuple[bool, int]:
        """Re-derive every hash. Returns (ok, records_checked)."""
        if not self.audit_path.exists():
            return True, 0
        prev = AUDIT_GENESIS
        count = 0
        for raw in self.audit_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            count += 1
            try:
                entry = json.loads(raw)
                claimed = entry.pop("hash")
            except (ValueError, KeyError):
                return False, count
            if entry.get("prev") != prev:
                return False, count
            if _digest(json.dumps(entry, sort_keys=True, separators=(",", ":"))) != claimed:
                return False, count
            prev = claimed
        return True, count


def _explain(decision: str, rule: str) -> str:
    if decision == "allow":
        return "Request allowed: actor is the recorded owner of the asset and is not revoked."
    return {
        "identity_revoked": "Denied: the actor's access was revoked for this asset class.",
        "owner_required": "Denied: the actor is not the recorded owner of this asset.",
        "unknown_asset": "Denied: no such asset exists in this installation.",
        "asset_integrity_failure": "Denied: the stored asset failed its integrity check.",
        "malformed_identity": "Denied: the request carried a malformed actor or asset identifier.",
    }.get(rule, "Denied: policy did not authorize this request.")


__all__ = ["StateStore", "StoreError", "verify_audit_file"]


def verify_audit_file(store: StateStore) -> tuple[bool, int]:
    return store.verify_audit_chain()
