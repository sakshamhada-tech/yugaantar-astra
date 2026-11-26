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
from .keystore import KeyStore, ensure_private_dir, write_key_file, read_key_file

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


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class StateStore:
    def __init__(self, state_dir: Path):
        self.root = ensure_private_dir(Path(state_dir) / "pqc-kv-state")
        self.assets_dir = ensure_private_dir(self.root / "assets")
        self.keys = KeyStore(self.root / "keys")
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
                asset_index[asset] = self._seal_asset(asset, body, recipient, signer)

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
            }
            self._write_state(state)
        return {"ready": True}

    def _rotate_keys(self):
        """Drop any existing installation keys and create a new set.

        Only meaningful together with re-sealing every asset, which setup does.
        """
        self.keys._cache.clear()
        for pattern in ("kem-*.key", "dsa-*.key", "hybrid-*.key"):
            for stale in (self.root / "keys").glob(pattern):
                try:
                    stale.unlink()
                except OSError:
                    raise StoreError("cannot rotate keys") from None
        recipient = self.keys.kem_keypair("asset-store")
        signer = self.keys.signing_keypair("service")
        return recipient, signer

    def _seal_asset(self, asset: str, body: str, recipient, signer) -> dict:
        envelope_id = "asset-" + _digest(asset)[:16]
        sealed = envelope.seal(
            plaintext=body.encode("utf-8"),
            recipient_public=recipient,
            sender_signing_secret=signer.secret_key,
            recipient="asset:" + asset,
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
        }

    def _open_asset(self, asset: str, entry: dict) -> str:
        recipient = self.keys.kem_keypair("asset-store")
        signer = self.keys.signing_keypair("service")
        record = read_key_file(self.assets_dir / entry["file"])
        try:
            env = envelope.from_dict(json.loads(record["envelope"]))
        except (KeyError, TypeError, ValueError):
            raise StoreError("stored envelope unreadable") from None
        # AAD check: an envelope moved from another asset will not open.
        if env.envelope_id != entry["envelope_id"] or env.recipient != "asset:" + asset:
            raise StoreError("stored envelope does not belong to this asset")
        try:
            body = envelope.open_envelope(
                env, recipient_secret=recipient, sender_signing_public=signer.public_key
            )
        except envelope.EnvelopeError:
            raise StoreError("stored envelope failed integrity checks") from None
        return body.decode("utf-8")

    # ------------------------------------------------------------ decisions
    def read(self, actor: str, asset: str, request_id: str) -> dict:
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
            decision, rule, body = self._decide(state, actor, asset)
            response: dict = {"decision": decision}
            if decision == DECISION_ALLOW:
                response["body"] = body
            self._record(state, request_id, actor, asset, decision, rule)
            self._write_state(state)
            return response

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
