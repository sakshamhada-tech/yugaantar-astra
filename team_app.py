"""Adapter application layer: identity check -> policy -> encrypted asset read.

The adapter (``track4_service.py``) does JSON transport only; every decision
below is ours. The contract it implements (``docs/adapter-v1.md``):

    setup          initialise from supplied owners/contents/disabled/key_material
    read           allow with exact stored body, or deny with no content
    revoke         revoke an actor, persist, other actors unaffected
    audit          replay the recorded decision for a request id
    protected_read ML-KEM-768 encapsulation + HMAC-SHA-256 proof of the body

Design choices worth knowing:

* **Content is encrypted at rest.** Each setup seals every synthetic body with an
  ML-KEM-768 + HKDF + AES-256-GCM + ML-DSA-65 envelope (see ``src/pqc_kv``). The
  reader decapsulates and verifies, so a tampered file becomes a *deny*, not a
  wrong body.
* **One process per request**, so all state is on disk under ``TRACK4_STATE_DIR``
  (or the OS temp dir). Nothing is kept in module globals between calls.
* **Deny is silent**: a denied response carries no body, no reason and no hint
  whether the asset exists. The reason is written to the audit log instead.
* **No secrets in output.** The synthetic ``key_material`` value is sealed at rest
  and has no read path at all. Diagnostics never include it.
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path

# Make src/ importable no matter which directory the worker launches us from.
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pqc_kv import intent  # noqa: E402
from pqc_kv.deps import BACKEND  # noqa: E402
from pqc_kv.keystore import default_state_dir  # noqa: E402
from pqc_kv.store import StateStore, StoreError  # noqa: E402

# --- test-only fault injection, defused at import -----------------------------
# TRACK4_FAULT_AT is a crash-injection hook used by the Phase 3 recovery tests. It is
# read here, ONCE, from the environment, and then deleted from os.environ so that
# nothing downstream -- including a future bug -- can set it from a request payload.
# Only the five documented point names switch it on; anything else is ignored.
_FAULT_POINT_ACTIVE = intent.take_fault_configuration()

SUPPORTED_OPS = {"setup", "read", "revoke", "audit", "protected_read"}
# Phase 3: key lifecycle and log integrity. Additions, like the messaging ops: the
# contract explicitly says the twelve goals include capabilities outside its
# protected-resource interface.
KEY_OPS = {"rotate", "key_status", "log_verify", "log_head", "recover",
           "log_events_verify", "log_events_head",
           "cluster_publish", "cluster_sync", "cluster_status",
           "backup_create", "backup_restore"}
# Phase 2: messaging operations are additions to, not replacements for, the five
# contract operations. The adapter contract says the twelve goals include
# capabilities outside its protected-resource interface, and explicitly notes that
# end-to-end messaging, replay protection and forward secrecy need separate
# evidence. track4_service.py stays byte-identical to the starter.
# Phase 4: detection operations (checklist goals 6, 7, 8). Additions again, for the
# same reason as Phases 2 and 3 -- the contract says the twelve goals include
# capabilities outside its protected-resource interface. `track4_service.py` is
# untouched, and an unknown op still returns `unsupported_operation`.
DETECT_OPS = {"detect_log", "detect_append", "detect_status"}
MESSAGING_OPS = {
    "msg_identity", "msg_directory_add", "msg_directory_show",
    "msg_handshake_init", "msg_handshake_finish", "msg_handshake_complete",
    "msg_handshake_confirm", "msg_send", "msg_receive", "msg_status",
    "msg_ticket_issue", "msg_resume", "msg_close",
}


def _store() -> StateStore:
    return StateStore(default_state_dir())


def _log(message: str) -> None:
    """Diagnostics to stderr only. Never pass protected values through here."""
    print(f"track4: {message}", file=sys.stderr, flush=True)


def dispatch(request: dict) -> dict:
    op = request.get("op")
    if op in MESSAGING_OPS:
        return _dispatch_messaging(request)
    if op in DETECT_OPS:
        return _dispatch_detect(request)
    if op in KEY_OPS:
        return _dispatch_keys(request)
    if op not in SUPPORTED_OPS:
        return {"error": "unsupported_operation"}

    if not BACKEND.has_aead:
        _log("no AES-GCM backend available; refusing to claim encrypted service")
        return {"error": "crypto_backend_unavailable"}

    try:
        store = _store()
        if op == "setup":
            return _handle_setup(store, request)
        if op == "read":
            return _handle_read(store, request)
        if op == "revoke":
            return store.revoke(request.get("actor"))
        if op == "audit":
            return store.audit(request.get("request_id"))
        return _handle_protected_read(store, request)
    except StoreError:
        # Opaque: no paths, no state names, no exception text.
        return {"error": "request_failed"}
    except (KeyError, TypeError, ValueError):
        return {"error": "malformed_request"}


# --------------------------------------------------------------------- handlers
def _handle_setup(store: StateStore, request: dict) -> dict:
    try:
        return store.setup(request)
    except StoreError:
        return {"error": "setup_failed"}


def _handle_read(store: StateStore, request: dict) -> dict:
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return {"error": "malformed_request"}
    # Goal 1: `key_version` is how a request declares it is using an old key. Absent
    # means "whatever is active", which is what an ordinary client means.
    version = request.get("key_version")
    if version is not None:
        if not isinstance(version, int) or isinstance(version, bool):
            return {"error": "malformed_request"}
    return store.read(request.get("actor"), request.get("asset"), request_id, version)


def _handle_protected_read(store: StateStore, request: dict) -> dict:
    """Interoperable protected read: ML-KEM-768 + HMAC-SHA-256 proof.

    Contract: ``proof`` is lowercase hex HMAC-SHA-256 keyed by the KEM shared
    secret, over UTF-8 ``challenge + stored_body`` with no separator. The shared
    secret never leaves this process; only the KEM ciphertext and the proof do.
    """
    actor = request.get("actor")
    asset = request.get("asset")
    challenge = request.get("challenge")
    request_id = request.get("request_id") or ("pr-" + hashlib.sha256(
        (str(actor) + str(asset)).encode("utf-8", "replace")
    ).hexdigest()[:16])

    # Authorization and the audit record happen in one locked step (TOCTOU fix):
    # a revocation committed by another process mid-request cannot be missed.
    allowed, body, rule = store.protect_read(actor, asset, request_id)

    if not allowed:
        # Same shape as a plain deny: no content, no reason.
        return {"decision": "deny"}

    import base64

    from pqc_kv import kem

    # Note: the decision is already recorded by protect_read(), atomically with the
    # policy check. These failure paths deliberately do NOT record again -- doing so
    # would create a second event for one request (the duplicate rule would label it
    # `reject`), which is exactly the double-counting this project is trying to avoid.
    # The malformed-input reasons are visible in the adapter's stderr diagnostics.
    try:
        peer_public = base64.b64decode(str(request["public_key"]).encode("ascii"), validate=True)
    except Exception:
        return {"decision": "deny"}

    if not isinstance(challenge, str):
        return {"decision": "deny"}

    try:
        encapsulation = kem.encapsulate(peer_public)
    except kem.KemError:
        return {"decision": "deny"}

    mac = hmac.new(
        encapsulation.shared_secret,
        (challenge + body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "decision": "allow",
        "ciphertext": base64.b64encode(encapsulation.ciphertext).decode("ascii"),
        "proof": mac,
    }


# --------------------------------------------------------------------- Phase 2
def _dispatch_messaging(request: dict) -> dict:
    """Messaging operations. One generic failure; reasons stay in the audit log."""
    try:
        from pqc_kv.messaging import ops as messaging_ops

        return messaging_ops.dispatch(request)
    except Exception:
        # Never surface a messaging reason code to the caller: `wrong_recipient`
        # vs `signature_invalid` would be an oracle. One answer, like Phase 1.
        return {"error": "request_failed"}


# --------------------------------------------------------------------- Phase 4
def _dispatch_detect(request: dict) -> dict:
    """Detection operations: goals 6, 7 and 8.

    Two behaviours worth knowing:

    * The report *is* the answer. It carries the alerts, the counts of what was
      refused and why, the supported timing range, and per-source clock corrections,
      so a caller can audit the run without a second request.
    * High-signal findings are also written into the Phase 3 signed key-event log,
      so that a privilege-change or lateral-movement alert becomes tamper-evident
      rather than living only in a JSON response. The log's field policy is not
      weakened to make that work: the record carries ``rule`` and ``alert_id``, which
      are the detector's own validated tokens, never the prose explanation.
    """
    op = request.get("op")
    try:
        from pqc_kv.detect import ops as detect_ops

        handler = detect_ops.OPS[op]
        result = handler(request)
        if isinstance(result, dict) and result.get("error"):
            return result
        if op in ("detect_log", "detect_append"):
            _record_detections(result)
        return result
    except Exception:
        # One opaque failure, as everywhere else. A detector that explained its
        # own crash would be a debugging interface for hostile input.
        return {"error": "request_failed"}


def _record_detections(result: dict) -> None:
    """Append high-signal detections to the signed key-event log, best-effort.

    Reports *whether* it happened, in ``detections_signed``, rather than claiming
    success silently. Two reasons it can be skipped:

    * no alerts reached the recording bar (low-severity and follow-on findings are
      deliberately excluded -- see ``detect_ops.RECORDABLE_RULES``);
    * the adapter's own state has not been set up, so there is no key-event log to
      write to. Detection must work without the KV store being initialised, because
      these are separate capabilities: a caller may want detection over a log with
      no assets configured at all.

    A log write never changes the detection answer. Detection is the product; the
    log is the audit trail of it.
    """
    result["detections_signed"] = 0
    alerts = result.get("alerts") or []
    if not alerts:
        return
    try:
        from pqc_kv.detect import ops as detect_ops

        store = _store()
        # `record_event` raises when setup has not run. Check first, so the skip is a
        # reported fact rather than an exception we swallow.
        store._read_state()
    except Exception:
        result["detections_signed_error"] = "adapter_state_not_initialised"
        return
    written = 0
    try:
        for entry in alerts:
            if entry.get("rule") not in detect_ops.RECORDABLE_RULES:
                continue
            if entry.get("severity") not in ("high", "medium"):
                continue
            # Colon is in the log's identifier charset; "/" is not. Using a
            # separator the policy accepts is the right fix -- loosening the policy
            # for our own convenience is not.
            detail = f"{entry['rule']}:{entry['alert_id']}"
            store.record_event("detect", actor=entry.get("identity", ""),
                               detail=detail)
            written += 1
    except Exception:
        # A log failure must not fail the detection. The count says how far it got,
        # and `log_events_verify` shows the chain's own state.
        result["detections_signed_error"] = "log_write_failed"
    result["detections_signed"] = written


# --------------------------------------------------------------------- Phase 3
def _dispatch_keys(request: dict) -> dict:
    """Rotation and log-integrity operations. One opaque failure, as always."""
    op = request.get("op")
    try:
        store = _store()
        if op == "rotate":
            grace = request.get("grace", 2)
            if not isinstance(grace, int) or isinstance(grace, bool) or grace < 0:
                return {"error": "malformed_request"}
            return store.rotate({"grace": grace})
        if op == "key_status":
            status = store.key_status()
            # Deliberately reports *that* the hook is armed, never its value.
            status["fault_injection_active"] = bool(_FAULT_POINT_ACTIVE)
            return status
        if op == "recover":
            return store.recover()
        if op == "backup_create":
            # The operator supplies the key. It is used for this call and dropped; it
            # is never written to the state directory and never logged.
            secret = _decode_secret(request.get("backup_key"))
            if secret is None:
                return {"error": "malformed_request"}
            return {"backup": store.create_backup(secret)}
        if op == "backup_restore":
            secret = _decode_secret(request.get("backup_key"))
            blob = request.get("backup")
            if secret is None or not isinstance(blob, dict):
                return {"error": "malformed_request"}
            from pqc_kv.keystore import b64d as _b64d

            try:
                signing_public = _b64d(str(request.get("signing_public", "")))
            except Exception:
                return {"error": "malformed_request"}
            try:
                return store.restore_backup(blob, secret, signing_public)
            except Exception:
                # A damaged, tampered or stale backup is one opaque failure. The
                # operator's own script can tell them apart from the log.
                return {"error": "backup_refused"}
        if op == "log_verify":
            ok, records = store.verify_audit_chain()
            return {"ok": ok, "records": records}
        if op == "cluster_publish":
            kind = request.get("kind")
            if kind not in ("revoke", "rotate", "enrol"):
                return {"error": "malformed_request"}
            payload = request.get("payload")
            if not isinstance(payload, dict):
                return {"error": "malformed_request"}
            notice = store.publish_notice(kind, payload)
            # The publisher enforces its own notice immediately. Without this, the
            # one node that definitely knows about the revocation is the one node
            # that keeps honouring the old state -- found by the acceptance script.
            from pqc_kv.keystore import b64e as _b64e
            from pqc_kv.keystore import KeyStore as _KeyStore

            pair = _KeyStore(store.root / "cluster-identity").signing_keypair("cluster-publisher")
            applied = store.apply_notices([notice], pair.public_key)
            return {"published": True, "kind": notice["kind"], "seq": notice["seq"],
                    "applied_locally": applied["applied"], "notice": notice}
        if op == "cluster_sync":
            # Pull every notice currently in the shared outbox and apply the valid
            # ones. The outbox is a directory of *signed* blobs; trust comes from the
            # signature and the publisher key the caller pins, not from the location.
            publisher = request.get("publisher_public")
            if not isinstance(publisher, str):
                return {"error": "malformed_request"}
            import base64 as _b64

            try:
                publisher_bytes = _b64.b64decode(publisher.encode("ascii"), validate=True)
            except Exception:
                return {"error": "malformed_request"}
            outbox = store.cluster_outbox()
            notices = []
            if outbox.exists():
                import json as _json

                for path in sorted(outbox.glob("*.json")):
                    try:
                        notices.append(_json.loads(path.read_text(encoding="utf-8"))["notice"])
                    except Exception:
                        continue
            return store.apply_notices(notices, publisher_bytes)
        if op == "cluster_status":
            state = store._read_state()
            return {
                "active_version": state.get("active_version", 1),
                "remote_key_version": state.get("remote_key_version", 0),
                "disabled": sorted(state.get("disabled", [])),
            }
        if op == "log_events_verify":
            # Operator verification of the signed key-event log. `expected_head` is
            # the value the operator wrote down outside the state directory; without
            # it, a truncation is invisible (a shorter valid chain is still valid).
            expected = request.get("expected_head")
            if expected is not None and not isinstance(expected, str):
                return {"error": "malformed_request"}
            return store.verify_events(expected_head=expected)
        if op == "log_events_head":
            return store.events_head()
        if op == "log_head":
            # Deliberately just the head digest: an operator stores this elsewhere
            # and later proves the file has not been rewritten or truncated.
            return store.log_head()
        return {"error": "unsupported_operation"}
    except Exception:
        # Rotation can fail for many reasons; none of them is the caller's business.
        return {"error": "request_failed"}


def _decode_secret(value) -> bytes | None:
    """Decode the operator's backup key from base64. Never echoed, never stored."""
    if not isinstance(value, str):
        return None
    import base64 as _b64

    try:
        secret = _b64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return None
    return secret if len(secret) >= 16 else None
