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

from pqc_kv.deps import BACKEND  # noqa: E402
from pqc_kv.keystore import default_state_dir  # noqa: E402
from pqc_kv.store import StateStore, StoreError  # noqa: E402

SUPPORTED_OPS = {"setup", "read", "revoke", "audit", "protected_read"}
# Phase 2: messaging operations are additions to, not replacements for, the five
# contract operations. The adapter contract says the twelve goals include
# capabilities outside its protected-resource interface, and explicitly notes that
# end-to-end messaging, replay protection and forward secrecy need separate
# evidence. track4_service.py stays byte-identical to the starter.
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
    return store.read(request.get("actor"), request.get("asset"), request_id)


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

    allowed, body, rule = store.open_for_protected_read(actor, asset)

    if not allowed:
        store.record_external(request_id, actor, asset, "deny", rule)
        # Same shape as a plain deny: no content, no reason.
        return {"decision": "deny"}

    import base64

    from pqc_kv import kem

    try:
        peer_public = base64.b64decode(str(request["public_key"]).encode("ascii"), validate=True)
    except Exception:
        store.record_external(request_id, actor, asset, "deny", "malformed_public_key")
        return {"decision": "deny"}

    if not isinstance(challenge, str):
        store.record_external(request_id, actor, asset, "deny", "malformed_challenge")
        return {"decision": "deny"}

    try:
        encapsulation = kem.encapsulate(peer_public)
    except kem.KemError:
        store.record_external(request_id, actor, asset, "deny", "invalid_public_key")
        return {"decision": "deny"}

    mac = hmac.new(
        encapsulation.shared_secret,
        (challenge + body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    store.record_external(request_id, actor, asset, "allow", rule)
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
