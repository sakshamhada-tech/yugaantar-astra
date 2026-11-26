"""Adapter operations for messaging.

These are *additions* to the five contract operations, not replacements. The
adapter contract fixes the protected-resource interface and explicitly says the
twelve goals include capabilities outside it; `docs/adapter-v1.md` also notes that
end-to-end messaging, replay protection and forward secrecy "each require separate
evidence". So the ops below live behind the same generic JSON shim
(`track4_service.py`, unchanged) and `setup` remains exactly as specified.

    msg_identity        create/load a local identity, list its fingerprint
    msg_directory_add   publish a public identity into the local directory
    msg_directory_show  list known peers + the directory digest
    msg_handshake_init  step 1: produce hello, persist initiator ephemerals
    msg_handshake_finish step 2: responder accepts, derives keys (no persistence)
    msg_handshake_complete step 3: initiator finalises, erases ephemerals, confirm
    msg_handshake_confirm  step 3 received by responder: mutual confirmation
    msg_send            encrypt + fragment a body for the peer
    msg_receive         accept a batch of fragments, deliver complete messages
    msg_status          session facts (counters, no keys)
    msg_ticket_issue    resumption ticket (goal 12), if supported
    msg_resume          consume a ticket and derive fresh keys
    msg_close           delete session state

Error handling rule for every op: one generic failure. The response is
``{"error": "request_failed"}`` with no detail; the reason code goes to the audit
log only. No plaintext, no keys, no field-level hints ever leave the process.
"""

from __future__ import annotations

from pathlib import Path

from ..keystore import KeyStore, default_state_dir
from ..store import StateStore
from . import driver, handshake as hs, identity, wire
from .directory import Directory, DirectoryError
from .ephemeral import EphemeralError
from .kdf import RatchetError
from .session import SessionError, SessionStore
from . import resumption

OPS = {
    "msg_identity",
    "msg_directory_add",
    "msg_directory_show",
    "msg_handshake_init",
    "msg_handshake_finish",
    "msg_handshake_complete",
    "msg_handshake_confirm",
    "msg_send",
    "msg_receive",
    "msg_status",
    "msg_ticket_issue",
    "msg_resume",
    "msg_close",
}


class OpsError(Exception):
    """One failure type for every messaging op. Carries a reason code, nothing else."""

    def __init__(self, reason: str = "request_failed") -> None:
        super().__init__(reason)
        self.reason = reason


def _root() -> Path:
    return default_state_dir()


def _policy():
    """Wire Phase 1 revocation into messaging.

    Reads the StateStore's disabled list on each call (cheap: one small JSON file)
    so a revocation applied by the protected-resource side immediately applies to
    messaging, without the two subsystems sharing a cache.
    """

    def policy(user_id: str, action: str) -> bool:
        # StateStore.is_revoked takes the store's lock and returns False when no
        # setup has run, which is the right default: messaging is usable for an
        # identity that was never registered, and a revocation is an explicit act.
        return not StateStore(_root()).is_revoked(user_id)

    return policy


def _identity(user_id) -> identity.PrivateIdentity:
    # Coercing None to "None" would silently create an identity for a bogus id.
    if not isinstance(user_id, str) or not user_id.strip():
        raise OpsError("malformed_request")
    return identity.generate(KeyStore(_root() / "pqc-kv-messaging" / "identities"), user_id)


def _directory() -> Directory:
    return Directory(_root())


def _sessions() -> SessionStore:
    return SessionStore(_root())


def _session(session_id: str) -> dict:
    try:
        return _sessions().get(session_id)
    except SessionError:
        raise OpsError(wire.FailureReason.UNKNOWN_SESSION) from None


def dispatch(request: dict) -> dict:
    """Entry point used by team_app. Always returns a dict; never leaks detail."""
    op = request.get("op")
    if op not in OPS:
        raise OpsError("unsupported_operation")

    try:
        if op == "msg_identity":
            who = _identity(request.get("user_id"))
            response = {"user_id": who.user_id, "fingerprint": who.fingerprint}
            # The public record is what a peer needs to pin us. It is public by
            # definition (it is the directory entry), so exporting it leaks nothing
            # that a fingerprint comparison would not reveal anyway.
            if request.get("export_public"):
                response["public"] = who.public.to_dict()
            return response

        if op == "msg_directory_add":
            record = request["identity"]
            peer = identity.PublicIdentity.from_dict(record)
            _directory().add(peer)
            return {"added": peer.user_id, "fingerprint": peer.fingerprint}

        if op == "msg_directory_show":
            directory = _directory()
            return {
                "users": directory.known_users(),
                "directory_digest": directory.fingerprint(),
            }

        if op == "msg_handshake_init":
            who = _identity(request.get("self_user"))
            peer = _directory().lookup(str(request["peer_user"]))
            hello, session_id = hs.initiate(
                identity=who, peer=peer, state_root=_root(), session_id=request.get("session_id")
            )
            return {"hello": hello.to_dict(), "session_id": session_id}

        if op == "msg_handshake_finish":
            who = _identity(request.get("self_user"))
            hello = hs.Hello.from_dict(request["hello"])
            peer = _directory().lookup(hello.initiator_user)
            accept, keys = hs.respond(
                identity=who, hello=hello, peer=peer, directory_lookup=lambda u: _directory().lookup(u)
            )
            _create_session(keys, hello.session_id)
            return {"accept": accept.to_dict(), "session_id": hello.session_id}

        if op == "msg_handshake_complete":
            who = _identity(request.get("self_user"))
            accept = hs.Accept.from_dict(request["accept"])
            peer = _directory().lookup(accept.responder_user)
            confirm, keys = hs.complete(
                identity=who, accept=accept, state_root=_root(), peer=peer
            )
            # Emitting the confirm finishes the handshake for the initiator: there is
            # no fourth message. The responder only becomes confirmed once it
            # verifies this confirm, which is why msg_handshake_confirm sets its own.
            _create_session(keys, accept.session_id, confirmed=True)
            return {"confirm": confirm.to_dict(), "session_id": accept.session_id}

        if op == "msg_handshake_confirm":
            who = _identity(request.get("self_user"))
            message = hs.Confirm.from_dict(request["confirm"])
            peer = _directory().lookup(message.initiator_user)
            session = _session(message.session_id)
            hs.confirm(
                identity=who,
                message=message,
                session_transcript=_unb64(session["transcript_hash"]),
                peer=peer,
            )
            state = _sessions().mutate(
                message.session_id, lambda s: {**s, "confirmed": True}
            )
            return {"session_id": message.session_id, "confirmed": state["confirmed"]}

        if op == "msg_send":
            session_id = str(request["session_id"])
            session = _session(session_id)
            peer = _directory().lookup(session["peer_user"])
            body = str(request.get("body", "")).encode("utf-8")
            # The signing secret comes from this installation's keystore; the
            # session only needs to remember who it belongs to.
            self_identity = _identity(session["self_user"])
            fragments = driver.send_message(
                state_root=_root(),
                session_id=session_id,
                session=session,
                recipient=peer,
                body=body,
                signer_public=self_identity.public.signing_public,
                signing_secret=self_identity.signing_secret,
                fragment_bytes=int(request.get("fragment_bytes", driver.DEFAULT_FRAGMENT_BYTES)),
                policy=_policy(),
            )
            return {
                "session_id": session_id,
                "fragment_count": len(fragments),
                "fragments": fragments,
            }

        if op == "msg_receive":
            session_id = str(request["session_id"])
            session = _session(session_id)
            peer = _directory().lookup(session["peer_user"])
            result = driver.receive_fragments(
                state_root=_root(),
                session_id=session_id,
                fragments=list(request.get("fragments") or []),
                peer=peer,
                policy=_policy(),
            )
            return {
                "delivered": [
                    {
                        "message_id": m.message_id,
                        "sequence": m.sequence,
                        "body": m.body.decode("utf-8", "replace"),
                        "fragment_count": m.fragment_count,
                    }
                    for m in result.delivered
                ],
                "failures": result.failures,
                "duplicate_fragments": result.duplicate_fragments,
            }

        if op == "msg_status":
            session_id = str(request["session_id"])
            session = _session(session_id)
            return {
                "session_id": session_id,
                "role": session["role"],
                "peer_user": session["peer_user"],
                "peer_fp": session["peer_fp"],
                "sent": int(session.get("sent", 0)),
                "received": int(session.get("received", 0)),
                "partials": len(session.get("partials", {})),
                "confirmed": bool(session.get("confirmed", False)),
            }

        if op == "msg_ticket_issue":
            return resumption.issue(
                state_root=_root(),
                session=_session(str(request["session_id"])),
                session_id=str(request["session_id"]),
                budget=int(request.get("budget", resumption.DEFAULT_BUDGET)),
            )

        if op == "msg_resume":
            session_id = str(request["session_id"])
            return resumption.resume(
                state_root=_root(),
                session=_session(session_id),
                session_id=session_id,
                ticket=str(request["ticket"]),
                proof=str(request["proof"]),
                peer=identity.PublicIdentity.from_dict(request["peer"]),
                identities=_identity(str(request["self_user"])),
            )

        if op == "msg_close":
            session_id = str(request["session_id"])
            removed = _sessions().delete(session_id)
            return {"session_id": session_id, "closed": removed}

    except OpsError:
        raise
    except (hs.HandshakeError, wire.WireError, RatchetError, SessionError,
            DirectoryError, EphemeralError, driver.DriverError) as error:
        # One opaque failure; the code is for the audit log, not the caller.
        raise OpsError(getattr(error, "reason", "request_failed")) from None
    except (KeyError, TypeError, ValueError):
        raise OpsError("malformed_request") from None
    except Exception:
        raise OpsError("request_failed") from None

    raise OpsError("unsupported_operation")


def _create_session(keys: hs.SessionKeys, session_id: str, *, confirmed: bool = False) -> None:
    """Persist a new session's ratchet state. Secrets stay in the state directory."""
    session = {
        "self_user": keys.self_user,
        "self_fp": keys.self_fp,
        "peer_user": keys.peer_user,
        "peer_fp": keys.peer_fp,
        "role": keys.role,
        "transcript_hash": _b64(keys.transcript_hash),
        # Seed for future resumption: HKDF derives a *fresh* root from this plus the
        # ticket secret. Storing it means resumption is only as strong as this file,
        # which is stated in SECURITY_NOTES section 11.
        "root_seed": _b64(keys.root_key),
        "send": driver.SendRatchet(keys.send_chain).to_dict(),
        "recv": driver.ReceiveRatchet(keys.recv_chain).to_dict(),
        "next_message_id": "m-00000001",
        "seen_ids": [],
        "partials": {},
        "confirmed": confirmed,
    }
    _sessions().put(session_id, session)


def _b64(value: bytes) -> str:
    import base64

    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    import base64

    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        raise OpsError("malformed_request") from None
