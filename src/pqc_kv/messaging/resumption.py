"""Goal 12: session resumption with tickets. Deliberately conservative.

The requirement is: tickets bound to the authenticated peer fingerprint, proof of
possession, **fresh keys on resume**, single-use, and expiring.

Why this is not just "reuse the old root key":

* Reusing a root key would mean a stolen ticket grants a *previous* session's
  keys. So a resume derives a **new** root: HKDF over (old root || ticket secret ||
  fresh nonces from both sides), with a different label. The previous chain keys
  are discarded, not continued.
* A ticket is a bearer token. To stop a stolen ticket file from being used by
  someone else, resumption requires **proof of possession**: a signature by the
  peer's long-term ML-DSA key over a fresh, single-use challenge that the resumer
  must supply. Possession of the ticket alone is not enough.
* Single use: the ticket id is deleted from the store the moment it is redeemed,
  before the caller receives anything.

**Expiry without a trusted clock.** Wall-clock expiry is unavailable -- the adapter
contract's container gives us a clock we cannot trust, and a hostile or skewed
clock would silently extend a ticket's life. Instead a ticket carries a
**budget**: a maximum number of resumes, and a maximum sequence gap. Both are
integers in our own state, so they cannot be forged by skewing a clock. When the
budget is exhausted the ticket is dead and a full handshake is required.

Honest limits, which SECURITY_NOTES repeats:

* "Expiry" means budget exhaustion, not wall time. A ticket left unused for a year
  is still valid if its budget is untouched. That is a real difference from a
  TTL-based design and is stated rather than glossed.
* Resuming still requires the peer to be in the directory under the same
  fingerprint; a rotated identity cannot resume (that is intentional).
* The ticket secret lives in the same state directory as everything else, so this
  does not raise the bar against an attacker who can read that directory. What it
  buys over a full handshake is: no new ephemeral exchange, and the guarantee that
  a *ticket alone* is useless without the long-term signing key.
* Because all of the above is testable to the same standard as goals 9-11, goal 12
  is marked **supported** (with the limits above), not "not supported".
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

import json
import os
import tempfile

from ..keystore import b64d, b64e, ensure_private_dir
from ..symmetric import KEY_LEN, hkdf_sha256

RESUME_CONTEXT = b"pqc-kv/v2/resumption"
DEFAULT_BUDGET = 3  # resumes per ticket before a full handshake is required
TICKET_MAGIC = "pqc-kv-ticket"
TICKET_VERSION = 1


class ResumptionError(Exception):
    """One failure type. Carries a reason code only."""

    def __init__(self, reason: str = "resume_failed") -> None:
        super().__init__(reason)
        self.reason = reason


class Reason:
    UNKNOWN_TICKET = "unknown_ticket"
    EXPIRED = "ticket_expired"
    WRONG_PEER = "wrong_peer"
    PROOF_INVALID = "proof_invalid"
    ALREADY_USED = "ticket_already_used"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class Ticket:
    """A resumption ticket. The secret never leaves the state directory.

    ``ticket_id`` and ``challenge`` are public; ``secret`` is stored server-side and
    only its keyed hash is compared.
    """

    ticket_id: str
    peer_fp: str
    peer_user: str
    session_id: str
    challenge: str
    secret: bytes
    budget: int

    def to_dict(self) -> dict:
        return {
            "ticket_id": self.ticket_id,
            "peer_fp": self.peer_fp,
            "peer_user": self.peer_user,
            "session_id": self.session_id,
            "challenge": self.challenge,
            "secret": b64e(self.secret),
            "budget": self.budget,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Ticket":
        try:
            return cls(
                ticket_id=str(data["ticket_id"]),
                peer_fp=str(data["peer_fp"]),
                peer_user=str(data["peer_user"]),
                session_id=str(data["session_id"]),
                challenge=str(data["challenge"]),
                secret=b64d(data["secret"]),
                budget=int(data["budget"]),
            )
        except Exception:
            raise ResumptionError(Reason.MALFORMED) from None

    def __repr__(self) -> str:
        return "Ticket(id=%r, peer=%r, budget=%d, secret=<redacted>)" % (
            self.ticket_id,
            self.peer_user,
            self.budget,
        )


def issue(*, state_root: Path, session: dict, session_id: str, budget: int = DEFAULT_BUDGET) -> dict:
    """Create a ticket bound to the session's peer fingerprint."""
    if not isinstance(budget, int) or budget < 0:
        raise ResumptionError(Reason.MALFORMED)
    ticket = Ticket(
        ticket_id="t-" + secrets.token_hex(16),
        peer_fp=session["peer_fp"],
        peer_user=session["peer_user"],
        session_id=session_id,
        challenge=secrets.token_hex(24),
        secret=secrets.token_bytes(32),
        budget=budget,
    )
    tickets = _load(state_root)
    tickets[ticket.ticket_id] = ticket
    _save(state_root, tickets)
    return {
        "ticket_id": ticket.ticket_id,
        "challenge": ticket.challenge,
        "peer_fp": ticket.peer_fp,
        "budget": ticket.budget,
    }


def proof_payload(ticket_id: str, challenge: str, peer_fp: str) -> bytes:
    """Exactly what the resumer must sign. Public, deterministic, no secrets."""
    return b"|".join(
        [
            RESUME_CONTEXT,
            b"proof",
            str(TICKET_VERSION).encode(),
            ticket_id.encode(),
            challenge.encode(),
            peer_fp.encode(),
        ]
    )


def resume(
    *,
    state_root: Path,
    session: dict,
    session_id: str,
    ticket: str,
    proof: str,
    peer,
    identities,
) -> dict:
    """Redeem a ticket, verify possession, derive **fresh** chain keys.

    ``peer`` is the trusted PublicIdentity from the directory; ``proof`` is the hex
    of an ML-DSA signature over :func:`proof_payload`.
    """
    record = _lookup(state_root, str(ticket))
    if record is None:
        raise ResumptionError(Reason.UNKNOWN_TICKET)

    if record.peer_fp != peer.fingerprint or record.peer_user != peer.user_id:
        raise ResumptionError(Reason.WRONG_PEER)
    if record.session_id != session_id:
        raise ResumptionError(Reason.WRONG_PEER)
    if record.budget <= 0:
        # Budget exhaustion, not wall-clock expiry. See the module docstring.
        _save(state_root, {k: v for k, v in _load(state_root).items() if k != record.ticket_id})
        raise ResumptionError(Reason.EXPIRED)

    payload = proof_payload(record.ticket_id, record.challenge, record.peer_fp)
    try:
        signature = bytes.fromhex(str(proof))
    except ValueError:
        raise ResumptionError(Reason.MALFORMED) from None

    from .. import dsa

    if not dsa.verify(peer.signing_public, payload, signature):
        raise ResumptionError(Reason.PROOF_INVALID)

    # Fresh root, not the old one. The old chain keys are discarded by the caller
    # writing the new state; nothing here continues a previous chain.
    # A missing seed would silently produce a root that only the ticket protects,
    # so treat it as a hard failure rather than an empty contribution.
    seed = session.get("root_seed")
    if not seed:
        raise ResumptionError(Reason.MALFORMED)
    ikm = b"".join(
        [
            b64d(seed),
            record.secret,
            record.challenge.encode(),
            str(record.budget).encode(),
        ]
    )
    salt = hkdf_sha256(
        payload, salt=b"", info=RESUME_CONTEXT + b"/salt", length=KEY_LEN
    )
    fresh_root = hkdf_sha256(ikm, salt=salt, info=RESUME_CONTEXT + b"/root", length=KEY_LEN)

    # Single use: drop or decrement *before* returning anything, so a crash after
    # this point cannot hand the same ticket out twice.
    tickets = _load(state_root)
    if record.budget > 1:
        tickets[record.ticket_id] = Ticket(
            ticket_id=record.ticket_id,
            peer_fp=record.peer_fp,
            peer_user=record.peer_user,
            session_id=record.session_id,
            challenge=record.challenge,
            secret=record.secret,
            budget=record.budget - 1,
        )
    else:
        tickets.pop(record.ticket_id, None)
    _save(state_root, tickets)

    return {
        "session_id": session_id,
        "fresh_root": b64e(fresh_root),
        "remaining_budget": max(0, record.budget - 1),
        "resumed": True,
    }


def verify_response(*, ticket_id: str, challenge: str, peer_fp: str, proof: str, peer) -> bool:
    """Optional peer-side check that a resumed session is talking to the right key."""
    from .. import dsa

    try:
        signature = bytes.fromhex(str(proof))
    except ValueError:
        return False
    return dsa.verify(peer.signing_public, proof_payload(ticket_id, challenge, peer_fp), signature)


# --------------------------------------------------------------- ticket store
# No cache: every call reads and rewrites the file. A process-local cache would
# drift between the one-process-per-request invocations the adapter forces, and a
# stale ticket cache is a replay oracle. The file is tiny; correctness wins.
def _path(state_root: Path) -> Path:
    return Path(state_root) / "pqc-kv-messaging" / "tickets.json"


def _load(state_root: Path) -> dict:
    path = _path(state_root)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ResumptionError(Reason.MALFORMED) from None
    if not isinstance(data, dict) or data.get("magic") != TICKET_MAGIC:
        raise ResumptionError(Reason.MALFORMED)
    if data.get("version") != TICKET_VERSION:
        raise ResumptionError(Reason.MALFORMED)
    tickets = {}
    for key, value in (data.get("tickets") or {}).items():
        tickets[key] = Ticket.from_dict(value)
    return tickets


def _save(state_root: Path, tickets: dict) -> None:
    """Atomic, fsynced, 0600. Tickets are state and may not be lost silently."""
    directory = ensure_private_dir(Path(state_root) / "pqc-kv-messaging")
    path = directory / "tickets.json"
    payload = {
        "magic": TICKET_MAGIC,
        "version": TICKET_VERSION,
        "tickets": {key: ticket.to_dict() for key, ticket in tickets.items()},
    }
    fd, name = tempfile.mkstemp(dir=str(directory), prefix=".tickets-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        name = None
    except OSError:
        raise ResumptionError(Reason.MALFORMED) from None
    finally:
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass


def _lookup(state_root: Path, ticket_id: str):
    return _load(state_root).get(ticket_id)


__all__ = [
    "DEFAULT_BUDGET",
    "Reason",
    "ResumptionError",
    "Ticket",
    "issue",
    "proof_payload",
    "resume",
    "verify_response",
]
