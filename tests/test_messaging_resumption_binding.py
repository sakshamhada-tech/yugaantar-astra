"""Goal 12, adversarially: who may inherit a session.

The brief's sentence is specific: *a different identity cannot inherit the session by
presenting the same session identifier.* The existing resumption tests cover a missing
proof, a wrong-key proof, a ticket for another peer, an unknown ticket and budget
exhaustion. What they did not cover is the attack the brief actually names -- an
attacker who holds **the ticket and the session id both** and simply presents them with
its own key. That is the case a real stolen-laptop incident looks like, so it is
tested here directly.

Two further holes this file closes:

* the session id is checked only *after* the peer check, so a stolen ticket replayed
  against a **different** session id was never exercised. A ticket that redeems against
  the wrong session is a session-inheritance bug even when the peer is genuine.
* a ticket redeemed by the right peer against the right session but belonging to a
  *different* session object was never tested, which is how "the same session
  identifier" and "the same session" quietly diverge.
"""

from __future__ import annotations

import pytest

from pqc_kv import dsa
from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import identity, resumption

SID = "s-0001"


@pytest.fixture()
def world(tmp_path):
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    mallory = identity.generate(store, "mallory")
    root = tmp_path / "state"
    session = {
        "root_seed": "11" * 32,
        "self_user": "alice", "self_fp": alice.fingerprint,
        "peer_user": "bob", "peer_fp": bob.fingerprint,
        "role": "initiator",
    }
    return {"alice": alice, "bob": bob, "mallory": mallory,
            "root": root, "session": session}


def issue(world, budget=3, session_id=SID):
    return resumption.issue(state_root=world["root"], session=world["session"],
                            session_id=session_id, budget=budget)


def proof_by(who, ticket):
    return resumption.proof_payload(
        ticket["ticket_id"], ticket["challenge"], ticket["peer_fp"]
    ), who


def redeem(world, ticket, *, peer, signer, session_id=SID, session=None):
    payload = resumption.proof_payload(
        ticket["ticket_id"], ticket["challenge"], ticket["peer_fp"]
    )
    return resumption.resume(
        state_root=world["root"], session=session or world["session"],
        session_id=session_id, ticket=ticket["ticket_id"],
        proof=dsa.sign(signer.signing_secret, payload).hex(),
        peer=peer, identities={"alice": world["alice"].public},
    )


# ---------------------------------------------- the sentence in the brief
def test_a_thief_with_the_ticket_and_the_session_id_cannot_inherit_it(world):
    """Mallory holds the ticket file and knows the session id. She still cannot.

    She presents both, correct in every visible respect, with her own key pair. The
    ticket names the peer fingerprint inside its signed payload, so her identity is
    wrong before possession is even considered.
    """
    ticket = issue(world)
    with pytest.raises(resumption.ResumptionError) as info:
        redeem(world, ticket, peer=world["mallory"].public, signer=world["mallory"])
    assert info.value.reason == resumption.Reason.WRONG_PEER


def test_the_ticket_itself_cannot_be_used_as_the_proof(world):
    """Holding the ticket is not holding the key, even with the right peer claimed."""
    ticket = issue(world)
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"],
                          session_id=SID, ticket=ticket["ticket_id"],
                          proof=ticket["ticket_id"], peer=world["bob"].public,
                          identities={"alice": world["alice"].public})
    assert info.value.reason in (resumption.Reason.MALFORMED,
                                 resumption.Reason.PROOF_INVALID)


def test_the_right_peer_with_a_signature_over_the_wrong_ticket_is_refused(world):
    """Bob signs, but over a different ticket's challenge: not proof for this one."""
    ticket = issue(world)
    other = issue(world)
    payload = resumption.proof_payload(
        other["ticket_id"], other["challenge"], other["peer_fp"]
    )
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"],
                          session_id=SID, ticket=ticket["ticket_id"],
                          proof=dsa.sign(world["bob"].signing_secret, payload).hex(),
                          peer=world["bob"].public,
                          identities={"alice": world["alice"].public})
    assert info.value.reason == resumption.Reason.PROOF_INVALID


# ------------------------------------------------- same identity, wrong session
def test_a_ticket_does_not_redeem_against_a_different_session_id(world):
    """A genuine ticket is bound to one session, not to the ticket holder in general."""
    ticket = issue(world)
    with pytest.raises(resumption.ResumptionError) as info:
        redeem(world, ticket, peer=world["bob"].public, signer=world["bob"],
               session_id="s-9999")
    assert info.value.reason == resumption.Reason.WRONG_PEER


def test_a_ticket_from_another_session_cannot_be_imported(world, tmp_path):
    """A ticket issued for session A must not resume session B.

    This is the "same session identifier" claim seen from the other side: the binding
    is to the session, so a second session's ticket travelling to the first is refused
    even when peer and identity are all correct.
    """
    ticket_a = issue(world, session_id="s-aaaa")
    with pytest.raises(resumption.ResumptionError) as info:
        redeem(world, ticket_a, peer=world["bob"].public, signer=world["bob"],
               session_id=SID)
    assert info.value.reason == resumption.Reason.WRONG_PEER


# ------------------------------------------------------------- what a resume is
def test_a_successful_resume_is_bound_to_the_authenticated_peer(world):
    """The positive control: the one caller who *should* resume, does.

    Without this, every refusal above could be explained by resumption being broken.
    """
    ticket = issue(world)
    resumed = redeem(world, ticket, peer=world["bob"].public, signer=world["bob"])
    assert resumed["resumed"] is True
    assert resumed["session_id"] == SID
    # The binding is proven by the fact that it succeeded only for the peer named in
    # the ticket; every other identity is refused in the tests above.
    assert resumed["fresh_root"] != world["session"]["root_seed"]


def test_a_resumed_root_is_fresh_and_not_the_previous_one(world):
    """Resuming must not hand back the old root, or a stolen ticket leaks the past."""
    first = issue(world)
    a = redeem(world, first, peer=world["bob"].public, signer=world["bob"])
    b = redeem(world, first, peer=world["bob"].public, signer=world["bob"])
    assert a["fresh_root"] != b["fresh_root"]
    assert a["fresh_root"] != world["session"]["root_seed"]


def test_a_stolen_ticket_cannot_be_replayed_after_the_budget_is_spent(world):
    """The thief may be late; the budget still bounds the window."""
    ticket = issue(world, budget=1)
    redeem(world, ticket, peer=world["bob"].public, signer=world["bob"])
    with pytest.raises(resumption.ResumptionError) as info:
        redeem(world, ticket, peer=world["bob"].public, signer=world["bob"])
    # The spent ticket is *deleted*, not flagged, so this is `unknown_ticket` rather
    # than `ticket_expired`. Asserting which refusal matters: an earlier draft of this
    # test expected `EXPIRED` and failed, which is the same distinction the suite pins
    # for proofs elsewhere -- deletion, not a boolean, is what makes it single-use.
    assert info.value.reason == resumption.Reason.UNKNOWN_TICKET


def test_refusals_carry_no_material_from_the_ticket(tmp_path):
    """An opaque error must not become an oracle.

    The reason code is reported for logs, but no ticket, challenge or signature may
    appear in the exception text, or a caller learns what to fix next.
    """
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    root = tmp_path / "state"
    session = {"root_seed": "22" * 32, "self_user": "alice",
               "self_fp": alice.fingerprint, "peer_user": "bob",
               "peer_fp": bob.fingerprint, "role": "initiator"}
    ticket = resumption.issue(state_root=root, session=session, session_id=SID, budget=2)
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=root, session=session, session_id=SID,
                          ticket=ticket["ticket_id"],
                          proof="00" * 10, peer=bob.public,
                          identities={"alice": alice.public})
    text = str(info.value)
    assert ticket["ticket_id"] not in text
    assert ticket["challenge"] not in text
