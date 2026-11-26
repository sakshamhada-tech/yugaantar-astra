"""Goal 12: tickets bound to the peer, proof of possession, fresh keys, single use."""

from __future__ import annotations

import pytest

from pqc_kv import dsa
from pqc_kv.keystore import KeyStore, b64e
from pqc_kv.messaging import identity, resumption

SESSION_ID = "s-" + "1" * 32


@pytest.fixture()
def world(tmp_path):
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    session = {
        "peer_fp": bob.fingerprint,
        "peer_user": "bob",
        "self_user": "alice",
        "root_seed": b64e(b"r" * 32),
        "transcript_hash": b64e(b"t" * 32),
    }
    # The session belongs to alice, and its peer is bob. The ticket is bound to
    # bob's fingerprint, so resuming requires BOB's proof of possession.
    return {"root": tmp_path / "state", "alice": alice, "bob": bob, "session": session,
            "self": alice}


def issue(world, budget=3):
    return resumption.issue(state_root=world["root"], session=world["session"],
                            session_id=SESSION_ID, budget=budget)


def make_proof(world, ticket, signer=None):
    signer = signer or world["bob"]  # ticket is bound to the peer = bob
    payload = resumption.proof_payload(ticket["ticket_id"], ticket["challenge"], ticket["peer_fp"])
    return signer.sign(payload).hex()


def test_issue_binds_peer_fingerprint(world):
    ticket = issue(world)
    assert ticket["peer_fp"] == world["bob"].fingerprint
    assert ticket["budget"] == 3
    assert len(ticket["ticket_id"]) > 8


def test_resume_with_valid_proof_gives_fresh_root(world):
    ticket = issue(world)
    result = resumption.resume(
        state_root=world["root"], session=world["session"], session_id=SESSION_ID,
        ticket=ticket["ticket_id"], proof=make_proof(world, ticket),
        peer=world["bob"].public, identities=world["self"],
    )
    assert result["resumed"] is True
    # Fresh: not equal to the seed the session started from.
    assert result["fresh_root"] != world["session"]["root_seed"]


def test_each_resume_yields_a_different_root(world):
    first_ticket = issue(world)
    a = resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket=first_ticket["ticket_id"], proof=make_proof(world, first_ticket),
                          peer=world["bob"].public, identities=world["self"])
    b = resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket=first_ticket["ticket_id"], proof=make_proof(world, first_ticket),
                          peer=world["bob"].public, identities=world["self"])
    assert a["fresh_root"] != b["fresh_root"]


def test_missing_proof_is_refused(world):
    ticket = issue(world)
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket=ticket["ticket_id"], proof="", peer=world["bob"].public,
                          identities=world["self"])
    assert info.value.reason == resumption.Reason.PROOF_INVALID


def test_proof_from_the_wrong_key_is_refused(world, tmp_path):
    """Possession of the ticket file alone must be useless."""
    thief = identity.generate(KeyStore(tmp_path / "thief"), "mallory")
    ticket = issue(world)
    payload = resumption.proof_payload(ticket["ticket_id"], ticket["challenge"], ticket["peer_fp"])
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket=ticket["ticket_id"], proof=thief.sign(payload).hex(),
                          peer=world["bob"].public, identities=world["self"])
    assert info.value.reason == resumption.Reason.PROOF_INVALID


def test_ticket_for_another_peer_is_refused(world, tmp_path):
    carol = identity.generate(KeyStore(tmp_path / "c"), "carol")
    ticket = issue(world)
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket=ticket["ticket_id"], proof=make_proof(world, ticket),
                          peer=carol.public, identities=world["self"])
    assert info.value.reason == resumption.Reason.WRONG_PEER


def test_unknown_ticket_is_refused(world):
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket="t-nope", proof="00" * 10, peer=world["bob"].public,
                          identities=world["self"])
    assert info.value.reason == resumption.Reason.UNKNOWN_TICKET


def test_budget_exhaustion_expires_the_ticket(world):
    ticket = issue(world, budget=1)
    resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                      ticket=ticket["ticket_id"], proof=make_proof(world, ticket),
                      peer=world["bob"].public, identities=world["self"])
    with pytest.raises(resumption.ResumptionError) as info:
        resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                          ticket=ticket["ticket_id"], proof=make_proof(world, ticket),
                          peer=world["bob"].public, identities=world["self"])
    assert info.value.reason == resumption.Reason.UNKNOWN_TICKET


def test_budget_decrements_and_is_reported(world):
    ticket = issue(world, budget=3)
    result = resumption.resume(state_root=world["root"], session=world["session"], session_id=SESSION_ID,
                               ticket=ticket["ticket_id"], proof=make_proof(world, ticket),
                               peer=world["bob"].public, identities=world["self"])
    assert result["remaining_budget"] == 2


def test_ticket_file_is_private(world):
    import stat
    issue(world)
    path = world["root"] / "pqc-kv-messaging" / "tickets.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_ticket_secret_never_appears_in_output(world):
    import json
    ticket = issue(world)
    blob = json.dumps(ticket)
    assert "secret" not in blob


def test_missing_root_seed_is_a_hard_failure(tmp_path):
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    session = {"peer_fp": bob.fingerprint, "peer_user": "bob", "root_seed": None}
    root = tmp_path / "state"
    ticket = resumption.issue(state_root=root, session=session, session_id=SESSION_ID, budget=1)
    with pytest.raises(resumption.ResumptionError):
        resumption.resume(state_root=root, session=session, session_id=SESSION_ID,
                          ticket=ticket["ticket_id"], proof=make_proof({"bob": bob}, ticket),
                          peer=bob.public, identities=alice)


def test_verify_response_helper(world):
    ticket = issue(world)
    proof = make_proof(world, ticket)
    assert resumption.verify_response(ticket_id=ticket["ticket_id"], challenge=ticket["challenge"],
                                      peer_fp=ticket["peer_fp"], proof=proof,
                                      peer=world["bob"].public) is True
    assert resumption.verify_response(ticket_id=ticket["ticket_id"], challenge="other",
                                      peer_fp=ticket["peer_fp"], proof=proof,
                                      peer=world["bob"].public) is False


def test_ticket_repr_hides_secret(world):
    ticket = issue(world)
    record = resumption._lookup(world["root"], ticket["ticket_id"])
    assert record.secret.hex()[:16] not in repr(record)
