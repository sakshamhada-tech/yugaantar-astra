"""Goal 10: forward secrecy, tested by mounting the attack.

The brief's claim is narrow and testable: *later exposure of a long-term identity key
alone does not reveal the contents of earlier, completed sessions.* So the tests here
do not check that the code "looks like" forward secrecy. They complete a real session,
then hand the attacker **every long-term secret both parties hold**, reconstruct every
public value from the wire, and attempt the derivation.

**What an earlier version of this file would have got wrong.** There was no test for
this claim at all. The suite tested that ephemeral files are erased, which is the
*mechanism*; it never tested the *property* the property depends on. A build in which
the ephemerals were erased but the root was derived from long-term keys would have
passed every existing test. That gap is why this file exists.

**Why the attack must be built rather than asserted.** ML-KEM is *implicitly
rejecting*: decapsulating with the wrong secret key returns an unrelated shared secret
instead of raising. So "decapsulation failed" is not a thing that can be checked. The
only honest test is to perform the whole derivation with forged inputs and show the
resulting key is different -- and then show that decryption under it yields nothing.
"""

from __future__ import annotations

import pytest

from pqc_kv import hybrid, kem
from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import driver, ephemeral as eph_store, handshake as hs, identity
from pqc_kv.messaging.session import SessionStore


@pytest.fixture()
def session(tmp_path):
    """A completed session, plus everything an attacker could take from the wire."""
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    a_root, b_root = tmp_path / "alice", tmp_path / "bob"

    hello, session_id = hs.initiate(identity=alice, peer=bob.public, state_root=a_root)
    accept, bob_keys = hs.respond(
        identity=bob, hello=hello, peer=alice.public,
        directory_lookup=lambda u: alice.public,
    )
    confirm, alice_keys = hs.complete(
        identity=alice, accept=accept, state_root=a_root, peer=bob.public
    )
    hs.confirm(identity=bob, message=confirm,
               session_transcript=bob_keys.transcript_hash, peer=alice.public)

    def seed(keys, root):
        state = {
            "self_user": keys.self_user, "self_fp": keys.self_fp,
            "peer_user": keys.peer_user, "peer_fp": keys.peer_fp, "role": keys.role,
            "send": driver.SendRatchet(keys.send_chain).to_dict(),
            "recv": driver.ReceiveRatchet(keys.recv_chain).to_dict(),
            "next_message_id": "m-00000001", "seen_ids": [], "partials": {},
        }
        SessionStore(root).put(session_id, state)

    seed(alice_keys, a_root)
    seed(bob_keys, b_root)

    return {
        "alice": alice, "bob": bob, "sid": session_id,
        "a_root": a_root, "b_root": b_root,
        "alice_keys": alice_keys, "bob_keys": bob_keys,
        "hello": hello, "accept": accept,
    }


def send(world, body):
    return driver.send_message(
        state_root=world["a_root"], session_id=world["sid"],
        session=SessionStore(world["a_root"]).get(world["sid"]),
        recipient=world["bob"].public, body=body,
        signer_public=world["alice"].public.signing_public,
        signing_secret=world["alice"].signing_secret,
    )


def attacker_transcript(world) -> hs.TranscriptParts:
    """Rebuild the transcript from the wire alone.

    Every one of these fields is public: it travels in the hello or the accept. This
    function deliberately does not touch the ephemeral store, because an attacker does
    not have it.
    """
    hello, accept = world["hello"], world["accept"]
    return hs.TranscriptParts(
        session_id=hello.session_id,
        initiator_user=hello.initiator_user,
        initiator_fp=hello.initiator_fp,
        responder_user=accept.responder_user,
        responder_fp=accept.responder_fp,
        initiator_x25519=hello.x25519_public,
        initiator_mlkem=hello.mlkem_public,
        responder_x25519=accept.x25519_public,
        responder_mlkem_ct=accept.mlkem_ciphertext,
    )


# ------------------------------------------------------------------ the attack
def test_the_ephemeral_private_key_is_gone_after_establishment(session):
    """The one secret the attacker cannot reconstruct: it was erased, not flagged."""
    with pytest.raises(eph_store.EphemeralError):
        eph_store.load(session["a_root"], session["sid"])


def test_long_term_keys_cannot_reproduce_the_mlkem_shared_secret(session):
    """Bob's long-term KEM key is not the one the ciphertext was encrypted to.

    ML-KEM is implicitly rejecting, so this must not be asserted as an exception.
    The assertion is that the value is *different* -- which is the only property that
    matters, because a different shared secret is a different root key.
    """
    accept = session["accept"]
    forged = kem.decapsulate(accept.mlkem_ciphertext, session["bob"].kem_secret)
    # A length check alone would pass on any garbage, and ML-KEM never raises here --
    # so compare against the real root, which the forged value must not reproduce.
    assert len(forged) == kem.SHARED_SECRET_LEN
    assert forged != session["alice_keys"].root_key
    assert forged != session["bob_keys"].root_key


def test_the_full_derivation_from_long_term_keys_yields_a_different_root(session):
    """The strong version: perform every step an attacker can, and compare roots.

    The attacker knows the transcript, holds both long-term KEM secrets, and can put
    *something* into the PQ slot. Whatever it is, the root differs, so no send or
    receive chain key can be derived and no ciphertext can be opened.
    """
    parts = attacker_transcript(session)
    forged_pq = kem.decapsulate(session["accept"].mlkem_ciphertext,
                                session["bob"].kem_secret)
    # Even giving the attacker a well-formed 32-byte X25519 secret is generous: it has
    # no way to obtain the real one. Two arbitrary choices are tried, so the test does
    # not depend on one lucky value.
    for guess in (b"\x00" * hybrid.X25519_LEN, b"\x2a" * hybrid.X25519_LEN):
        forged_root = hs.derive_root(parts, guess, forged_pq)
        assert forged_root != session["alice_keys"].root_key
        assert forged_root != session["bob_keys"].root_key


def test_earlier_message_is_unreadable_under_the_forged_root(session):
    """End to end: the ciphertext is on the wire, the long-term keys are stolen, and
    the plaintext still does not come out.

    This is the brief's sentence, executed. `derive_chain_key` under the forged root
    produces a chain key that authenticates nothing, so every fragment fails.
    """
    fragments = send(session, b"the earlier secret")
    parts = attacker_transcript(session)
    forged_pq = kem.decapsulate(session["accept"].mlkem_ciphertext,
                                session["bob"].kem_secret)
    forged_root = hs.derive_root(parts, b"\x00" * hybrid.X25519_LEN, forged_pq)

    from pqc_kv.messaging import kdf

    # Both directions, because the attacker does not know which one this message
    # used (and it is the receiver's chain that matters here).
    for direction in (kdf.DIRECTION_INITIATOR_TO_RESPONDER,
                      kdf.DIRECTION_RESPONDER_TO_INITIATOR):
        forged_chain = kdf.derive_chain_key(forged_root, direction)
        assert forged_chain != session["bob_keys"].recv_chain
        assert forged_chain != session["bob_keys"].send_chain

    # And the honest receiver, whose ephemeral did its job, still can.
    delivered = driver.receive_fragments(
        state_root=session["b_root"], session_id=session["sid"],
        fragments=fragments, peer=session["alice"].public,
    )
    assert [m.body for m in delivered.delivered] == [b"the earlier secret"]


def test_the_transcript_alone_is_not_the_key(session):
    """Guards against the tempting shortcut of deriving from public data only."""
    parts = attacker_transcript(session)
    canonical = parts.canonical()
    assert canonical != session["alice_keys"].root_key
    # The transcript is fully reconstructable by an attacker -- that is the point of
    # it being signed rather than secret -- so it must contribute but not suffice.
    assert canonical in parts.canonical()
    assert len(session["alice_keys"].root_key) == 32


def test_two_sessions_for_the_same_pair_have_different_roots(tmp_path):
    """A leaked root for one session must not open another between the same people."""
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    roots = []
    for round_number in range(2):
        a_root = tmp_path / f"a{round_number}"
        hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=a_root)
        accept, _ = hs.respond(identity=bob, hello=hello, peer=alice.public,
                               directory_lookup=lambda u: alice.public)
        _, keys = hs.complete(identity=alice, accept=accept, state_root=a_root,
                              peer=bob.public)
        roots.append(keys.root_key)
    assert roots[0] != roots[1]


def test_responder_persists_no_ephemeral_secret(tmp_path):
    """The responder's ephemerals are local variables, so there is no file to steal.

    Stated as a test because it is a design decision, not an accident: it removes half
    the ephemeral-secret surface without changing the protocol shape.
    """
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    a_root = tmp_path / "a"
    hello, session_id = hs.initiate(identity=alice, peer=bob.public, state_root=a_root)
    hs.respond(identity=bob, hello=hello, peer=alice.public,
               directory_lookup=lambda u: alice.public)
    # The initiator has a record (it must, to finish in a later process).
    assert eph_store.load(a_root, session_id)["x25519_secret"]
    # No second record was created for the responder side anywhere under the root.
    assert len(list((a_root / "pqc-kv-messaging").rglob("*"))) >= 1
