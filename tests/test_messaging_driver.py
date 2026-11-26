"""Send/receive: fragmentation, replay, revocation, at-most-once, hostile transport."""

from __future__ import annotations

import random

import pytest

from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import driver, handshake as hs, identity, simnet, wire
from pqc_kv.messaging.session import SessionStore


@pytest.fixture()
def world(tmp_path):
    """Two parties with separate state roots and a completed handshake."""
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    a_root, b_root = tmp_path / "alice-state", tmp_path / "bob-state"

    hello, session_id = hs.initiate(identity=alice, peer=bob.public, state_root=a_root)
    accept, bob_keys = hs.respond(
        identity=bob, hello=hello, peer=alice.public, directory_lookup=lambda u: alice.public
    )
    confirm, alice_keys = hs.complete(identity=alice, accept=accept, state_root=a_root, peer=bob.public)
    hs.confirm(identity=bob, message=confirm, session_transcript=bob_keys.transcript_hash, peer=alice.public)

    def seed(keys, root):
        session = {
            "self_user": keys.self_user, "self_fp": keys.self_fp,
            "peer_user": keys.peer_user, "peer_fp": keys.peer_fp, "role": keys.role,
            "send": driver.SendRatchet(keys.send_chain).to_dict(),
            "recv": driver.ReceiveRatchet(keys.recv_chain).to_dict(),
            "next_message_id": "m-00000001", "seen_ids": [], "partials": {},
        }
        SessionStore(root).put(session_id, session)
        return SessionStore(root).get(session_id)

    return {
        "alice": alice, "bob": bob, "sid": session_id,
        "a_root": a_root, "b_root": b_root,
        "a_sess": seed(alice_keys, a_root), "b_sess": seed(bob_keys, b_root),
    }


def send(world, body, fragment_bytes=1024, recipient=None, secret=None):
    session = SessionStore(world["a_root"]).get(world["sid"])
    return driver.send_message(
        state_root=world["a_root"], session_id=world["sid"], session=session,
        recipient=recipient or world["bob"].public, body=body,
        signer_public=world["alice"].public.signing_public,
        signing_secret=secret or world["alice"].signing_secret,
        fragment_bytes=fragment_bytes,
    )


def receive(world, fragments, policy=None, peer=None):
    return driver.receive_fragments(
        state_root=world["b_root"], session_id=world["sid"], fragments=fragments,
        peer=peer or world["alice"].public, policy=policy,
    )


# ------------------------------------------------------------------- basics
def test_single_fragment_round_trip(world):
    fragments = send(world, b"short and sweet")
    result = receive(world, fragments)
    assert [m.body for m in result.delivered] == [b"short and sweet"]
    assert result.failures == []


def test_multi_fragment_round_trip(world):
    body = bytes(range(256)) * 40  # 10240 bytes -> 10 fragments
    fragments = send(world, body)
    assert len(fragments) == 10
    assert receive(world, fragments).delivered[0].body == body


def test_empty_body_round_trip(world):
    assert receive(world, send(world, b"")).delivered[0].body == b""


def test_only_first_fragment_carries_a_signature(world):
    """Per-message signing: one 3309-byte signature, not one per fragment."""
    fragments = send(world, b"x" * 5000)
    assert fragments[0]["s"] != ""
    assert all(f["s"] == "" for f in fragments[1:])


def test_out_of_order_delivery_is_tolerated(world):
    body = bytes(range(256)) * 20
    fragments = send(world, body)
    shuffled = fragments[:]
    random.Random(11).shuffle(shuffled)
    assert receive(world, shuffled).delivered[0].body == body


def test_partial_then_rest(world):
    body = bytes(range(256)) * 40
    fragments = send(world, body)
    first = receive(world, fragments[:6])
    assert first.delivered == []
    assert [f["reason"] for f in first.failures] == [wire.FailureReason.INCOMPLETE]
    second = receive(world, fragments[6:])
    assert second.delivered[0].body == body


def test_incomplete_message_reports_reason_and_id_without_plaintext(world):
    fragments = send(world, b"secret body " * 300)
    result = receive(world, fragments[:1])
    assert result.failures
    failure = result.failures[0]
    assert set(failure) == {"reason", "message_id"}
    assert "secret body" not in str(failure)


# ------------------------------------------------------------------- replay
def test_replayed_message_is_not_delivered_again(world):
    fragments = send(world, b"once only")
    assert len(receive(world, fragments).delivered) == 1
    again = receive(world, fragments)
    assert again.delivered == []
    assert again.duplicate_fragments == len(fragments)


def test_replay_after_partial_delivery(world):
    fragments = send(world, b"y" * 4000)
    receive(world, fragments[:2])
    receive(world, fragments)  # completes
    assert receive(world, fragments).delivered == []


def test_replay_of_evicted_message_id_is_still_refused(world):
    """The seen-id list is bounded; the ratchet, not the list, stops replay."""
    from pqc_kv.messaging.session import MAX_TRACKED_MESSAGE_IDS

    first = send(world, b"first")
    assert len(receive(world, first).delivered) == 1

    # Flood the id memory past its bound by marking ids directly.
    def flood(state):
        for index in range(MAX_TRACKED_MESSAGE_IDS + 2):
            SessionStore.remember_id(state, f"filler-{index}")
        return state

    SessionStore(world["b_root"]).mutate(world["sid"], flood)
    assert "m-00000001" not in SessionStore(world["b_root"]).get(world["sid"])["seen_ids"]

    # Its id is forgotten, so the duplicate check passes -- but the sequence was
    # consumed, so the ratchet refuses it.
    replay = receive(world, first)
    assert replay.delivered == []
    assert [f["reason"] for f in replay.failures] == [wire.FailureReason.REPLAY]


# --------------------------------------------------------- recipient binding
def test_readdressed_to_another_user_is_refused(world):
    fragments = send(world, b"for bob only")
    retargeted = []
    for fragment in fragments:
        payload = {**fragment, "h": {**fragment["h"], "ru": "carol"}}
        retargeted.append(payload)
    result = receive(world, retargeted)
    assert result.delivered == []
    assert [f["reason"] for f in result.failures] == [wire.FailureReason.WRONG_RECIPIENT]


def test_readdressed_to_another_fingerprint_is_refused(world):
    fragments = send(world, b"for bob only")
    retargeted = [{**f, "h": {**f["h"], "rfp": "0" * 64}} for f in fragments]
    result = receive(world, retargeted)
    assert result.delivered == []
    assert [f["reason"] for f in result.failures] == [wire.FailureReason.WRONG_RECIPIENT]


def test_send_to_wrong_recipient_is_refused(world):
    carol = identity.generate(KeyStore(world["a_root"] / "other"), "carol")
    with pytest.raises(driver.DriverError) as info:
        send(world, b"nope", recipient=carol.public)
    assert info.value.reason == wire.FailureReason.WRONG_RECIPIENT


# ---------------------------------------------------------------- tampering
@pytest.mark.parametrize("field", ["c", "t", "n"])
def test_tampered_ciphertext_fields_are_refused(world, field):
    fragments = send(world, b"tamper me")
    damaged = [dict(f) for f in fragments]
    value = damaged[0][field]
    flip = "A" if value[:1] != "A" else "B"
    damaged[0][field] = flip + value[1:]
    result = receive(world, damaged)
    assert result.delivered == []


def test_unsigned_fragment_set_is_refused(world):
    fragments = send(world, b"sign me")
    stripped = [{**f, "s": ""} for f in fragments]
    result = receive(world, stripped)
    assert result.delivered == []
    assert wire.FailureReason.SIGNATURE_INVALID in [f["reason"] for f in result.failures]


def test_fragment_from_a_stranger_is_refused(world):
    fragments = send(world, b"hello")
    stranger = identity.generate(KeyStore(world["a_root"] / "stranger"), "mallory")
    result = receive(world, fragments, peer=stranger.public)
    assert result.delivered == []
    assert [f["reason"] for f in result.failures] == [wire.FailureReason.WRONG_SENDER]


# ---------------------------------------------------------------- revocation
def test_revoked_sender_cannot_send(world):
    def policy(user, action):
        return user != "alice"

    with pytest.raises(driver.DriverError) as info:
        session = SessionStore(world["a_root"]).get(world["sid"])
        driver.send_message(
            state_root=world["a_root"], session_id=world["sid"], session=session,
            recipient=world["bob"].public, body=b"blocked",
            signer_public=world["alice"].public.signing_public,
            signing_secret=world["alice"].signing_secret, policy=policy,
        )
    assert info.value.reason == wire.FailureReason.POLICY_DENIED


def test_revoked_receiver_cannot_receive(world):
    fragments = send(world, b"held back")
    result = receive(world, fragments, policy=lambda user, action: user != "bob")
    assert result.delivered == []
    assert [f["reason"] for f in result.failures] == [wire.FailureReason.POLICY_DENIED]


def test_policy_is_consulted_with_the_local_user(world):
    seen = []

    def policy(user, action):
        seen.append((user, action))
        return True

    fragments = send(world, b"audit me")
    session = SessionStore(world["a_root"]).get(world["sid"])
    driver.send_message(
        state_root=world["a_root"], session_id=world["sid"], session=session,
        recipient=world["bob"].public, body=b"second", signer_public=world["alice"].public.signing_public,
        signing_secret=world["alice"].signing_secret, policy=policy,
    )
    receive(world, fragments, policy=policy)
    assert ("alice", "send") in seen
    assert ("bob", "receive") in seen


def test_revocation_wired_from_statestore(world, tmp_path):
    """The real hook: StateStore.revoke -> policy denies."""
    from pqc_kv.store import StateStore

    store = StateStore(tmp_path / "app-state")
    store.setup({"owners": {"brief": "alice"}, "contents": {"brief": "x"}, "disabled": [], "key_material": "k"})

    def policy(user, action):
        if user in store._read_state().get("disabled", []):
            return False
        return True

    fragments = send(world, b"before revocation")
    assert len(receive(world, fragments, policy=policy).delivered) == 1

    store.revoke("bob")  # the local recipient is now revoked
    blocked = receive(world, send(world, b"after revocation"), policy=policy)
    assert blocked.delivered == []
    assert blocked.failures[0]["reason"] == wire.FailureReason.POLICY_DENIED


# ------------------------------------------------------------ at-most-once
def test_ratchet_persists_before_plaintext_is_returned(world):
    """Simulate a crash after persistence: the message must not be readable again."""
    body = b"crash window"
    fragments = send(world, body)
    receive(world, fragments)

    state = SessionStore(world["b_root"]).get(world["sid"])
    assert state["received"] == 1
    assert "m-00000001" in state["seen_ids"]

    # A second attempt in a brand-new store instance (as if restarted) must fail.
    again = driver.receive_fragments(
        state_root=world["b_root"], session_id=world["sid"], fragments=fragments,
        peer=world["alice"].public,
    )
    assert again.delivered == []


def test_failed_decrypt_does_not_consume_the_ratchet(world):
    """A message that fails authentication must not advance the chain."""
    good = send(world, b"payload")
    before = SessionStore(world["b_root"]).get(world["sid"])["recv"]

    damaged = [dict(f) for f in good]
    damaged[0]["c"] = ("A" if damaged[0]["c"][:1] != "A" else "B") + damaged[0]["c"][1:]
    receive(world, damaged)
    after_failure = SessionStore(world["b_root"]).get(world["sid"])["recv"]
    assert before == after_failure


# ------------------------------------------------------------------ simnet
def test_lossy_network_reports_statistics(world):
    body = bytes(range(256)) * 20
    fragments = send(world, body)
    network = simnet.LossyNetwork(drop=0.2, duplicate=0.2, corrupt=0.1, shuffle=True, seed=3)
    delivered_batches = network.deliver_in_batches(fragments, batches=4)
    bodies = []
    for batch in delivered_batches:
        bodies.extend(m.body for m in receive(world, batch).delivered)
    stats = network.stats.as_dict()
    assert stats["sent"] == len(fragments)
    # Every fragment is accounted for: delivered exactly once, or dropped.
    assert stats["delivered"] == stats["sent"] - stats["dropped"] + stats["duplicated"]
    assert set(stats) == {"sent", "dropped", "duplicated", "corrupted", "truncated", "delivered"}


def test_no_loss_delivers_exactly_once(world):
    body = b"deterministic"
    fragments = send(world, body)
    clean = simnet.LossyNetwork(seed=1)
    delivered = []
    for batch in clean.deliver_in_batches(fragments, batches=1):
        delivered.extend(receive(world, batch).delivered)
    assert [m.body for m in delivered] == [body]


def test_heavy_loss_is_eventually_delivered_by_retry(world):
    """App-level retry of missing fragments: the protocol tolerates partial sets."""
    body = bytes(range(256)) * 16
    fragments = send(world, body)
    lossy = simnet.LossyNetwork(drop=0.5, shuffle=True, seed=9)
    first = lossy.transmit(fragments)
    result = receive(world, first)
    if not result.delivered:
        # Re-send whatever never arrived, as a retransmit would.
        received_ids = {f["h"]["fi"] for f in first}
        missing = [f for f in fragments if f["h"]["fi"] not in received_ids]
        result = receive(world, missing)
    assert result.delivered[0].body == body


def test_corruption_never_yields_plaintext(world):
    body = b"integrity " * 200
    fragments = send(world, body)
    hostile = simnet.LossyNetwork(corrupt=1.0, shuffle=True, seed=5)
    for batch in hostile.deliver_in_batches(fragments, batches=3):
        result = receive(world, batch)
        assert result.delivered == []


def test_simulator_is_deterministic():
    a = simnet.LossyNetwork(drop=0.3, shuffle=True, seed=42)
    b = simnet.LossyNetwork(drop=0.3, shuffle=True, seed=42)
    payload = [{"c": f"payload{i}"} for i in range(20)]
    assert a.transmit(payload) == b.transmit(payload)


def test_simulator_validates_probabilities():
    for bad in ({"drop": -0.1}, {"drop": 1.5}, {"corrupt": "x"}):
        with pytest.raises((ValueError, TypeError)):
            simnet.LossyNetwork(**bad)
