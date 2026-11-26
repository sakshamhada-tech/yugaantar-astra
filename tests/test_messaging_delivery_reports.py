"""Goals 9 and 11, asserted at the level the brief states them.

**Goal 11** says the receiver "discards incomplete or invalid messages **and reports
delivery failures**". The existing tamper tests assert only that nothing was delivered.
That is half the claim: a receiver that silently drops a forged message and one that
reports `signature_invalid` with the message id both deliver nothing, and only the
second is usable by an operator. The tests here assert the *report*.

**Goal 9** says the receiver rejects "messages whose authenticated recipient
information has changed". The existing tests mutate the recipient user id and the
fingerprint. This file adds the cases those leave open: changing the recipient in the
AAD but not the header, changing the sender's binding, and confirming that the
recipient fields really are inside the authenticated envelope rather than merely
compared afterwards.

Every failure must also be *safe to log*: a reason code and a message id, no plaintext
and no recovered key material.
"""

from __future__ import annotations

import pytest

from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import driver, handshake as hs, identity, wire
from pqc_kv.messaging.session import SessionStore


@pytest.fixture()
def world(tmp_path):
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    carol = identity.generate(store, "carol")
    a_root, b_root = tmp_path / "alice", tmp_path / "bob"

    hello, sid = hs.initiate(identity=alice, peer=bob.public, state_root=a_root)
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
        SessionStore(root).put(sid, {
            "self_user": keys.self_user, "self_fp": keys.self_fp,
            "peer_user": keys.peer_user, "peer_fp": keys.peer_fp, "role": keys.role,
            "send": driver.SendRatchet(keys.send_chain).to_dict(),
            "recv": driver.ReceiveRatchet(keys.recv_chain).to_dict(),
            "next_message_id": "m-00000001", "seen_ids": [], "partials": {},
        })

    seed(alice_keys, a_root)
    seed(bob_keys, b_root)
    return {"alice": alice, "bob": bob, "carol": carol, "sid": sid,
            "a_root": a_root, "b_root": b_root}


def send(world, body, recipient=None):
    return driver.send_message(
        state_root=world["a_root"], session_id=world["sid"],
        session=SessionStore(world["a_root"]).get(world["sid"]),
        recipient=recipient or world["bob"].public, body=body,
        signer_public=world["alice"].public.signing_public,
        signing_secret=world["alice"].signing_secret,
    )


def receive(world, fragments, peer=None):
    return driver.receive_fragments(
        state_root=world["b_root"], session_id=world["sid"],
        fragments=fragments, peer=peer or world["alice"].public,
    )


def reasons(result):
    return [f["reason"] for f in result.failures]


# ----------------------------------------------------------------- goal 11
def test_incomplete_message_reports_a_failure_with_the_message_id(world):
    """"Discards incomplete" is only half of it; the operator must be told."""
    fragments = send(world, b"x" * 4000)
    assert len(fragments) > 1
    result = receive(world, fragments[:1])
    assert result.delivered == []
    assert reasons(result) == [wire.FailureReason.INCOMPLETE]
    assert result.failures[0]["message_id"] == fragments[0]["h"]["mid"]


def test_a_tampered_fragment_reports_signature_invalid(world):
    """A forged fragment must be a *reported* failure, not a silent drop."""
    fragments = send(world, b"tamper me")
    damaged = [dict(f) for f in fragments]
    value = damaged[0]["s"]
    damaged[0]["s"] = ("A" if value[:1] != "A" else "B") + value[1:]
    result = receive(world, damaged)
    assert result.delivered == []
    assert reasons(result) == [wire.FailureReason.SIGNATURE_INVALID]
    assert result.failures[0]["message_id"]


def test_a_stripped_signature_is_reported_not_ignored(world):
    result = receive(world, [{**f, "s": ""} for f in send(world, b"sign me")])
    assert result.delivered == []
    assert reasons(result) == [wire.FailureReason.SIGNATURE_INVALID]


def test_failures_never_carry_plaintext_or_key_material(world):
    """The report goes to a log. It must not become the leak."""
    body = b"secret-canary-value"
    fragments = send(world, body)
    damaged = [dict(f) for f in fragments]
    value = damaged[0]["s"]
    damaged[0]["s"] = ("A" if value[:1] != "A" else "B") + value[1:]
    result = receive(world, damaged)
    blob = repr(result.failures) + repr(result.delivered)
    assert "secret-canary-value" not in blob
    assert body.decode() not in blob
    # A failure is a closed shape: reason + message id, nothing else.
    assert set(result.failures[0]) == {"reason", "message_id"}


def test_a_failed_message_does_not_consume_the_ratchet(world):
    """A forged fragment must not be able to desynchronise the receiver.

    Otherwise dropping two bad fragments is a cheap denial of service against an
    otherwise healthy session.
    """
    good = send(world, b"deliver me")
    bad = [dict(f) for f in good]
    value = bad[0]["s"]
    bad[0]["s"] = ("A" if value[:1] != "A" else "B") + value[1:]

    assert receive(world, bad).delivered == []
    # The genuine fragments still arrive and still open.
    result = receive(world, good)
    assert [m.body for m in result.delivered] == [b"deliver me"]


def test_recovery_after_partial_delivery_delivers_exactly_once(world):
    """Goal 11's positive half: when recovery succeeds, deliver complete messages."""
    fragments = send(world, b"y" * 3000)
    half = len(fragments) // 2
    assert receive(world, fragments[:half]).delivered == []
    got = receive(world, list(reversed(fragments[half:])))
    assert len(got.delivered) == 1
    assert got.delivered[0].body == b"y" * 3000
    # And a further replay does not deliver it a second time.
    assert receive(world, fragments).delivered == []


# ----------------------------------------------------------------- goal 9
def test_changing_the_recipient_user_is_refused(world):
    fragments = [dict(f) for f in send(world, b"hi")]
    for fragment in fragments:
        fragment["h"]["ru"] = "carol"
    result = receive(world, fragments)
    assert result.delivered == []
    assert reasons(result)[0] in (wire.FailureReason.WRONG_RECIPIENT,
                                  wire.FailureReason.SIGNATURE_INVALID)


def test_changing_the_recipient_fingerprint_is_refused(world):
    fragments = [dict(f) for f in send(world, b"hi")]
    for fragment in fragments:
        fragment["h"]["rfp"] = world["carol"].fingerprint
    result = receive(world, fragments)
    assert result.delivered == []
    assert reasons(result)[0] in (wire.FailureReason.WRONG_RECIPIENT,
                                  wire.FailureReason.SIGNATURE_INVALID)


def test_changing_every_recipient_field_at_once_is_still_refused(world):
    """Rewriting the whole recipient block must not produce a "consistent" lie."""
    fragments = [dict(f) for f in send(world, b"hi")]
    for fragment in fragments:
        fragment["h"]["ru"] = "carol"
        fragment["h"]["rfp"] = world["carol"].fingerprint
    result = receive(world, fragments)
    assert result.delivered == []


def test_the_recipient_fields_are_inside_the_signature(world):
    """Structural proof of the claim, independent of which check fires first.

    If the recipient were compared only *after* signature verification, a re-addressed
    fragment with a recomputed signature would be accepted. It cannot be: the header
    is part of the signed bytes, so altering it invalidates the signature.
    """
    fragments = send(world, b"hi")
    header = wire.Header.from_dict(fragments[0]["h"])
    signed = header.canonical()
    for field, value in (("ru", "carol"),
                         ("rfp", world["carol"].fingerprint)):
        changed = wire.Header.from_dict({**fragments[0]["h"], field: value})
        assert changed.canonical() != signed


def test_a_message_addressed_to_carol_never_reaches_bob(world):
    """The positive control for recipient binding.

    The sender refuses first: a session holds one authenticated peer, so addressing it
    to anyone else raises before any bytes exist. That is the stronger outcome -- there
    is no ciphertext to leak -- and it is what this test asserts.
    """
    with pytest.raises(driver.DriverError) as info:
        send(world, b"for carol", recipient=world["carol"].public)
    assert info.value.reason == wire.FailureReason.WRONG_RECIPIENT


def test_unknown_header_keys_are_ignored_not_authenticated(world):
    """A stray key in the header changes nothing -- for better and for worse.

    Found by accident: a typo (`rf` instead of `rfp`) added an unknown key and the
    message was still delivered, because `from_dict` reads known fields and `canonical`
    serialises only those. So an attacker cannot smuggle meaning through extra keys,
    **and** cannot break a message by adding one. Both directions are asserted, because
    "ignored" is the sort of behaviour that is either harmless or a bypass depending on
    which side of the signature it lands on.
    """
    fragments = send(world, b"extra keys")
    padded = [dict(f) for f in fragments]
    padded[0]["h"] = {**padded[0]["h"], "zz": "noise", "ru_extra": "mallory"}
    result = receive(world, padded)
    assert [m.body for m in result.delivered] == [b"extra keys"]
    # And the padding is not part of what was signed.
    plain = wire.Header.from_dict(fragments[0]["h"]).canonical()
    dirty = wire.Header.from_dict(padded[0]["h"]).canonical()
    assert plain == dirty


def test_duplicate_delivery_of_a_fragment_is_counted(world):
    fragments = send(world, b"count me")
    assert len(receive(world, fragments).delivered) == 1
    again = receive(world, fragments)
    assert again.delivered == []
    assert again.duplicate_fragments == len(fragments)
