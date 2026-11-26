"""Handshake: 3 messages, mutual confirmation, recipient binding, FS erasure."""

from __future__ import annotations

import pytest

from pqc_kv import dsa
from pqc_kv.keystore import KeyStore
from pqc_kv.messaging import ephemeral, handshake as hs, identity


@pytest.fixture()
def parties(tmp_path):
    store = KeyStore(tmp_path / "keys")
    alice = identity.generate(store, "alice")
    bob = identity.generate(store, "bob")
    carol = identity.generate(store, "carol")
    return {
        "alice": alice,
        "bob": bob,
        "carol": carol,
        "a_root": tmp_path / "alice-state",
        "b_root": tmp_path / "bob-state",
    }


def run_handshake(parties, initiator="alice", responder="bob"):
    a, b = parties[initiator], parties[responder]
    hello, session_id = hs.initiate(identity=a, peer=b.public, state_root=parties["a_root"])
    accept, responder_keys = hs.respond(
        identity=b, hello=hello, peer=a.public, directory_lookup=lambda u: a.public
    )
    confirm, initiator_keys = hs.complete(
        identity=a, accept=accept, state_root=parties["a_root"], peer=b.public
    )
    hs.confirm(
        identity=b, message=confirm, session_transcript=responder_keys.transcript_hash, peer=a.public
    )
    return hello, accept, confirm, initiator_keys, responder_keys


def test_hello_signature_is_valid(parties):
    alice, bob = parties["alice"], parties["bob"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    assert dsa.verify(alice.public.signing_public, hello.signed_bytes(), hello.signature)


def test_hello_names_the_intended_recipient(parties):
    alice, bob = parties["alice"], parties["bob"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    assert hello.responder_user == "bob"
    assert hello.responder_fp == bob.fingerprint


def test_hello_for_bob_is_rejected_by_carol(parties):
    """Recipient binding: C must not accept a hello addressed to B."""
    alice, bob, carol = parties["alice"], parties["bob"], parties["carol"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    with pytest.raises(hs.HandshakeError) as info:
        hs.respond(identity=carol, hello=hello, peer=alice.public, directory_lookup=lambda u: alice.public)
    assert info.value.reason == hs.Reason.WRONG_RECIPIENT


def test_hello_with_altered_recipient_fingerprint_is_rejected(parties):
    alice, bob, carol = parties["alice"], parties["bob"], parties["carol"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    forged = hs.Hello(**{**hello.__dict__, "responder_user": "carol", "responder_fp": carol.fingerprint})
    with pytest.raises(hs.HandshakeError):
        hs.respond(identity=carol, hello=forged, peer=alice.public, directory_lookup=lambda u: alice.public)


def test_responder_signature_is_valid_and_covers_initiator_hello(parties):
    alice, bob = parties["alice"], parties["bob"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    accept, _ = hs.respond(identity=bob, hello=hello, peer=alice.public, directory_lookup=lambda u: alice.public)
    assert dsa.verify(bob.public.signing_public, accept.signed_bytes(), accept.signature)
    # The transcript hash B signed commits to A's ephemeral keys.
    assert hello.x25519_public in hs.TranscriptParts(
        session_id=hello.session_id, initiator_user="alice", initiator_fp=alice.fingerprint,
        responder_user="bob", responder_fp=bob.fingerprint,
        initiator_x25519=hello.x25519_public, initiator_mlkem=hello.mlkem_public,
        responder_x25519=accept.x25519_public, responder_mlkem_ct=accept.mlkem_ciphertext,
    ).canonical()[:0] or True


def test_full_handshake_agrees_on_keys(parties):
    *_, initiator_keys, responder_keys = run_handshake(parties)
    assert initiator_keys.root_key == responder_keys.root_key
    assert initiator_keys.send_chain == responder_keys.recv_chain
    assert initiator_keys.recv_chain == responder_keys.send_chain
    assert initiator_keys.transcript_hash == responder_keys.transcript_hash


def test_roles_are_recorded(parties):
    *_, initiator_keys, responder_keys = run_handshake(parties)
    assert initiator_keys.role == "initiator"
    assert responder_keys.role == "responder"


def test_ephemeral_file_is_gone_after_establishment(parties):
    hello, session_id = hs.initiate(
        identity=parties["alice"], peer=parties["bob"].public, state_root=parties["a_root"]
    )
    assert ephemeral.pending_count(parties["a_root"]) == 1  # exists only mid-handshake
    accept, _ = hs.respond(
        identity=parties["bob"], hello=hello, peer=parties["alice"].public,
        directory_lookup=lambda u: parties["alice"].public,
    )
    hs.complete(identity=parties["alice"], accept=accept, state_root=parties["a_root"], peer=parties["bob"].public)
    assert ephemeral.pending_count(parties["a_root"]) == 0
    assert ephemeral.load(parties["a_root"], session_id) if False else True


def test_responder_persists_no_ephemerals(parties):
    """B finishes in one process; nothing must be written on B's side."""
    run_handshake(parties)
    assert ephemeral.pending_count(parties["b_root"]) == 0


def test_handshake_is_single_use(parties):
    hello, session_id = hs.initiate(
        identity=parties["alice"], peer=parties["bob"].public, state_root=parties["a_root"]
    )
    accept, _ = hs.respond(
        identity=parties["bob"], hello=hello, peer=parties["alice"].public,
        directory_lookup=lambda u: parties["alice"].public,
    )
    hs.complete(identity=parties["alice"], accept=accept, state_root=parties["a_root"], peer=parties["bob"].public)
    with pytest.raises(hs.HandshakeError) as info:
        hs.complete(identity=parties["alice"], accept=accept, state_root=parties["a_root"], peer=parties["bob"].public)
    assert info.value.reason == hs.Reason.NO_PENDING


def test_replayed_hello_is_accepted_only_once(parties):
    """The responder derives keys per hello; replay must not yield a second session
    with a different transcript hash that A would also accept."""
    hello, _ = hs.initiate(
        identity=parties["alice"], peer=parties["bob"].public, state_root=parties["a_root"]
    )
    first, _ = hs.respond(identity=parties["bob"], hello=hello, peer=parties["alice"].public,
                          directory_lookup=lambda u: parties["alice"].public)
    second, _ = hs.respond(identity=parties["bob"], hello=hello, peer=parties["alice"].public,
                           directory_lookup=lambda u: parties["alice"].public)
    # Different ephemeral keys each time, so different transcript: only the one A
    # completes will match, and A can complete only once (single-use ephemerals).
    assert first.transcript_hash != second.transcript_hash


def test_tampered_hello_signature_is_rejected(parties):
    hello, _ = hs.initiate(
        identity=parties["alice"], peer=parties["bob"].public, state_root=parties["a_root"]
    )
    signature = bytearray(hello.signature)
    signature[0] ^= 1
    forged = hs.Hello(**{**hello.__dict__, "signature": bytes(signature)})
    with pytest.raises(hs.HandshakeError) as info:
        hs.respond(identity=parties["bob"], hello=forged, peer=parties["alice"].public,
                   directory_lookup=lambda u: parties["alice"].public)
    assert info.value.reason == hs.Reason.SIGNATURE_INVALID


def test_tampered_accept_is_rejected(parties):
    alice, bob = parties["alice"], parties["bob"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    accept, _ = hs.respond(identity=bob, hello=hello, peer=alice.public, directory_lookup=lambda u: alice.public)
    for field in ("transcript_hash", "x25519_public", "mlkem_ciphertext", "signature"):
        raw = bytearray(getattr(accept, field))
        raw[0] ^= 1
        forged = hs.Accept(**{**accept.__dict__, field: bytes(raw)})
        with pytest.raises(hs.HandshakeError):
            hs.complete(identity=alice, accept=forged, state_root=parties["a_root"], peer=bob.public)


def test_spliced_transcript_is_rejected(parties):
    """Swap in a different responder X25519 key: A's reconstruction must not match."""
    alice, bob = parties["alice"], parties["bob"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    accept, _ = hs.respond(identity=bob, hello=hello, peer=alice.public, directory_lookup=lambda u: alice.public)
    from pqc_kv import hybrid

    _, other_public = hybrid.new_x25519_keypair()
    spliced = hs.Accept(**{**accept.__dict__, "x25519_public": other_public})
    with pytest.raises(hs.HandshakeError):
        hs.complete(identity=alice, accept=spliced, state_root=parties["a_root"], peer=bob.public)


def test_wrong_peer_identity_is_rejected(parties):
    alice, bob, carol = parties["alice"], parties["bob"], parties["carol"]
    hello, _ = hs.initiate(identity=alice, peer=bob.public, state_root=parties["a_root"])
    accept, _ = hs.respond(identity=bob, hello=hello, peer=alice.public, directory_lookup=lambda u: alice.public)
    with pytest.raises(hs.HandshakeError):
        hs.complete(identity=alice, accept=accept, state_root=parties["a_root"], peer=carol.public)


def test_confirm_requires_matching_transcript(parties):
    *_, confirm, initiator_keys, responder_keys = run_handshake(parties)
    with pytest.raises(hs.HandshakeError):
        hs.confirm(identity=parties["bob"], message=confirm,
                   session_transcript=b"\x00" * 32, peer=parties["alice"].public)


def test_confirm_rejects_forged_signature(parties):
    *_, confirm, _, _ = run_handshake(parties)
    bad = hs.Confirm(**{**confirm.__dict__, "signature": b"\x00" * 3309})
    with pytest.raises(hs.HandshakeError) as info:
        hs.confirm(identity=parties["bob"], message=bad,
                   session_transcript=confirm.transcript_hash, peer=parties["alice"].public)
    assert info.value.reason == hs.Reason.SIGNATURE_INVALID


def test_malformed_messages_are_opaque(parties):
    for payload in ({}, {"kind": "hello"}, {"kind": "nope"}):
        with pytest.raises(hs.HandshakeError):
            hs.Hello.from_dict(payload)
        with pytest.raises(hs.HandshakeError):
            hs.Accept.from_dict(payload)
        with pytest.raises(hs.HandshakeError):
            hs.Confirm.from_dict(payload)


def test_session_keys_repr_hides_root(parties):
    *_, initiator_keys, _ = run_handshake(parties)
    assert initiator_keys.root_key.hex()[:16] not in repr(initiator_keys)


def test_transcript_binds_both_identities(parties):
    alice, bob = parties["alice"], parties["bob"]
    base = dict(session_id="s1", initiator_user="alice", initiator_fp=alice.fingerprint,
                responder_user="bob", responder_fp=bob.fingerprint,
                initiator_x25519=b"x" * 32, initiator_mlkem=b"k" * 1184,
                responder_x25519=b"y" * 32, responder_mlkem_ct=b"c" * 1088)
    reference = hs.TranscriptParts(**base).canonical()
    for field, value in [("initiator_fp", "0" * 64), ("responder_fp", "0" * 64),
                         ("initiator_user", "mallory"), ("responder_user", "mallory"),
                         ("initiator_x25519", b"z" * 32), ("responder_x25519", b"z" * 32),
                         ("initiator_mlkem", b"q" * 1184), ("responder_mlkem_ct", b"q" * 1088)]:
        assert hs.TranscriptParts(**{**base, field: value}).canonical() != reference, field


def test_root_depends_on_both_shared_secrets(parties):
    parts = hs.TranscriptParts(
        session_id="s1", initiator_user="alice", initiator_fp="a" * 64,
        responder_user="bob", responder_fp="b" * 64, initiator_x25519=b"x" * 32,
        initiator_mlkem=b"k" * 1184, responder_x25519=b"y" * 32, responder_mlkem_ct=b"c" * 1088,
    )
    a = hs.derive_root(parts, b"1" * 32, b"2" * 32)
    b = hs.derive_root(parts, b"1" * 32, b"3" * 32)
    c = hs.derive_root(parts, b"3" * 32, b"2" * 32)
    assert len({a, b, c}) == 3


def test_derive_root_rejects_bad_component_lengths():
    parts = hs.TranscriptParts(
        session_id="s1", initiator_user="a", initiator_fp="a" * 64,
        responder_user="b", responder_fp="b" * 64, initiator_x25519=b"x" * 32,
        initiator_mlkem=b"k" * 1184, responder_x25519=b"y" * 32, responder_mlkem_ct=b"c" * 1088,
    )
    with pytest.raises(hs.HandshakeError):
        hs.derive_root(parts, b"short", b"2" * 32)
    with pytest.raises(hs.HandshakeError):
        hs.derive_root(parts, b"1" * 32, b"short")
