"""Envelope seal/open: round trip and every tamper path. This is the core of Step 2."""

from __future__ import annotations

import json

import pytest

from pqc_kv import dsa, envelope, hybrid, kem

from .conftest import flip_bit

PLAINTEXT = b"quarterly numbers: revenue 42"
RECIPIENT = "asset:brief"
ENVELOPE_ID = "env-0001"
CONTEXT = "pqc-kv/v1/asset-body"


def seal(kem_pair, sign_pair, body=PLAINTEXT, mode=envelope.MODE_KEM):
    recipient_public = kem_pair if mode == envelope.MODE_KEM else hybrid.public_of(kem_pair)
    return envelope.seal(
        plaintext=body,
        recipient_public=recipient_public,
        sender_signing_secret=sign_pair.secret_key,
        recipient=RECIPIENT,
        envelope_id=ENVELOPE_ID,
        context=CONTEXT,
        mode=mode,
    )


def test_roundtrip_kem(kem_keys, signing_keys):
    env = seal(kem_keys, signing_keys)
    assert (
        envelope.open_envelope(
            env, recipient_secret=kem_keys, sender_signing_public=signing_keys.public_key
        )
        == PLAINTEXT
    )


def test_roundtrip_through_json(kem_keys, signing_keys):
    env = seal(kem_keys, signing_keys)
    revived = envelope.from_dict(json.loads(envelope.to_json(env)))
    assert (
        envelope.open_envelope(
            revived, recipient_secret=kem_keys, sender_signing_public=signing_keys.public_key
        )
        == PLAINTEXT
    )


def test_same_plaintext_different_ciphertext(kem_keys, signing_keys):
    first = seal(kem_keys, signing_keys)
    second = seal(kem_keys, signing_keys)
    assert first.ciphertext != second.ciphertext
    assert first.nonce != second.nonce
    assert first.kem_ciphertext != second.kem_ciphertext


# ------------------------------------------------------------------ tampering
TAMPER_FIELDS = ["nonce", "ciphertext", "tag", "kem_ciphertext", "signature"]


@pytest.mark.parametrize("field", TAMPER_FIELDS)
@pytest.mark.parametrize("index", [0, 7])
def test_flipped_bit_anywhere_is_rejected(kem_keys, signing_keys, field, index):
    env = seal(kem_keys, signing_keys)
    tampered = _replace(env, **{field: flip_bit(getattr(env, field), index)})
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            tampered, recipient_secret=kem_keys, sender_signing_public=signing_keys.public_key
        )


def test_flipped_aad_identifier_is_rejected(kem_keys, signing_keys):
    """Changing the header (asset/context) must break authentication."""
    env = seal(kem_keys, signing_keys)
    for replacement in (
        {"recipient": "asset:other"},
        {"envelope_id": "env-9999"},
        {"context": "pqc-kv/v1/other"},
        {"version": 2},
    ):
        tampered = _replace(env, **replacement)
        with pytest.raises(envelope.EnvelopeError):
            envelope.open_envelope(
                tampered,
                recipient_secret=kem_keys,
                sender_signing_public=signing_keys.public_key,
            )


def test_wrong_recipient_key_cannot_open(kem_keys, signing_keys):
    stranger = kem.generate_keypair()
    env = seal(kem_keys, signing_keys)
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            env, recipient_secret=stranger, sender_signing_public=signing_keys.public_key
        )


def test_wrong_sender_public_key_fails_verification(kem_keys, signing_keys):
    impostor = dsa.generate_keypair()
    env = seal(kem_keys, signing_keys)
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            env, recipient_secret=kem_keys, sender_signing_public=impostor.public_key
        )


def test_signed_by_someone_else_is_rejected(kem_keys):
    """Signature proves origin, not just integrity: a valid signature by a
    different signer is still not accepted when we expect our own signer."""
    ours, theirs = dsa.generate_keypair(), dsa.generate_keypair()
    env = seal(kem_keys, theirs)
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            env, recipient_secret=kem_keys, sender_signing_public=ours.public_key
        )


def test_truncated_and_garbage_envelopes_fail_cleanly(kem_keys, signing_keys):
    env = seal(kem_keys, signing_keys)
    cases = [
        _replace(env, ciphertext=env.ciphertext[: len(env.ciphertext) // 2]),
        _replace(env, signature=env.signature[:-1]),
        _replace(env, kem_ciphertext=b""),
        _replace(env, nonce=b""),
        _replace(env, tag=b""),
        _replace(env, mode="hybrid-with-no-key"),
    ]
    for case in cases:
        with pytest.raises(envelope.EnvelopeError):
            envelope.open_envelope(
                case, recipient_secret=kem_keys, sender_signing_public=signing_keys.public_key
            )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"suite": "nope"},
        {"suite": envelope.SUITE, "v": 1, "mode": "kem", "rcpt": "r", "env": "e", "ctx": "c",
         "nonce": "***not base64***", "ct": "", "tag": "", "kem_ct": "", "hy_pub": "", "sig": ""},
        {"suite": envelope.SUITE, "v": "one", "mode": "kem", "rcpt": "r", "env": "e", "ctx": "c",
         "nonce": "", "ct": "", "tag": "", "kem_ct": "", "hy_pub": "", "sig": ""},
        "not-a-dict",
    ],
)
def test_malformed_wire_format_rejected(payload):
    with pytest.raises(envelope.EnvelopeError):
        envelope.from_dict(payload)


def test_error_messages_do_not_leak_which_check_failed(kem_keys, signing_keys):
    env = seal(kem_keys, signing_keys)
    messages = set()
    for tampered in (
        _replace(env, ciphertext=flip_bit(env.ciphertext)),
        _replace(env, signature=flip_bit(env.signature)),
        _replace(env, nonce=flip_bit(env.nonce)),
        _replace(env, tag=flip_bit(env.tag)),
    ):
        with pytest.raises(envelope.EnvelopeError) as info:
            envelope.open_envelope(
                tampered,
                recipient_secret=kem_keys,
                sender_signing_public=signing_keys.public_key,
            )
        messages.add(str(info.value))
    # Only structural failures get a specific message; crypto failures are uniform.
    assert len(messages) <= 2
    assert all("signature" not in m or "verification failed" in m for m in messages)
    for message in messages:
        assert PLAINTEXT.decode() not in message
        assert kem_keys.secret_key.hex()[:16] not in message


def test_repr_hides_plaintext(kem_keys, signing_keys):
    env = seal(kem_keys, signing_keys)
    assert PLAINTEXT.decode() not in repr(env)
    assert len(env.ciphertext) == len(PLAINTEXT)


# --------------------------------------------------------------------- hybrid
def test_hybrid_roundtrip(hybrid_keys, signing_keys):
    env = seal(hybrid_keys, signing_keys, mode=envelope.MODE_HYBRID)
    assert (
        envelope.open_envelope(
            env, recipient_secret=hybrid_keys, sender_signing_public=signing_keys.public_key
        )
        == PLAINTEXT
    )


@pytest.mark.parametrize(
    "field", ["hybrid_public", "kem_ciphertext", "nonce", "ciphertext", "tag", "signature"]
)
def test_hybrid_tamper_rejected(hybrid_keys, signing_keys, field):
    env = seal(hybrid_keys, signing_keys, mode=envelope.MODE_HYBRID)
    tampered = _replace(env, **{field: flip_bit(getattr(env, field))})
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            tampered, recipient_secret=hybrid_keys, sender_signing_public=signing_keys.public_key
        )


def test_hybrid_wrong_recipient_key_rejected(hybrid_keys, signing_keys):
    env = seal(hybrid_keys, signing_keys, mode=envelope.MODE_HYBRID)
    other = hybrid.generate_keypair()
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            env, recipient_secret=other, sender_signing_public=signing_keys.public_key
        )


def test_envelope_is_not_reusable_across_recipients(kem_keys, signing_keys):
    """AAD binds the recipient label, so moving an envelope to another label fails."""
    env = seal(kem_keys, signing_keys)
    with pytest.raises(envelope.EnvelopeError):
        envelope.open_envelope(
            _replace(env, recipient="asset:notes"),
            recipient_secret=kem_keys,
            sender_signing_public=signing_keys.public_key,
        )


# -------------------------------------------------------------------- helpers
def _replace(env: envelope.Envelope, **changes) -> envelope.Envelope:
    data = dict(env.__dict__)
    data.update(changes)
    return envelope.Envelope(**data)
