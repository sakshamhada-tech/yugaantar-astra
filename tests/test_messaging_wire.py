"""Wire format: recipient binding, per-field tamper detection, fragmentation."""

from __future__ import annotations

import base64
import json

import pytest

from pqc_kv import dsa
from pqc_kv.messaging import wire

SENDER_FP = "a" * 64
RECIPIENT_FP = "b" * 64
OTHER_FP = "c" * 64


def make_header(**overrides):
    base = dict(
        version=wire.PROTOCOL_VERSION,
        suite=wire.SUITE,
        session_id="s-" + "1" * 32,
        sender_fp=SENDER_FP,
        sender_user="alice",
        recipient_fp=RECIPIENT_FP,
        recipient_user="bob",
        message_id="m-00000001",
        sequence=0,
        fragment_index=0,
        fragment_total=1,
    )
    base.update(overrides)
    return wire.Header(**base)


def make_fragment(header=None, signature=b"\x01" * 3309, **overrides):
    header = header or make_header()
    data = dict(
        header=header,
        nonce=b"\x00" * 12,
        ciphertext=b"ciphertext",
        tag=b"\x00" * 16,
        signature=signature,
    )
    data.update(overrides)
    return wire.Fragment(**data)


# ------------------------------------------------------- header validation
@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 1},
        {"version": 99},
        {"suite": "pqc-kv/v1/envelope"},
        {"sender_fp": "short"},
        {"recipient_fp": ""},
        {"session_id": ""},
        {"sender_user": ""},
        {"recipient_user": ""},
        {"message_id": ""},
        {"session_id": "x" * 300},
        {"sequence": -1},
        {"fragment_total": 0},
        {"fragment_total": wire.MAX_FRAGMENTS + 1},
        {"fragment_index": 5, "fragment_total": 5},
        {"fragment_index": -1},
    ],
)
def test_header_rejects_bad_values(overrides):
    with pytest.raises(wire.WireError):
        make_header(**overrides)


# ------------------------------------------------------------- binding
def test_recipient_binding_is_in_the_signed_header():
    """The canonical bytes must change for every binding-relevant field."""
    base = make_header().canonical()
    for entry in [
        ("recipient_user", "carol", {}),
        ("recipient_fp", OTHER_FP, {}),
        ("sender_user", "mallory", {}),
        ("sender_fp", OTHER_FP, {}),
        ("session_id", "s-" + "2" * 32, {}),
        ("message_id", "m-00000002", {}),
        ("sequence", 7, {}),
        ("fragment_index", 1, {"fragment_total": 2}),
        ("fragment_total", 2, {}),
    ]:
        field, value, extra = entry
        variant = make_header(**{field: value, **extra}).canonical()
        assert variant != base, field


def test_unsupported_version_and_suite_are_rejected_outright():
    """Stronger than 'differs': an unknown version/suite never becomes a header."""
    for overrides in ({"version": 3}, {"version": 1}, {"suite": "other"}):
        with pytest.raises(wire.WireError):
            make_header(**overrides)


def test_canonical_form_is_deterministic():
    assert make_header().canonical() == make_header().canonical()


def test_readdressing_to_another_user_changes_aad():
    original = make_fragment()
    readdressed = make_fragment(header=make_header(recipient_user="carol"))
    assert original.aad() != readdressed.aad()


def test_signed_bytes_cover_nonce_and_tag():
    """A signature must not survive swapping the ciphertext/ tag/nonce."""
    original = make_fragment()
    for change in ({"nonce": b"\x01" * 12}, {"tag": b"\x02" * 16}, {"ciphertext": b"other"}):
        assert make_fragment(**change).signed_bytes() != original.signed_bytes()


@pytest.mark.parametrize(
    "field",
    ["session_id", "sender_fp", "sender_user", "recipient_fp", "recipient_user",
     "message_id", "sequence", "fragment_index", "fragment_total"],
)
def test_single_field_edit_breaks_the_signature(field):
    signer = dsa.generate_keypair()
    header = make_header()
    fragment = make_fragment(header=header, signature=dsa.sign(signer.secret_key, make_fragment(header=header).signed_bytes()))
    assert fragment.verify_signature(signer.public_key) is True

    value = getattr(header, field)
    if field == "fragment_total":
        tampered_value = 2  # still valid: 0 <= index 0 < 2, and different
    elif field == "fragment_index":
        tampered_value = 1  # requires total > 1, so widen it below
    elif field.endswith("fp"):
        tampered_value = ("0" * 64) if value != "0" * 64 else "1" * 64
    elif field.endswith("user"):
        tampered_value = "carol" if value != "carol" else "dave"
    elif field == "sequence":
        tampered_value = value + 1
    else:
        tampered_value = value + "x"
    if field == "fragment_index":
        bad = make_fragment(header=make_header(fragment_index=1, fragment_total=2),
                            signature=fragment.signature)
        assert bad.verify_signature(signer.public_key) is False
        return
    bad = make_fragment(header=make_header(**{field: tampered_value}), signature=fragment.signature)
    assert bad.verify_signature(signer.public_key) is False


# --------------------------------------------------------- serialisation
def test_fragment_round_trips():
    fragment = make_fragment()
    revived = wire.Fragment.from_dict(fragment.to_dict())
    assert revived.header == fragment.header
    assert revived.signed_bytes() == fragment.signed_bytes()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("h"),
        lambda d: d["h"].pop("sid"),
        lambda d: d["h"].update({"v": "not-an-int"}),
        lambda d: d.update({"n": "***"}),
        lambda d: d.update({"c": 12345}),
        lambda d: d.update({"t": "not!base64!"}),
        lambda d: d.update({"s": None}),
        lambda d: d["h"].update({"ru": ""}),
    ],
)
def test_malformed_fragment_raises_opaque_error(mutate):
    data = json.loads(json.dumps(make_fragment().to_dict()))
    mutate(data)
    with pytest.raises(wire.WireError):
        wire.Fragment.from_dict(data)


def test_split_produces_contiguous_fragments():
    signer = dsa.generate_keypair()
    calls = {"n": 0}

    def header_for(index, total, chunk):
        calls["n"] += 1
        return make_header(fragment_index=index, fragment_total=total)

    def encrypt_fragment(header, chunk):
        return b"n" * 12, chunk, b"t" * 16

    def sign_fragment(fragment):
        return dsa.sign(signer.secret_key, fragment.signed_bytes())

    fragments = wire.split(b"x" * 2500, header_for=header_for,
                           encrypt_fragment=encrypt_fragment, sign_fragment=sign_fragment,
                           fragment_bytes=1000)
    assert len(fragments) == 3
    assert [f.header.fragment_index for f in fragments] == [0, 1, 2]
    assert all(f.header.fragment_total == 3 for f in fragments)
    assert calls["n"] == 3


def test_split_handles_empty_body_as_one_fragment():
    fragments = wire.split(b"", header_for=lambda i, t, c: make_header(fragment_index=i, fragment_total=t),
                           encrypt_fragment=lambda h, c: (b"n" * 12, c, b"t" * 16),
                           sign_fragment=lambda f: b"s" * 3309)
    assert len(fragments) == 1
    assert fragments[0].ciphertext == b""


def test_message_repr_hides_body():
    message = wire.Message(message_id="m1", sender_user="a", sender_fp=SENDER_FP,
                           recipient_user="b", recipient_fp=RECIPIENT_FP, sequence=0,
                           body=b"top secret plaintext", fragment_count=1)
    assert "top secret" not in repr(message)
