"""Ratchet: directionality, irreversibility, out-of-order tolerance, hard bounds."""

from __future__ import annotations

import pytest

from pqc_kv.messaging import kdf
from pqc_kv.symmetric import KEY_LEN

ROOT = bytes(range(32))


def test_directions_are_agreed_and_independent():
    i2r = kdf.derive_chain_key(ROOT, kdf.DIRECTION_INITIATOR_TO_RESPONDER)
    r2i = kdf.derive_chain_key(ROOT, kdf.DIRECTION_RESPONDER_TO_INITIATOR)
    assert len(i2r) == KEY_LEN and len(r2i) == KEY_LEN
    assert i2r != r2i


def test_unknown_direction_refused():
    for bad in ("send", "recv", "I2R", ""):
        with pytest.raises(kdf.RatchetError):
            kdf.derive_chain_key(ROOT, bad)


def test_bad_root_key_length_refused():
    with pytest.raises(kdf.RatchetError):
        kdf.derive_chain_key(b"short", kdf.DIRECTION_INITIATOR_TO_RESPONDER)


def test_sender_and_receiver_agree_in_order():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    for expected in range(5):
        sequence, key = send.next_key()
        assert sequence == expected
        assert recv.take_key(expected) == key


def test_message_keys_are_distinct_and_chain_advances():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    keys = [send.next_key()[1] for _ in range(20)]
    assert len(set(keys)) == 20


def test_chain_step_is_one_way():
    """Given the current chain key you must not recover the previous one."""
    chain = kdf.derive_chain_key(ROOT, "i2r")
    nxt = kdf.derive_next_chain_key(chain)
    assert nxt != chain
    # There is no inverse operation exposed; the best an attacker can do is guess.
    assert kdf.derive_message_key(nxt) != kdf.derive_message_key(chain)


def test_out_of_order_is_tolerated():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    keys = [send.next_key()[1] for _ in range(6)]
    for sequence in (0, 3, 1, 5, 2, 4):
        assert recv.take_key(sequence) == keys[sequence]


def test_skipped_keys_are_cached_then_consumed():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    keys = [send.next_key()[1] for _ in range(5)]
    recv.take_key(4)  # jumps ahead, parks 0..3
    assert len(recv.skipped) == 4
    assert recv.take_key(2) == keys[2]
    assert len(recv.skipped) == 3
    with pytest.raises(kdf.RatchetError):
        recv.take_key(2)  # single use


def test_replay_of_consumed_sequence_refused():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    send.next_key()
    recv.take_key(0)
    with pytest.raises(kdf.RatchetError) as info:
        recv.take_key(0)
    assert kdf.RatchetFailure.ALREADY_USED in str(info.value)


def test_too_far_ahead_is_refused():
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    with pytest.raises(kdf.RatchetError) as info:
        recv.take_key(kdf.MAX_SKIP_AHEAD + 1)
    assert kdf.RatchetFailure.TOO_FAR_AHEAD in str(info.value)
    assert len(recv.skipped) == 0  # refused before deriving anything


def test_skipped_cache_is_bounded_and_evicts_oldest():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"), max_skipped=8, max_skip_ahead=64)
    for _ in range(20):
        send.next_key()
    recv.take_key(19)  # parks 0..18 but only 8 may be retained
    assert len(recv.skipped) == 8
    assert list(recv.skipped) == [11, 12, 13, 14, 15, 16, 17, 18]  # oldest evicted
    for sequence in range(11):
        with pytest.raises(kdf.RatchetError):
            recv.take_key(sequence)
    assert recv.take_key(18) is not None


def test_state_round_trips_through_dict():
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    keys = [send.next_key()[1] for _ in range(4)]
    recv.take_key(3)

    revived_send = kdf.SendRatchet.from_dict(send.to_dict())
    revived_recv = kdf.ReceiveRatchet.from_dict(recv.to_dict())

    assert revived_recv.take_key(1) == keys[1]
    sequence, key = revived_send.next_key()
    assert sequence == 4
    assert revived_recv.take_key(sequence) == key


def test_malformed_state_refused():
    with pytest.raises(kdf.RatchetError):
        kdf.ReceiveRatchet.from_dict({})
    with pytest.raises(kdf.RatchetError):
        kdf.SendRatchet.from_dict({"chain_key": "***"})
    with pytest.raises(kdf.RatchetError):
        kdf.ReceiveRatchet(chain_key=b"short")


def test_repr_hides_keys():
    recv = kdf.ReceiveRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    assert recv.chain_key.hex()[:16] not in repr(recv)
    assert send.chain_key.hex()[:16] not in repr(send)


def test_break_it_on_purpose_wrong_root_diverges():
    """Deliberate-misuse check: a different root must never produce a usable key."""
    send = kdf.SendRatchet(kdf.derive_chain_key(ROOT, "i2r"))
    wrong = kdf.ReceiveRatchet(kdf.derive_chain_key(b"\xff" * 32, "i2r"))
    _, key = send.next_key()
    assert wrong.take_key(0) != key
