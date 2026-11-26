"""AES-256-GCM usage: fresh nonces, AAD binding, clean tamper rejection."""

from __future__ import annotations

import pytest

from pqc_kv import symmetric
from pqc_kv.aead import NonceBudget, NonceBudgetExhausted, build_aad, fresh_nonce

from .conftest import flip_bit

KEY = b"k" * 32


def test_roundtrip():
    nonce, aad = fresh_nonce(), b"header"
    ct, tag = symmetric.aesgcm_encrypt(KEY, nonce, b"payload", aad)
    assert symmetric.aesgcm_decrypt(KEY, nonce, ct, tag, aad) == b"payload"


def test_same_plaintext_gives_different_ciphertexts():
    """Fresh nonce per message: identical bodies must not look identical at rest."""
    aad = b"header"
    ct1, _ = symmetric.aesgcm_encrypt(KEY, fresh_nonce(), b"same body", aad)
    ct2, _ = symmetric.aesgcm_encrypt(KEY, fresh_nonce(), b"same body", aad)
    assert ct1 != ct2


def test_nonces_do_not_repeat_in_a_sample():
    seen = {fresh_nonce() for _ in range(2048)}
    assert len(seen) == 2048


@pytest.mark.parametrize("field", ["nonce", "ciphertext", "tag", "aad", "key"])
def test_single_bit_flip_anywhere_is_rejected(field):
    nonce, aad = fresh_nonce(), b"header"
    ct, tag = symmetric.aesgcm_encrypt(KEY, nonce, b"payload", aad)
    parts = {"key": KEY, "nonce": nonce, "ciphertext": ct, "tag": tag, "aad": aad}
    parts[field] = flip_bit(parts[field])
    with pytest.raises(symmetric.TamperError):
        symmetric.aesgcm_decrypt(
            parts["key"], parts["nonce"], parts["ciphertext"], parts["tag"], parts["aad"]
        )


def test_wrong_key_rejected():
    nonce, aad = fresh_nonce(), b"header"
    ct, tag = symmetric.aesgcm_encrypt(KEY, nonce, b"payload", aad)
    with pytest.raises(symmetric.TamperError):
        symmetric.aesgcm_decrypt(b"z" * 32, nonce, ct, tag, aad)


def test_truncated_input_rejected_cleanly():
    nonce, aad = fresh_nonce(), b"header"
    ct, tag = symmetric.aesgcm_encrypt(KEY, nonce, b"payload", aad)
    with pytest.raises(symmetric.TamperError):
        symmetric.aesgcm_decrypt(KEY, nonce, ct, b"\x00" * 3, aad)


def test_tamper_error_carries_no_detail():
    nonce, aad = fresh_nonce(), b"header"
    ct, tag = symmetric.aesgcm_encrypt(KEY, nonce, b"payload", aad)
    with pytest.raises(symmetric.TamperError) as info:
        symmetric.aesgcm_decrypt(KEY, nonce, flip_bit(ct), tag, aad)
    message = str(info.value)
    assert message == "authentication failed"
    assert nonce.hex() not in message


def test_aad_is_deterministic_and_field_sensitive():
    a = build_aad(suite="s", recipient="r", envelope_id="e", context="c", version=1)
    b = build_aad(suite="s", recipient="r", envelope_id="e", context="c", version=1)
    c = build_aad(suite="s", recipient="r2", envelope_id="e", context="c", version=1)
    assert a == b and a != c


def test_aad_is_unambiguous_across_field_boundaries():
    """Joining fields must not allow ('ab','c') and ('a','bc') to collide."""
    a = build_aad(suite="s", recipient="ab", envelope_id="c", context="x", version=1)
    b = build_aad(suite="s", recipient="a", envelope_id="bc", context="x", version=1)
    assert a != b


def test_nonce_budget_stops_at_limit():
    budget = NonceBudget(limit=3)
    for _ in range(3):
        budget.take()
    with pytest.raises(NonceBudgetExhausted):
        budget.take()


def test_nonce_budget_is_thread_safe_ish():
    """Concurrent takers must never exceed the limit (double-spend check)."""
    import threading

    budget = NonceBudget(limit=100)
    granted = []

    def worker():
        for _ in range(200):
            try:
                granted.append(budget.take())
            except NonceBudgetExhausted:
                return

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(granted) == 100
    assert len(set(granted)) == 100
