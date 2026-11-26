"""Session store: atomicity, bounding, replay memory, eviction behaviour."""

from __future__ import annotations

import stat

import pytest

from pqc_kv.messaging.session import (
    MAX_PARTIAL_MESSAGES,
    MAX_TRACKED_MESSAGE_IDS,
    PartialMessage,
    SessionError,
    SessionStore,
)


@pytest.fixture()
def store(tmp_path):
    return SessionStore(tmp_path / "state")


def test_put_get_delete(store):
    store.put("s1", {"self_user": "alice", "seq": 0})
    assert store.exists("s1") is True
    assert store.get("s1")["self_user"] == "alice"
    assert store.delete("s1") is True
    assert store.exists("s1") is False


def test_unknown_session_raises(store):
    with pytest.raises(SessionError):
        store.get("nope")


def test_state_file_is_private(store):
    store.put("s1", {"a": 1})
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_state_survives_a_new_instance(tmp_path):
    SessionStore(tmp_path / "state").put("s1", {"value": 42})
    assert SessionStore(tmp_path / "state").get("s1")["value"] == 42


def test_mutate_is_read_modify_write(store):
    store.put("s1", {"counter": 1})
    store.mutate("s1", lambda s: {**s, "counter": s["counter"] + 1})
    assert store.get("s1")["counter"] == 2


def test_corrupt_state_is_refused(store, tmp_path):
    store.put("s1", {"a": 1})
    store.path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SessionError):
        SessionStore(tmp_path / "state").get("s1")


# ------------------------------------------------------------ partials
def test_partial_tracks_missing_indices():
    partial = PartialMessage(message_id="m1", total=3)
    partial.add(0, {"x": 1})
    partial.add(2, {"x": 3})
    assert partial.missing() == [1]
    assert partial.complete is False
    partial.add(1, {"x": 2})
    assert partial.complete is True


def test_partial_round_trips_through_session_state(store):
    store.put("s1", {})
    partial = PartialMessage("m1", total=2)
    partial.add(0, {"c": "aaa"})
    store.mutate("s1", lambda s: (SessionStore.store_partial(s, partial), s)[1])
    revived = SessionStore.load_partial(store.get("s1"), "m1")
    assert revived.total == 2
    assert revived.fragments[0] == {"c": "aaa"}


def test_partials_are_bounded_and_evict_oldest(store):
    store.put("s1", {})
    for index in range(MAX_PARTIAL_MESSAGES + 10):
        partial = PartialMessage(f"m{index}", total=2)
        partial.add(0, {"i": index})
        store.mutate("s1", lambda s, p=partial: (SessionStore.store_partial(s, p), s)[1])
    state = store.get("s1")
    assert len(state["partials"]) == MAX_PARTIAL_MESSAGES
    assert "m0" not in state["partials"]
    assert f"m{MAX_PARTIAL_MESSAGES + 9}" in state["partials"]


def test_drop_partial(store):
    store.put("s1", {})
    partial = PartialMessage("m1", total=2)
    store.mutate("s1", lambda s: (SessionStore.store_partial(s, partial), s)[1])
    store.mutate("s1", lambda s: (SessionStore.drop_partial(s, "m1"), s)[1])
    assert SessionStore.load_partial(store.get("s1"), "m1") is None


# --------------------------------------------------------- replay memory
def test_remember_id_reports_novelty(store):
    """Novelty is a property of the persisted state, not of a detached copy."""
    store.put("s1", {})
    first = store.mutate("s1", lambda s: (SessionStore.remember_id(s, "m1"), s)[1])
    assert first["seen_ids"] == ["m1"]
    second = store.mutate("s1", lambda s: (SessionStore.remember_id(s, "m1"), s)[1])
    assert second["seen_ids"] == ["m1"]  # not duplicated


def test_replay_memory_is_bounded_and_evicts_oldest(store):
    store.put("s1", {})
    state = store.get("s1")
    for index in range(MAX_TRACKED_MESSAGE_IDS + 5):
        SessionStore.remember_id(state, f"m{index}")
    assert len(state["seen_ids"]) == MAX_TRACKED_MESSAGE_IDS
    assert "m0" not in state["seen_ids"]
    # An evicted id is "novel" again here -- the ratchet, not this list, is what
    # rejects its replay. Documented in SECURITY_NOTES.
    assert SessionStore.remember_id(state, "m0") is True


def test_repr_hides_fragment_contents():
    partial = PartialMessage("m1", total=2)
    partial.add(0, {"secret": "plaintext-here"})
    assert "plaintext-here" not in repr(partial)
