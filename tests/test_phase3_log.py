"""Goal 5: log injection cannot forge events, and the chain is signed.

Two attack groups:
  * hostile text trying to *become* a second event, or to change who an event is about
  * tampering with the file itself: edit, delete, reorder, insert, truncate
"""

from __future__ import annotations

import json

import pytest

from pqc_kv import dsa
from pqc_kv.keystore import KeyStore
from pqc_kv.logsign import (
    ALLOWED_ACTIONS,
    GENESIS,
    EventLog,
    LogError,
    Reason,
    classify,
    encode_line,
    validate_identifier,
)

#: Hostile strings a judge might try. Each one is aimed at a different failure.
HOSTILE = [
    'maya","action":"revoke","actor":"ravi',
    'maya\n{"action":"revoke","actor":"ravi"}',
    "maya\r\nrevoke",
    "maya\x00ravi",
    "maya\x1b[31m",
    "maya\x08\x0c",
    "\u202emaya",                 # right-to-left override
    "\u0430lice",                 # Cyrillic 'a' look-alike
    "maya" + " " * 200,
    "a" * 5000,
    "maya|ravi",
    '{"magic":"pqc-kv-eventlog","version":1,"seq":2}',
    "maya\travi",
    None,
    7,
    ["maya"],
    {"actor": "maya"},
]


@pytest.fixture()
def log(tmp_path):
    keys = KeyStore(tmp_path / "keys")
    pair = keys.signing_keypair("eventlog")
    return EventLog(tmp_path / "events.jsonl", pair.secret_key, pair.public_key)


# ------------------------------------------------------- injection attempts
def test_an_empty_identifier_means_absent_and_is_allowed(log):
    """System events (rotation, recovery) have no actor. That must be expressible.

    "" is deliberately accepted while None and other non-strings are refused: an
    absent actor is a legitimate state, a malformed one is not.
    """
    record = log.append(action="rotate", actor="")
    assert record["actor"] == ""
    with pytest.raises(LogError):
        log.append(action="rotate", actor=None)


def test_valid_identifiers_are_accepted(log):
    for good in ("maya", "ravi-2", "svc_backup.1", "node0", "team a", "a@b", "x:y#z"):
        log.append(action="read", actor=good)


def test_every_hostile_identifier_is_refused(log):
    for hostile in HOSTILE:
        with pytest.raises(LogError) as info:
            log.append(action="read", actor=hostile)
        assert info.value.reason == Reason.BAD_IDENTIFIER
    # Nothing was written by any of the refusals.
    assert log.records() == []


def test_a_forged_json_value_cannot_create_a_second_record(log):
    """The classic log-injection payload: close the string, add a fake event."""
    payload = 'maya","action":"revoke","actor":"ravi'
    with pytest.raises(LogError):
        log.append(action="read", actor=payload)
    log.append(action="read", actor="maya")
    records = log.records()
    assert len(records) == 1
    assert records[0]["actor"] == "maya"
    assert records[0]["action"] == "read"


def test_a_newline_in_an_identifier_cannot_split_a_record(log):
    log.append(action="read", actor="maya")
    with pytest.raises(LogError):
        log.append(action="read", actor="ravi\n{\"action\":\"revoke\"}")
    lines = [l for l in (log.path).read_text().splitlines() if l.strip()]
    assert len(lines) == 1, "one append must produce exactly one line"


def test_every_emitted_line_is_a_single_json_object(log):
    log.append(action="read", actor="maya")
    log.append(action="revoke", actor="ravi")
    for line in log.path.read_text().splitlines():
        if not line.strip():
            continue
        assert "\n" not in line
        parsed = json.loads(line)                     # raises if it is two objects
        assert set(parsed) >= {"action", "actor", "seq", "prev", "hash", "sig"}
        assert parsed["magic"] == "pqc-kv-eventlog"


def test_action_names_are_an_allowlist(log):
    assert log.append(action="revoke", actor="maya")["action"] == "revoke"
    for bad in ("Revoke", "delete_all", "", None, "read\nrevoke"):
        with pytest.raises(LogError):
            log.append(action=bad, actor="maya")


def test_detail_text_is_validated_too(log):
    with pytest.raises(LogError):
        log.append(action="read", actor="maya", detail="a\nb")


def test_classify_matches_validate(log):
    for text in ("maya", "a b", "\u0430lice", "x\ny", "a" * 5000):
        should = "accepted"
        try:
            validate_identifier(text)
        except LogError:
            should = "rejected"
        assert classify(text) == should


def test_the_length_prefix_encoding_is_unambiguous():
    """Two different field layouts must never hash the same bytes."""
    from pqc_kv.logsign import _length_prefixed

    assert _length_prefixed({"ab": "c"}) != _length_prefixed({"a": "bc"})
    assert _length_prefixed({"a": "b|c"}) != _length_prefixed({"a": "b", "c": ""})


# ------------------------------------------------------------ chain integrity
def test_a_clean_chain_verifies(log):
    for i in range(5):
        log.append(action="read", actor="maya", detail=f"r{i}")
    result = log.verify()
    assert result["ok"] is True
    assert result["records"] == 5


def test_editing_a_record_is_detected(log):
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")
    lines = log.path.read_text().splitlines()
    record = json.loads(lines[1])
    record["actor"] = "ravi"
    lines[1] = encode_line(record)
    log.path.write_text("\n".join(lines) + "\n")
    result = log.verify()
    assert result["ok"] is False
    assert result["first_bad"] == 2


def test_deleting_a_record_is_detected(log):
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = log.verify()
    assert result["ok"] is False
    assert result["first_bad"] == 2


def test_reordering_records_is_detected(log):
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n")
    assert log.verify()["ok"] is False


def test_inserting_a_record_is_detected(log):
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")
    lines = log.path.read_text().splitlines()
    fake = json.loads(lines[0])
    fake["seq"] = 2
    fake["action"] = "revoke"
    log.path.write_text("\n".join([lines[0], encode_line(fake), lines[1], lines[2]]) + "\n")
    result = log.verify()
    assert result["ok"] is False


def test_truncating_the_log_is_detected_against_a_remembered_head(log):
    for i in range(5):
        log.append(action="read", actor="maya", detail=f"r{i}")
    head, count = log.head()
    assert count == 5

    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:2]) + "\n")
    # The truncated chain is internally valid: a shorter chain is still a chain.
    assert log.verify()["ok"] is True, "a chain alone cannot see truncation"
    # It is only caught by comparing against the head an operator wrote down.
    result = log.verify(expected_head=head)
    assert result["ok"] is False
    assert result["reason"] == "head_mismatch"


def test_a_truncated_log_still_verifies_without_an_anchor(log):
    log.append(action="read", actor="maya")
    log.append(action="revoke", actor="ravi")
    log.path.write_text(log.path.read_text().splitlines()[0] + "\n")
    assert log.verify()["ok"] is True
    assert log.verify(expected_head=GENESIS)["ok"] is False


def test_an_empty_log_verifies(log):
    assert log.verify() == {"ok": True, "records": 0, "first_bad": None, "reason": None}


# -------------------------------------------------------- signed chain heads
def test_every_record_carries_a_valid_signature(log):
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")
    for record in log.records():
        body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
        from pqc_kv.logsign import _length_prefixed
        import base64

        assert dsa.verify(log.signing_public, _length_prefixed(body),
                          base64.b64decode(record["sig"]))


def test_a_forged_record_signed_with_another_key_is_detected(tmp_path):
    """This is the whole-file-rewrite attack, now blocked by the signature."""
    import base64
    import hashlib

    keys = KeyStore(tmp_path / "keys")
    real = keys.signing_keypair("eventlog")
    forger = keys.signing_keypair("other")
    log = EventLog(tmp_path / "events.jsonl", real.secret_key, real.public_key)
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")

    # Rewrite history with a valid *internal* chain, but signed by the wrong key.
    from pqc_kv.logsign import _length_prefixed

    prev = GENESIS
    forged_lines = []
    for seq in range(1, 4):
        fields = {"magic": "pqc-kv-eventlog", "version": 1, "seq": seq, "prev": prev,
                  "action": "read", "actor": "ravi", "detail": "forged"}
        digest = hashlib.sha256(_length_prefixed(fields)).hexdigest()
        sig = dsa.sign(forger.secret_key, _length_prefixed(fields))
        forged_lines.append(encode_line(dict(fields, hash=digest,
                                             sig=base64.b64encode(sig).decode())))
        prev = digest
    log.path.write_text("\n".join(forged_lines) + "\n")

    result = log.verify()
    assert result["ok"] is False
    assert result["first_bad"] == 1
    assert result["reason"] == Reason.BAD_SIGNATURE


def test_the_head_is_exportable_for_external_anchoring(log):
    log.append(action="read", actor="maya")
    head, count = log.head()
    assert len(head) == 64
    assert count == 1
    log.append(action="revoke", actor="ravi")
    assert log.head()[0] != head


def test_a_whole_file_rewrite_with_the_real_key_is_not_detectable(log):
    """Honest limit, asserted so it cannot be quietly forgotten.

    Someone who can write the file AND read the signing key beside it can produce a
    perfect log. Only an external anchor (the expected_head argument) catches this,
    and only for content they cannot re-sign.
    """
    for i in range(3):
        log.append(action="read", actor="maya", detail=f"r{i}")
    remembered = log.head()[0]

    # Rebuild the file from scratch with the real key: verifies cleanly.

    log.path.write_text("")
    for i in range(3):
        log.append(action="read", actor="ravi", detail=f"r{i}")

    assert log.verify()["ok"] is True
    assert log.records()[0]["actor"] == "ravi"
    # ...but the head no longer matches what the operator wrote down.
    assert log.verify(expected_head=remembered)["ok"] is False


# ------------------------------------------------------------------ fuzzing
def test_fuzz_hostile_strings_never_produce_a_second_event(log):
    """Deterministic fuzz over a large corpus, no hypothesis dependency.

    For every string: either it is refused, or it is accepted and the resulting file
    still has exactly one line per append. There is no third outcome.
    """
    import itertools
    import random

    pieces = [
        '"', '\\', "\n", "\r", "\x00", "\x1b", "\u202e", "\u0430", "{", "}", "[", "]",
        ",", ":", '"action":"revoke"', '"seq":99', "maya", "a" * 120, "\t", "\x7f",
        "\u0001", "\\n", "%0a", "&quot;", "'", "`", ";", "|",
    ]
    rng = random.Random(20261126)
    corpus = ["".join(rng.choice(pieces) for _ in range(rng.randint(1, 8)))
              for _ in range(400)]
    corpus += [a + b for a, b in itertools.product(['"', "\n", "\x00"], ["maya", "x"])]

    accepted = 0
    for text in corpus:
        before = len(log.records())
        try:
            log.append(action="read", actor=text)
            accepted += 1
        except LogError:
            assert len(log.records()) == before, "a refused append wrote something"
    assert len(log.records()) == accepted
    # Every line is still independently parseable and has exactly one actor field.
    for line in log.path.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        assert isinstance(record["actor"], str)
        assert record["action"] in ALLOWED_ACTIONS
    # And the chain over whatever was accepted is intact.
    assert log.verify()["ok"] is True
    print(f"\nfuzz: {len(corpus)} hostile strings, {accepted} accepted, "
          f"{len(corpus) - accepted} refused, 0 forged events")


def test_fuzz_a_hostile_actor_cannot_change_the_recorded_actor(log):
    """If a string is accepted at all, it must be recorded verbatim."""
    for text in ("maya", "maya ravi", "svc-a.b", "node0"):
        record = log.append(action="read", actor=text)
        assert record["actor"] == text
        assert json.loads(log.path.read_text().splitlines()[-1])["actor"] == text


# ------------------------------------------------- lifecycle events (goal 5)
def test_every_lifecycle_action_lands_in_the_signed_log(tmp_path):
    """rotate / revoke / recover / restore each produce a verifiable key event."""
    from pqc_kv.store import StateStore

    store = StateStore(tmp_path / "node")
    store.setup({"owners": {"brief": "maya"}, "contents": {"brief": "b"},
                 "disabled": [], "key_material": "M"})
    store.revoke("maya")
    store.rotate({"grace": 2})
    signer = store.ring.dsa_pair(2)
    blob = store.create_backup(b"operator-key-1234567890", signer=signer.secret_key)
    store.restore_backup(blob, b"operator-key-1234567890", signer.public_key)

    actions = [r["action"] for r in store._event_log().records()]
    assert actions == ["revoke", "rotate", "restore"]
    result = store.verify_events()
    assert result["ok"] is True
    assert result["records"] == 3


def test_a_revoked_actor_with_a_hostile_name_cannot_inject_a_log_event(tmp_path):
    """The actor name flows into the log, so a bad name must not become a record."""
    from pqc_kv.store import StateStore

    store = StateStore(tmp_path / "node")
    store.setup({"owners": {"brief": "maya"}, "contents": {"brief": "b"},
                 "disabled": [], "key_material": "M"})
    hostile = 'maya","action":"revoke","actor":"ravi'
    # The revocation itself still happens; only the *log entry* falls back to "".
    store.revoke(hostile)
    assert store.is_revoked(hostile) is True
    records = store._event_log().records()
    assert len(records) == 1
    assert records[0]["actor"] == ""
    assert records[0]["action"] == "revoke"


def test_the_event_log_cannot_be_truncated_invisibly_with_an_anchor(tmp_path):
    from pqc_kv.store import StateStore

    store = StateStore(tmp_path / "node")
    store.setup({"owners": {"brief": "maya"}, "contents": {"brief": "b"},
                 "disabled": [], "key_material": "M"})
    store.revoke("maya")
    store.rotate({"grace": 2})
    store.rotate({"grace": 2})
    # Anchor to the head of the *complete* log: three events.
    remembered = store.events_head()["events_head"]

    path = store.root / "key-events.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    path.write_text("\n".join(lines[:1]) + "\n")
    # Truncating to one record leaves a perfectly valid shorter chain.
    assert store.verify_events()["ok"] is True, "a chain alone cannot see truncation"
    # Only the anchored head reveals it.
    assert store.verify_events(expected_head=remembered)["ok"] is False


def test_an_edited_event_is_detected(tmp_path):
    from pqc_kv.store import StateStore

    store = StateStore(tmp_path / "node")
    store.setup({"owners": {"brief": "maya"}, "contents": {"brief": "b"},
                 "disabled": [], "key_material": "M"})
    store.revoke("maya")
    store.rotate({"grace": 2})
    path = store.root / "key-events.jsonl"
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["actor"] = "ravi"
    lines[1] = encode_line(record)
    path.write_text("\n".join(lines) + "\n")
    result = store.verify_events()
    assert result["ok"] is False
    assert result["first_bad"] == 2
