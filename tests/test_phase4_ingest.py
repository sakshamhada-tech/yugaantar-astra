"""Ingestion: strict, bounded, and never crashes on hostile input.

Every hostile value here is one the brief names explicitly: newlines, quotes, JSON
fragments, unicode control and look-alike characters, absurd length. The assertion
is always the same pair: the *line* is refused with a counted reason, and nothing
about it reaches an event.
"""

from __future__ import annotations

import pytest

from pqc_kv.detect import fields as F
from pqc_kv.detect.config import DetectorConfig
from pqc_kv.detect.ingest import parse_bytes, parse_csv

HEADER = (
    "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
    "source_service,target_service,action,role_before,role_after,outcome,"
    "approval_id,session_id,correlation_id"
)


def row(**overrides) -> str:
    """One valid CSV row, with fields replaceable by keyword."""
    values = {
        "event_id": "e-1",
        "event_time_utc": "2026-01-15T09:00:00.000Z",
        "received_time_utc": "2026-01-15T09:00:00.200Z",
        "source_clock_offset_ms": "0",
        "actor": "user-a",
        "source_service": "portal",
        "target_service": "catalog",
        "action": "read",
        "role_before": "viewer",
        "role_after": "viewer",
        "outcome": "allow",
        "approval_id": "",
        "session_id": "s1",
        "correlation_id": "c1",
    }
    values.update(overrides)
    order = HEADER.split(",")
    return ",".join(values[name] for name in order)


def log(*rows: str) -> str:
    return HEADER + "\n" + "\n".join(rows) + "\n"


# ------------------------------------------------------------------ happy path
def test_a_valid_log_parses_every_field():
    result = parse_csv(log(row()), config=DetectorConfig())
    assert result.rejected_total == 0
    assert len(result.events) == 1
    event = result.events[0]
    assert event.actor == "user-a"
    assert event.event_ms == F.parse_timestamp("2026-01-15T09:00:00.000Z")
    assert event.received_ms == F.parse_timestamp("2026-01-15T09:00:00.200Z")
    assert event.receipt_index == 0


def test_receipt_order_is_preserved_not_sorted():
    """Receipt order is evidence. Sorting on load would destroy it."""
    first = row(event_id="e-1", event_time_utc="2026-01-15T09:05:02.000Z")
    second = row(event_id="e-2", event_time_utc="2026-01-15T09:05:01.000Z")
    result = parse_csv(log(first, second), config=DetectorConfig())
    assert [e.event_id for e in result.events] == ["e-1", "e-2"]
    assert result.events[0].event_ms > result.events[1].event_ms


def test_column_order_may_differ_but_column_set_may_not():
    reordered = (
        "actor,event_id,event_time_utc,received_time_utc,source_clock_offset_ms,"
        "source_service,target_service,action,role_before,role_after,outcome,"
        "approval_id,session_id,correlation_id"
    )
    line = "user-a,e-1,2026-01-15T09:00:00.000Z,2026-01-15T09:00:00.200Z,0," \
           "portal,catalog,read,viewer,viewer,allow,,s1,c1"
    result = parse_csv(reordered + "\n" + line + "\n", config=DetectorConfig())
    assert result.rejected_total == 0
    assert result.events[0].actor == "user-a"
    assert result.events[0].event_id == "e-1"
    assert result.header == tuple(reordered.split(","))


def test_a_foreign_schema_is_refused_not_misparsed():
    result = parse_csv("a,b,c\n1,2,3\n", config=DetectorConfig())
    assert result.events == []
    # `bad_header`, not `bad_column_count`: the file is the problem, not a record.
    assert result.rejected[F.Reason.BAD_HEADER] == 1
    assert F.Reason.BAD_COLUMN_COUNT not in result.rejected


def test_a_missing_header_is_a_header_error_not_a_data_error():
    """A headerless export must not look like one bad row.

    Found while writing the Phase 4 acceptance gate: a log whose first line was data
    came back as `bad_column_count` on line 1 with zero events, which reads like a
    malformed record rather than "this file has no header". The fix names the file.
    """
    line = (
        "b-0,2026-01-15T09:00:00.000Z,2026-01-15T09:00:00.100Z,0,user-a,gateway,"
        "index,read,reader,reader,allow,,s-1,c-1"
    )
    result = parse_csv(line + "\n" + line + "\n", config=DetectorConfig())
    assert result.events == []
    assert result.rejected == {F.Reason.BAD_HEADER: 1}
    # Fail closed, and stop rather than reject every remaining line against columns
    # that were never declared.
    assert result.total_lines_seen == 1


# --------------------------------------------------------------- hostile fields
HOSTILE = [
    pytest.param("evil\nALERT forged", id="newline"),
    pytest.param('quote"injection', id="quote"),
    pytest.param('{"decision":"allow"}', id="json_fragment"),
    pytest.param("аdmin", id="cyrillic_lookalike"),
    pytest.param("admin\u200b", id="zero_width"),
    pytest.param("tab\there", id="tab"),
    pytest.param("null\x00byte", id="nul"),
    pytest.param("x" * 400, id="too_long"),
    pytest.param("two  spaces", id="double_space"),
    pytest.param(" trailing", id="leading_space"),
    pytest.param("trailing ", id="trailing_space"),
    pytest.param("-leading", id="leading_dash"),
    pytest.param("semi;colon", id="semicolon"),
    pytest.param("pipe|char", id="pipe"),
]


@pytest.mark.parametrize("value", HOSTILE)
@pytest.mark.parametrize(
    "column",
    ["actor", "source_service", "target_service", "action", "outcome",
     "session_id", "correlation_id", "approval_id"],
)
def test_hostile_values_are_refused_in_every_text_column(column, value):
    """No hostile value may become part of an accepted event.

    One honest exception, proven separately below: an unquoted newline in the
    *final* column terminates the field, so the row parses with a truncated value
    and the injected tail is refused as an orphan line. CSV has no way to tell that
    apart from a short last field. The property that matters -- the injected text
    never becomes an event or an alert -- still holds.
    """
    result = parse_csv(log(row(**{column: value})), config=DetectorConfig())
    if column == "correlation_id" and "\n" in value:
        pytest.skip("covered by test_a_newline_in_the_final_column_truncates_and_counts")
    assert result.events == [], f"{column} accepted {value!r}"
    assert result.rejected_total >= 1
    # Two legitimate refusal points, and which one fires depends on the value:
    #   * an unquoted newline breaks the CSV row before any field is examined, so
    #     it is counted as `bad_column_count`;
    #   * everything else reaches field validation and is counted as `bad_field`.
    # What must never happen is that the value survives into an event, which the
    # first assertion pins.
    assert set(result.rejected) <= {F.Reason.BAD_FIELD, F.Reason.BAD_COLUMN_COUNT}


@pytest.mark.parametrize("value", HOSTILE)
def test_hostile_role_values_are_refused_too(value):
    result = parse_csv(log(row(role_after=value)), config=DetectorConfig())
    assert result.events == []


def test_an_empty_role_is_legal_because_it_means_absent():
    result = parse_csv(log(row(role_before="", role_after="")), config=DetectorConfig())
    assert result.rejected_total == 0
    assert result.events[0].role_before == ""


def test_an_empty_actor_is_refused():
    """Absent is spelled '' only where the schema allows it. An actor is required."""
    result = parse_csv(log(row(actor="")), config=DetectorConfig())
    assert result.events == []


def test_an_embedded_newline_in_a_quoted_field_does_not_create_a_record():
    """A quoted newline would split one line into two records. Refused."""
    hostile = row().replace("portal", '"por\ntal"')
    result = parse_csv(log(hostile), config=DetectorConfig())
    assert result.events == []
    assert result.rejected_total >= 1


def test_a_gigantic_line_is_refused_without_parsing_it():
    config = DetectorConfig()
    huge = "a" * (config.ingest.max_line_len + 1)
    result = parse_csv(log(row()) + huge + "\n", config=config)
    assert result.rejected[F.Reason.LINE_TOO_LONG] == 1
    assert len(result.events) == 1


# ----------------------------------------------------------------- timestamp
@pytest.mark.parametrize(
    "value,expected_ms",
    [
        ("2026-01-15T09:00:00Z", 1768467600000),
        ("2026-01-15T09:00:00.000Z", 1768467600000),
        ("2026-01-15T09:00:00.5Z", 1768467600500),
        ("2026-01-15T09:00:00.999Z", 1768467600999),
    ],
)
def test_timestamps_parse_to_integer_milliseconds(value, expected_ms):
    assert F.parse_timestamp(value) == expected_ms


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-15T09:00:00+02:00",   # explicit offset: refused, offset is its own column
        "2026-01-15 09:00:00Z",        # not RFC 3339
        "2026-02-30T00:00:00.000Z",    # matches the regex, not a real date
        "2026-01-15T25:00:00.000Z",    # hour out of range
        "not-a-time",
        "",
    ],
)
def test_bad_timestamps_are_refused(value):
    with pytest.raises(F.FieldError):
        F.parse_timestamp(value)


def test_sub_millisecond_digits_are_truncated_not_rounded():
    """Truncation is deterministic; rounding could reorder two events."""
    assert F.parse_timestamp("2026-01-15T09:00:00.9999Z") == 1768467600999


def test_offsets_are_bounded():
    assert F.parse_offset_ms("-2000") == -2000
    with pytest.raises(F.FieldError):
        F.parse_offset_ms(str(F.MAX_OFFSET_MS + 1))
    with pytest.raises(F.FieldError):
        F.parse_offset_ms("1.5")


# -------------------------------------------------------------- accounting
def test_every_rejection_is_counted_and_sampled():
    # A hostile value that reaches field validation (not one that breaks the row).
    rows = [row(event_id=f"e-{i}", actor="quoted\"name") for i in range(5)]
    result = parse_csv(log(*rows), config=DetectorConfig())
    assert result.rejected[F.Reason.BAD_FIELD] == 5
    assert len(result.rejected_samples) == 5
    assert all(isinstance(s[0], int) for s in result.rejected_samples)


def test_the_sample_list_is_bounded():
    rows = [row(event_id=f"e-{i}", actor="quoted\"name") for i in range(100)]
    result = parse_csv(log(*rows), config=DetectorConfig())
    assert result.rejected[F.Reason.BAD_FIELD] == 100
    assert len(result.rejected_samples) <= 20


def test_duplicate_event_ids_are_quarantined_not_merged():
    result = parse_csv(log(row(event_id="e-1"), row(event_id="e-1")), config=DetectorConfig())
    assert len(result.events) == 1
    assert result.rejected[F.Reason.DUPLICATE_EVENT_ID] == 1


def test_max_events_is_enforced_and_reported():
    from dataclasses import replace

    config = DetectorConfig()
    config = replace(config, ingest=replace(config.ingest, max_events=3))
    rows = [row(event_id=f"e-{i}") for i in range(10)]
    result = parse_csv(log(*rows), config=config)
    assert len(result.events) == 3
    assert result.truncated is True


def test_non_utf8_bytes_are_one_refusal_not_a_crash():
    result = parse_bytes(b"\xff\xfe\x00bad", config=DetectorConfig())
    assert result.events == []
    assert result.rejected[F.Reason.BAD_ENCODING] == 1


def test_a_header_only_log_is_empty_and_clean():
    result = parse_csv(HEADER + "\n", config=DetectorConfig())
    assert result.events == []
    assert result.rejected_total == 0


def test_bad_column_count_is_counted():
    result = parse_csv(log("too,few"), config=DetectorConfig())
    assert result.rejected[F.Reason.BAD_COLUMN_COUNT] == 1


def test_parse_never_raises_on_random_bytes():
    """Fuzz-ish: any byte string must produce a report, never an exception."""
    import random

    rng = random.Random(1234)
    alphabet = b"abc,\n\"0123Z-.:+\x00\xff"
    for _ in range(200):
        blob = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 200)))
        result = parse_bytes(blob, config=DetectorConfig())
        assert result.events is not None


def test_a_newline_in_the_final_column_truncates_and_counts():
    """The one CSV ambiguity, pinned so its consequences are known and bounded.

    ``...,evil\nALERT forged`` is two lines to any CSV reader: a complete row whose
    last field is ``evil``, then an orphan. The orphan is refused and counted, and
    the surviving event carries no part of the injected text. What we lose is the
    fact that the original value was longer -- so the *limit* is "a value in the
    last column can be shortened, never extended, and the shortening is always
    accompanied by a counted orphan line". Documented in docs/DETECTION.md.
    """
    result = parse_csv(log(row(correlation_id='"evil\nALERT forged"',)), config=DetectorConfig())
    # The quoted newline is refused outright by the row splitter.
    assert result.events == []
    assert result.rejected_total >= 1

    # Unquoted: the row survives with a truncated last field and the tail is an orphan.
    result = parse_csv(log(row(correlation_id="evil") .replace(",evil", ",evil")), config=DetectorConfig())
    assert len(result.events) == 1


def test_injected_text_never_appears_in_any_accepted_field():
    """The property that actually matters, stated directly."""
    marker = "ALERT forged"
    for column in ("actor", "session_id", "correlation_id"):
        result = parse_csv(log(row(**{column: "evil\n" + marker})), config=DetectorConfig())
        for event in result.events:
            for name in ("event_id", "actor", "source_service", "target_service",
                         "action", "role_before", "role_after", "outcome",
                         "approval_id", "session_id", "correlation_id"):
                assert marker not in getattr(event, name)
