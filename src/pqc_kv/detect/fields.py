"""Strict field policy for detection input.

Log lines are hostile input. Names, service ids and reasons can carry newlines,
quotes, JSON fragments, unicode control or look-alike characters, or be absurdly
long. This module is the only place that decides what a log field may look like,
and it follows the Phase 3 rule exactly: **validate, never sanitise**.

Why refuse rather than clean
----------------------------
Stripping a newline out of ``"user-a\\nuser-b"`` produces ``user-auser-b`` -- a
name that appears nowhere in the data and that silently merges two identities into
one. Truncating a 5000-character actor to 96 characters makes a record about
somebody else. Both failures are worse than rejecting the line, because the
operator cannot see that it happened. So a field is either accepted verbatim or
the whole event is quarantined with a counted reason.

The charset is deliberately narrow ASCII. Cyrillic ``а`` (U+0430) and Latin ``a``
are the classic way to make an actor look like a different actor in a report;
we refuse non-ASCII outright rather than guess. This is a *detection* input
policy, not a general-purpose text field, so the narrowness costs nothing real.

Every rejection carries a machine-readable reason from :class:`Reason`. Event
idents are kept exactly as given (they are evidence), so their charset is a
little wider -- but still no whitespace, quotes or control characters, so an
event id can never break a line or a table cell.
"""

from __future__ import annotations

import datetime as _dt
import re

#: Longest identity/service/action/session/correlation/approval value we accept.
#: 96 characters is far beyond any real principal name and short enough that a
#: 100k-event log cannot be inflated into gigabytes by one field.
MAX_FIELD_LEN = 96
#: Event ids are quoted back in alerts as evidence, so they get their own cap.
MAX_EVENT_ID_LEN = 64
#: No log line may be longer than this. Enforced *before* parsing so a gigantic
#: line cannot be used to exhaust memory.
MAX_LINE_LEN = 65536
#: Hard cap on events accepted from one request, so a hostile caller cannot ask
#: for unbounded work. Rejecting is reported, never silent.
MAX_EVENTS = 1_000_000

_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@:#+/-]*$")
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]*$")
#: Field names in our own alert objects. Never taken from input.
_SAFE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")

#: Timestamp format used by the practice data: RFC 3339 with milliseconds and a
#: literal ``Z``. A bare ``Z`` is UTC by definition, so there is no local-time
#: ambiguity to resolve -- we never consult the host timezone.
_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"
)


class Reason:
    """Counted, reported ingest outcomes. Never carries the offending value."""

    EMPTY_LINE = "empty_line"
    LINE_TOO_LONG = "line_too_long"
    BAD_COLUMN_COUNT = "bad_column_count"
    BAD_FIELD = "bad_field"
    BAD_TIMESTAMP = "bad_timestamp"
    BAD_OFFSET = "bad_offset"
    BAD_ENCODING = "bad_encoding"
    DUPLICATE_EVENT_ID = "duplicate_event_id"


class FieldError(Exception):
    """Raised when one field is unacceptable. Reason only, never the value."""

    __slots__ = ("reason", "column")

    def __init__(self, reason: str, column: int = -1) -> None:
        super().__init__(reason)
        self.reason = reason
        self.column = column


def validate_ident(value: str, *, column: int = -1, allow_empty: bool = False) -> str:
    """Accept an identity/service/action string verbatim, or refuse it.

    Empty means "absent" in the practice schema (``approval_id`` is often empty),
    which is a real state and cannot smuggle anything. Everything else must be a
    bounded printable-ASCII token.
    """
    if not isinstance(value, str):
        raise FieldError(Reason.BAD_FIELD, column)
    if value == "":
        if allow_empty:
            return ""
        raise FieldError(Reason.BAD_FIELD, column)
    if len(value) > MAX_FIELD_LEN:
        raise FieldError(Reason.BAD_FIELD, column)
    if not _IDENT_RE.match(value):
        raise FieldError(Reason.BAD_FIELD, column)
    # A trailing dot or space, or a doubled space, is legal per the regex but is a
    # classic confusion trick ("user-alex" vs "user-alex "). Refuse the shape here
    # rather than deciding later that two names are the same.
    if value != value.strip() or "  " in value:
        raise FieldError(Reason.BAD_FIELD, column)
    return value


def validate_event_id(value: str, *, column: int = -1) -> str:
    """Event ids are quoted back as evidence. Keep them exactly, but bound them."""
    if not isinstance(value, str) or not value:
        raise FieldError(Reason.BAD_FIELD, column)
    if len(value) > MAX_EVENT_ID_LEN:
        raise FieldError(Reason.BAD_FIELD, column)
    if not _EVENT_ID_RE.match(value):
        raise FieldError(Reason.BAD_FIELD, column)
    return value


def parse_timestamp(value: str, *, column: int = -1) -> int:
    """Parse an RFC 3339 ``...Z`` stamp into integer **milliseconds** since epoch.

    Milliseconds throughout, because the practice data's finest unit is
    milliseconds and comparing integers removes every float-rounding question
    from ordering decisions. Truncates (never rounds) sub-millisecond digits so
    the same input can never produce two different orderings.

    Time is timezone-explicit: the trailing ``Z`` means UTC and nothing else. We
    refuse offsets like ``+02:00`` on purpose -- the source's clock offset is a
    *separate column* here, and silently folding two different mechanisms into
    one timestamp is how ordering bugs happen.
    """
    if not isinstance(value, str):
        raise FieldError(Reason.BAD_TIMESTAMP, column)
    match = _TS_RE.match(value)
    if match is None:
        raise FieldError(Reason.BAD_TIMESTAMP, column)
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    frac = match.group(7) or ""
    millis = int((frac + "000")[:3]) if frac else 0
    try:
        stamp = _dt.datetime(
            year, month, day, hour, minute, second, tzinfo=_dt.timezone.utc
        )
    except ValueError:
        # 2026-02-30T00:00:00Z matches the regex and is not a real instant.
        raise FieldError(Reason.BAD_TIMESTAMP, column) from None
    epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
    return int((stamp - epoch).total_seconds()) * 1000 + millis


def format_timestamp(millis: int) -> str:
    """Render milliseconds back to the input format, for human-readable output."""
    stamp = _dt.datetime.fromtimestamp(millis / 1000.0, tz=_dt.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis % 1000:03d}Z"


def parse_offset_ms(value: str, *, column: int = -1) -> int:
    """Parse ``source_clock_offset_ms``.

    Defined by the practice README as *known source offset relative to collector
    time*: subtract it from ``event_time_utc`` to get collector-clock event time.
    Bounded to +-1 hour; beyond that the value is not a clock offset, it is a
    corrupt or hostile field, and any ordering derived from it would be a guess.
    """
    if not isinstance(value, str) or value == "":
        raise FieldError(Reason.BAD_OFFSET, column)
    try:
        number = int(value, 10)
    except ValueError:
        raise FieldError(Reason.BAD_OFFSET, column) from None
    if abs(number) > MAX_OFFSET_MS:
        raise FieldError(Reason.BAD_OFFSET, column)
    return number


#: A per-source offset beyond an hour is refused at ingest rather than guessed at.
MAX_OFFSET_MS = 3_600_000


def safe_key(name: str) -> str:
    """Assert a key in our own output object is well-formed.

    Our alert dicts are built from literals, never from input, but this is cheap
    insurance: if a future edit ever splices an input value into a *key*, the
    detector raises instead of emitting attacker-chosen JSON structure.
    """
    if not isinstance(name, str) or not _SAFE_KEY_RE.match(name):
        raise FieldError(Reason.BAD_FIELD)
    return name


__all__ = [
    "MAX_EVENTS", "MAX_FIELD_LEN", "MAX_EVENT_ID_LEN", "MAX_LINE_LEN", "MAX_OFFSET_MS",
    "FieldError", "Reason", "format_timestamp", "parse_offset_ms", "parse_timestamp",
    "safe_key", "validate_event_id", "validate_ident",
]
