"""Strict ingestion of the practice log format.

The practice data is CSV in **receipt order** with a fixed header. Two properties
matter and are both easy to lose:

* **Receipt order is evidence.** The file's line order is what the collector saw.
  ``evt-014`` arrives before ``evt-013``; that is a fact about delivery, and the
  detector keeps it. Re-sorting on load would destroy the only record of it.
* **A bad line must never become a bad event.** Every line is validated field by
  field; anything that fails is quarantined with a counted reason and a line
  number. Nothing is silently dropped, truncated or repaired, and no input causes
  an exception to escape.

Size limits are enforced before parsing, so a hostile 500 MB "line" costs one
comparison, not a memory fault.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

from . import fields as F

#: Receipt order index for events that arrive out of order relative to event time.
@dataclass(frozen=True)
class Event:
    """One validated log event. All times are integer milliseconds since epoch.

    ``event_ms`` is the *source* stamp exactly as recorded. ``received_ms`` is the
    collector's stamp. ``offset_ms`` is the source's declared offset relative to
    the collector. Correction to a common clock happens in :mod:`timing`; storing
    the raw values here is what makes "sorting a report must not rewrite source
    evidence" true by construction.
    """

    event_id: str
    event_ms: int
    received_ms: int
    offset_ms: int
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str
    approval_id: str
    session_id: str
    correlation_id: str
    receipt_index: int

    # -------------------------------------------------------------- helpers
    @property
    def edges(self) -> tuple[str, str]:
        return (self.source_service, self.target_service)

    @property
    def role_changed(self) -> bool:
        """Structural privilege change: independent of any vocabulary.

        This is the signal that survives a rename. ``role_before != role_after``
        does not care what the roles are called, whether the actor is a person or
        a service, or which dataset this is.
        """
        return bool(self.role_after) and self.role_before != self.role_after

    @property
    def is_success(self) -> bool:
        """The record claims the action took effect.

        The practice data uses ``success`` for actions and ``allow``/``deny`` for
        reads, so we accept both success spellings but require an explicit one.
        An unknown outcome is treated as *not* a success: claiming a compromise
        from an ambiguous record is worse than under-claiming one.
        """
        return self.outcome in ("success", "allow")

    @property
    def is_denial(self) -> bool:
        return self.outcome == "deny"


@dataclass
class IngestResult:
    """Events plus a full accounting of what was refused and why."""

    events: list[Event] = field(default_factory=list)
    #: reason -> count. Never contains a field value.
    rejected: dict = field(default_factory=dict)
    #: First few quarantined lines: (line_number, reason). Bounded so a hostile log
    #: cannot make the report itself unbounded.
    rejected_samples: list = field(default_factory=list)
    header: tuple = ()
    #: True when the caller hit ``max_events`` and the remainder was not read.
    truncated: bool = False
    total_lines_seen: int = 0

    def reject(self, line_number: int, reason: str, *, sample_limit: int = 20) -> None:
        self.rejected[reason] = self.rejected.get(reason, 0) + 1
        if len(self.rejected_samples) < sample_limit:
            self.rejected_samples.append((line_number, reason))

    @property
    def rejected_total(self) -> int:
        return sum(self.rejected.values())


def _decode(raw: bytes) -> str:
    """Bytes to text, or refusal. Never ``errors="replace"``.

    Replacing undecodable bytes would invent characters, and an invented actor
    name is a wrong accusation. UTF-8 is the only encoding we accept.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise F.FieldError(F.Reason.BAD_ENCODING) from None


def parse_csv(
    text: str,
    *,
    config,
    header: tuple[str, ...] | None = None,
) -> IngestResult:
    """Parse a CSV log. Never raises on malformed input; every failure is counted."""
    result = IngestResult()
    columns = tuple(header) if header is not None else tuple(config.columns)
    max_events = config.ingest.max_events
    max_line = config.ingest.max_line_len
    allow_dupes = not config.ingest.reject_duplicate_event_ids

    seen_ids: set[str] = set()

    # A hostile line can be enormous. Check length before handing anything to the
    # csv module, which would otherwise happily build a huge field.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    body_started = False
    for line_number, line in enumerate(lines, start=1):
        result.total_lines_seen += 1
        if len(line) > max_line:
            result.reject(line_number, F.Reason.LINE_TOO_LONG)
            continue
        if line.endswith("\r"):
            line = line[:-1]
        if line.strip() == "":
            # A blank line is the one thing we skip without counting it as an
            # error: trailing newlines are not an attack.
            continue

        if not body_started:
            # Header row. We accept the declared columns in *any* order (a
            # re-ordered export is still valid data) but refuse a different set of
            # columns loudly, rather than mis-parsing a foreign schema.
            body_started = True
            try:
                names = tuple(_split_row(line))
            except F.FieldError:
                result.reject(line_number, F.Reason.BAD_COLUMN_COUNT)
                return result
            if set(names) != set(columns) or len(names) != len(columns):
                result.reject(line_number, F.Reason.BAD_COLUMN_COUNT)
                return result
            columns = names
            result.header = columns
            continue

        if len(result.events) >= max_events:
            result.truncated = True
            break

        try:
            row = _split_row(line)
        except F.FieldError:
            result.reject(line_number, F.Reason.BAD_COLUMN_COUNT)
            continue
        if len(row) != len(columns):
            result.reject(line_number, F.Reason.BAD_COLUMN_COUNT)
            continue

        try:
            event = _build_event(row, columns, line_number, len(result.events))
        except F.FieldError as exc:
            result.reject(line_number, exc.reason)
            continue

        if not allow_dupes and event.event_id in seen_ids:
            # Two records claiming one id: one of them is not what it says it is.
            # Refusing both is impossible (we already consumed the first), so the
            # second is quarantined and the first is kept -- with the collision
            # visible in the report.
            result.reject(line_number, F.Reason.DUPLICATE_EVENT_ID)
            continue
        seen_ids.add(event.event_id)
        result.events.append(event)

    return result


def _split_row(line: str) -> list[str]:
    """CSV-split one line with the stdlib reader (handles quotes and doubled quotes).

    Refuses embedded newlines: a quoted field containing ``\\n`` would otherwise let
    one line become two records and defeat the line accounting above.
    """
    try:
        rows = list(csv.reader(io.StringIO(line, newline=""), strict=True))
    except csv.Error:
        raise F.FieldError(F.Reason.BAD_COLUMN_COUNT) from None
    if len(rows) != 1:
        raise F.FieldError(F.Reason.BAD_COLUMN_COUNT)
    row = rows[0]
    for value in row:
        if "\n" in value or "\r" in value:
            raise F.FieldError(F.Reason.BAD_COLUMN_COUNT)
    return row


def _build_event(row: list[str], columns: tuple[str, ...], line: int, index: int) -> Event:
    """Validate every column and build an Event, or raise on the first bad one."""
    values = dict(zip(columns, row))

    def ident(name: str) -> str:
        return F.validate_ident(values[name], column=columns.index(name))

    event_id = F.validate_event_id(values["event_id"], column=columns.index("event_id"))
    event_ms = F.parse_timestamp(values["event_time_utc"])
    received_ms = F.parse_timestamp(values["received_time_utc"])
    offset_ms = F.parse_offset_ms(values["source_clock_offset_ms"])

    return Event(
        event_id=event_id,
        event_ms=event_ms,
        received_ms=received_ms,
        offset_ms=offset_ms,
        actor=ident("actor"),
        source_service=ident("source_service"),
        target_service=ident("target_service"),
        action=ident("action"),
        # Roles may be blank: a sign-in has no role change, and an empty
        # role_before/role_after is a real state rather than a defect.
        role_before=F.validate_ident(values["role_before"], allow_empty=True),
        role_after=F.validate_ident(values["role_after"], allow_empty=True),
        outcome=ident("outcome"),
        approval_id=F.validate_ident(values["approval_id"], allow_empty=True),
        session_id=F.validate_ident(values["session_id"], allow_empty=True),
        correlation_id=F.validate_ident(values["correlation_id"], allow_empty=True),
        receipt_index=index,
    )


def parse_bytes(data: bytes, *, config) -> IngestResult:
    """Byte input: decode then parse. A non-UTF-8 log is one refusal, not a crash."""
    try:
        text = _decode(data)
    except F.FieldError:
        result = IngestResult()
        result.reject(0, F.Reason.BAD_ENCODING)
        return result
    return parse_csv(text, config=config)


__all__ = ["Event", "IngestResult", "parse_bytes", "parse_csv"]
