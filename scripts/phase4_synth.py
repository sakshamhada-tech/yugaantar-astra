#!/usr/bin/env python3
"""Generate messy synthetic audit logs with ground-truth labels.

**Why this lives in ``scripts/`` and not in ``src/pqc_kv/detect/``**
It must not share a single constant with the detector. If the generator and the
rules agreed on, say, which services count as sensitive, the evaluation would
measure agreement between two copies of my own assumptions instead of measuring
whether the rules generalise. The generator imports nothing from ``pqc_kv``, and
the detector imports nothing from ``scripts``.

**What it produces that the practice data does not have**

* different identities, services and vocabulary (``northwind`` namespaces);
* volumes from a dozen events to hundreds of thousands;
* benign administration that *looks* alarming -- a first-ever role grant that is
  properly approved, a new-but-authorized service rollout;
* malicious activity that *looks* routine -- a role change for a role the subject
  already had, lateral movement over two hops instead of three;
* out-of-order delivery and per-source clock offsets, including one source whose
  offset exceeds the stated tolerance;
* hostile strings: newlines, quotes, JSON fragments, unicode look-alikes, control
  characters and 10 KB values, all of which must be quarantined rather than
  corrupting an alert;
* deliberately absent approvals, so the "no change control" path is exercised.

**Labels** are written as one row per (event_id, label) with the convention:
``malicious`` means "a human would want this in an incident report";
``benign`` covers routine work *and* approved administration. Incidents are
grouped with ``incident_id`` so time-to-alert can be computed from the first
malicious event of a group.

Deterministic: seeded, no wall clock, no environment reads. Two runs of the same
command produce byte-identical files.
"""

from __future__ import annotations

import argparse
import csv
import io
import random
from datetime import datetime, timedelta, timezone

GENERATOR_VERSION = "1.0"

# --------------------------------------------------------------------- vocab
# Deliberately unlike both the practice data and the detector's docs.
BENIGN_IDENTITIES = [
    "ana.petrova", "ben.okafor", "chen.wei", "dara.osei", "eli.ramirez",
    "farah.nasser", "gus.lindqvist", "hana.sato", "ivan.dvorak", "jo.mbeki",
    "kim.devries", "lena.moreau",
]
OPERATORS = ["ops.mirela", "ops.tomas", "ops.rhea"]
WORKERS = ["svc-ledger", "svc-notify", "svc-index", "svc-mediahub", "svc-cleanup"]

SERVICES = [
    "gateway", "directory", "vault", "ledger", "notify", "index",
    "mediahub", "scheduler", "metrics", "reports", "warehouse", "cleanup",
]
#: Services only an operator on the console legitimately starts from.
ADMIN_SOURCES = ["console", "directory"]

ROLES = ["reader", "analyst", "publisher", "reviewer", "operator"]
LOW_ROLES = ["reader", "analyst"]

BASE_TIME = datetime(2026, 3, 2, 0, 0, 0, tzinfo=timezone.utc)

COLUMNS = [
    "event_id", "event_time_utc", "received_time_utc", "source_clock_offset_ms",
    "actor", "source_service", "target_service", "action", "role_before",
    "role_after", "outcome", "approval_id", "session_id", "correlation_id",
]


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_stamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )


class Builder:
    """Accumulates events plus ground truth, then writes the two files."""

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.rows: list = []
        self.labels: list = []
        self.approvals: list = []
        self._n = 0
        self._incident = 0
        #: source service -> declared clock offset in ms.
        self.source_offsets: dict = {}

    # ------------------------------------------------------------------ core
    def add(
        self,
        *,
        at: datetime,
        actor: str,
        source: str,
        target: str,
        action: str,
        role_before: str = "",
        role_after: str = "",
        outcome: str = "allow",
        approval: str = "",
        session: str = "",
        correlation: str = "",
        event_id: str | None = None,
        label: str = "benign",
        incident: str = "",
        reason: str = "",
        delay_ms: int | None = None,
        offset_ms: int | None = None,
    ) -> str:
        self._n += 1
        eid = event_id or f"nw-{self._n:06d}"
        offset = offset_ms if offset_ms is not None else self.source_offsets.get(source, 0)
        # Received time is event time + transit + the source's own error, which is
        # how a real collector sees a skewed clock: the arrival instant is what the
        # network delivers, and the timestamp inside carries the skew.
        transit = delay_ms if delay_ms is not None else self.rng.randint(5, 400)
        received = at + timedelta(milliseconds=transit)
        self.rows.append({
            "event_id": eid,
            "event_time_utc": _stamp(at),
            "received_time_utc": _stamp(received),
            "source_clock_offset_ms": str(offset),
            "actor": actor,
            "source_service": source,
            "target_service": target,
            "action": action,
            "role_before": role_before,
            "role_after": role_after,
            "outcome": outcome,
            "approval_id": approval,
            "session_id": session or f"s-{actor.split('.')[0]}",
            "correlation_id": correlation or f"c-{self._n:06d}",
        })
        self.labels.append({
            "event_id": eid,
            "label": "malicious" if label == "malicious" else "benign",
            "category": label,
            "incident_id": incident,
            "reason": reason,
        })
        return eid

    def new_incident(self, name: str) -> str:
        self._incident += 1
        return f"inc-{self._incident:03d}-{name}"

    def approve(self, **kwargs) -> str:
        self.approvals.append(kwargs)
        return kwargs["approval_id"]

    # ------------------------------------------------------------------ files
    def events_csv(self) -> str:
        """Rows in **receipt order**, which is deliberately not event order.

        A real collector appends as events arrive, so the file order *is* the
        received-time order. Scenarios are generated out of order for convenience,
        so the sort happens here -- once, at write time -- rather than being left to
        the detector. A file whose rows were not in receipt order would not be a
        log; it would be a log someone had already shuffled.
        """
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        indexed = list(enumerate(self.rows))
        indexed.sort(key=lambda pair: (_parse_stamp(pair[1]["received_time_utc"]),
                                       pair[0]))
        for _, row in indexed:
            writer.writerow(row)
        return out.getvalue()

    def labels_csv(self) -> str:
        out = io.StringIO()
        writer = csv.DictWriter(
            out,
            fieldnames=["event_id", "label", "category", "incident_id", "reason"],
            lineterminator="\n",
        )
        writer.writeheader()
        for row in self.labels:
            writer.writerow(row)
        return out.getvalue()

    def approvals_json(self) -> str:
        import json

        return json.dumps(
            {"synthetic": True, "generator": GENERATOR_VERSION, "changes": self.approvals},
            indent=2,
            sort_keys=True,
        ) + "\n"


# ----------------------------------------------------------------- scenarios
def _window(at: datetime, minutes: int = 30) -> tuple[str, str]:
    return (
        _stamp(at - timedelta(minutes=5)),
        _stamp(at + timedelta(minutes=minutes)),
    )


def scenario_routine(b: Builder, days: int = 2, per_day: int = 40) -> None:
    """Benign traffic that establishes a baseline for each identity."""
    rng = b.rng
    for day in range(days):
        for identity in BENIGN_IDENTITIES:
            home = rng.choice(["gateway", "directory", "reports", "metrics"])
            role = rng.choice(LOW_ROLES)
            for _ in range(rng.randint(2, per_day // len(BENIGN_IDENTITIES) + 3)):
                at = BASE_TIME + timedelta(
                    days=day, hours=rng.randint(0, 20), minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                target = rng.choice(["directory", "reports", "metrics", "index"])
                b.add(
                    at=at, actor=identity, source=home, target=target,
                    action="read", role_before=role, role_after=role,
                    outcome="allow", label="benign", reason="routine read",
                )
            b.add(
                at=BASE_TIME + timedelta(days=day, hours=8, minutes=1),
                actor=identity, source="gateway", target="directory",
                action="sign_in", role_before=role, role_after=role,
                outcome="success", label="benign", reason="sign-in",
            )
    for worker in WORKERS:
        peer = rng.choice(SERVICES)
        for day in range(days):
            for _ in range(6):
                at = BASE_TIME + timedelta(
                    days=day, hours=rng.randint(0, 23), minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                b.add(
                    at=at, actor=worker, source=peer, target=rng.choice(
                        ["index", "notify", "ledger"]
                    ),
                    action="read", role_before="service-reader",
                    role_after="service-reader", outcome="allow",
                    label="benign", reason="routine service call",
                )


def scenario_approved_admin(b: Builder, count: int = 6, offset_hours: float = 35.0) -> None:
    """Benign administration that looks alarming: brand-new grants, properly ticketed.

    This is the main false-positive trap. Every one of these events is a
    first-seen privilege change for its subject, and every one is authorised.
    """
    rng = b.rng
    for index in range(count):
        subject = rng.choice(BENIGN_IDENTITIES)
        role = rng.choice(["analyst", "reviewer", "publisher"])
        at = BASE_TIME + timedelta(hours=offset_hours, minutes=index * 7)
        approval = f"chg-{2000 + int(offset_hours) * 10 + index}"
        start, until = _window(at, minutes=45)
        b.approve(
            approval_id=approval, approved_by=rng.choice(OPERATORS),
            subject=subject, operation="grant_role", role=role,
            scope=[rng.choice(["reports", "warehouse"]), "reports-node-a"],
            valid_from_utc=start, valid_until_utc=until,
        )
        operator = rng.choice(OPERATORS)
        b.add(
            at=at - timedelta(seconds=40), actor=operator, source="console",
            target="directory", action="approve_role_change",
            role_before="operator", role_after="operator", outcome="success",
            approval=approval, label="benign", reason="operator approves the change",
        )
        b.add(
            at=at, actor=subject, source="console", target="directory",
            action="role_change", role_before="reader", role_after=role,
            outcome="success", approval=approval, label="benign",
            reason="approved grant inside its window",
        )
        b.add(
            at=at + timedelta(seconds=rng.randint(20, 200)), actor=subject,
            source="gateway", target="reports", action="read",
            role_before=role, role_after=role, outcome="allow", approval=approval,
            label="benign", reason="access inside the approved scope",
        )


def scenario_unapproved_admin(b: Builder, *, at: datetime, subject: str) -> None:
    """Malicious: privilege escalation with no ticket at all."""
    incident = b.new_incident("escalation")
    b.add(
        at=at, actor=subject, source="console", target="directory",
        action="role_change", role_before="reader", role_after="operator",
        outcome="success", label="malicious", incident=incident,
        reason="self-granted operator role, no approval",
    )
    for hop in range(2):
        b.add(
            at=at + timedelta(seconds=30 + hop * 20), actor=subject,
            source="gateway" if hop == 0 else "reports", target="warehouse",
            action="read", role_before="operator", role_after="operator",
            outcome="allow", label="malicious", incident=incident,
            reason="data access immediately after the unapproved escalation",
        )


def scenario_invalid_ticket(b: Builder, *, at: datetime, subject: str,
                            other_subject: str, approval: str) -> None:
    """Malicious-but-subtle: cites a real ticket that covers something else.

    This is the near-miss the matching facts exist for. A detector that treats
    "an approval id is present" as approval passes this; requiring subject, role
    and window to match does not.
    """
    rng = b.rng
    incident = b.new_incident("borrowed-ticket")
    start, until = _window(at - timedelta(hours=6), minutes=20)
    b.approve(
        approval_id=approval, approved_by=rng.choice(OPERATORS),
        subject=other_subject, operation="grant_role", role="analyst",
        scope=["reports"], valid_from_utc=start, valid_until_utc=until,
    )
    b.add(
        at=at, actor=subject, source="console", target="directory",
        action="role_change", role_before="reader", role_after="operator",
        outcome="success", approval=approval, label="malicious", incident=incident,
        reason="cites another subject's expired, different-role ticket",
    )


def scenario_role_mismatch(b: Builder, *, at: datetime, subject: str,
                           approval: str) -> None:
    """Malicious: a ticket for a *lesser* role used to justify a greater one.

    This is the attack the role fact exists for. The subject, the operator and the
    time all match a real ticket; only the granted role differs. A detector that
    matched on subject and time alone would call this authorised.
    """
    rng = b.rng
    incident = b.new_incident("role-mismatch")
    start, until = _window(at + timedelta(hours=3), minutes=60)
    b.approve(
        approval_id=approval, approved_by=rng.choice(OPERATORS),
        subject=subject, operation="grant_role", role="reviewer",
        scope=["reports"], valid_from_utc=start, valid_until_utc=until,
    )
    b.add(
        at=at + timedelta(hours=3), actor=subject, source="console",
        target="directory", action="role_change", role_before="reader",
        role_after="operator", outcome="success", approval=approval,
        label="malicious", incident=incident,
        reason="granted operator under a ticket that authorises reviewer",
    )


def scenario_expired_ticket(b: Builder, *, at: datetime, subject: str,
                            approval: str) -> None:
    """Malicious: a genuine ticket for this very change, used after it expired."""
    rng = b.rng
    incident = b.new_incident("expired-ticket")
    # Window closed an hour before the event, far outside any clock tolerance.
    b.approve(
        approval_id=approval, approved_by=rng.choice(OPERATORS),
        subject=subject, operation="grant_role", role="operator",
        scope=["warehouse"], valid_from_utc=_stamp(at - timedelta(hours=6)),
        valid_until_utc=_stamp(at - timedelta(hours=2)),
    )
    b.add(
        at=at, actor=subject, source="console", target="directory",
        action="role_change", role_before="analyst", role_after="operator",
        outcome="success", approval=approval, label="malicious",
        incident=incident,
        reason="correct ticket, used two hours after it expired",
    )


def scenario_self_approval(b: Builder, *, at: datetime, subject: str,
                           approval: str) -> None:
    """Malicious: the subject approves its own change."""
    incident = b.new_incident("self-approval")
    start, until = _window(at)
    b.approve(
        approval_id=approval, approved_by=subject, subject=subject,
        operation="grant_role", role="operator", scope=["warehouse"],
        valid_from_utc=start, valid_until_utc=until,
    )
    b.add(
        at=at, actor=subject, source="console", target="directory",
        action="role_change", role_before="operator", role_after="operator",
        outcome="success", approval=approval, label="malicious", incident=incident,
        reason="self-approved privileged change",
    )


def scenario_lateral_chain(b: Builder, *, started: datetime, worker: str,
                           chain: list) -> None:
    """Malicious: valid credentials walking a new path, all allowed."""
    incident = b.new_incident("lateral")
    for index, (source, target) in enumerate(chain):
        b.add(
            at=started + timedelta(minutes=index * 2), actor=worker,
            source=source, target=target, action="read",
            role_before="service-reader", role_after="service-reader",
            outcome="allow", label="malicious", incident=incident,
            reason=f"hop {index + 1} of a first-seen service chain",
        )


def scenario_benign_variety(b: Builder, count: int = 25) -> None:
    """Benign but *varied* traffic: ordinary one-off accesses to unfamiliar services.

    This is the scenario that makes a false-positive rate meaningful. Without it the
    benign half of this log is homogeneous -- each identity reads a fixed home
    service and a small target set -- so first-seen edges almost never occur benignly
    and any detector scores perfectly. Real traffic is not like that: people chase a
    question into a service they have not touched before, and every such access is a
    legitimate first-seen edge.

    These events are labelled benign and a good detector will alert on some of them.
    That is the point: they are the cost of the rule, and hiding them would make the
    reported numbers a measure of the generator's tidiness rather than of the
    detector.
    """
    rng = b.rng
    for index in range(count):
        identity = rng.choice(BENIGN_IDENTITIES)
        at = BASE_TIME + timedelta(
            days=1, hours=rng.randint(0, 20), minutes=rng.randint(0, 59)
        )
        target = rng.choice(["warehouse", "mediahub", "scheduler", "cleanup"])
        b.add(
            at=at, actor=identity, source=rng.choice(["gateway", "reports"]),
            target=target, action="read", role_before="reader",
            role_after="reader", outcome="allow", label="benign",
            reason="one-off legitimate access to an unfamiliar service",
        )


def scenario_noise_denials(b: Builder, count: int = 12) -> None:
    """Benign: isolated and paired denials that must NOT look like movement."""
    rng = b.rng
    for index in range(count):
        identity = rng.choice(BENIGN_IDENTITIES)
        at = BASE_TIME + timedelta(days=1, hours=9, minutes=index * 3)
        b.add(
            at=at, actor=identity, source="gateway", target="warehouse",
            action="read", role_before="reader", role_after="reader",
            outcome="deny", label="benign",
            reason="permission denied, no chain out of the denied service",
        )


def scenario_clock_skew(b: Builder) -> None:
    """Benign: out-of-order delivery and a skewed source, correctly labelled."""
    # A source 4.5 seconds fast. Its events look later than they are.
    b.source_offsets["scheduler"] = 4500
    identity = "dara.osei"
    at = BASE_TIME + timedelta(days=1, hours=10)
    first = b.add(
        at=at, actor=identity, source="scheduler", target="index", action="read",
        role_before="reader", role_after="reader", outcome="allow",
        label="benign", reason="event from a source with a +4.5s clock offset",
        delay_ms=200,
    )
    # Delivered *before* the earlier event, which is the normal reordering case.
    second = b.add(
        at=at + timedelta(seconds=1), actor=identity, source="scheduler",
        target="metrics", action="read", role_before="reader",
        role_after="reader", outcome="allow", label="benign",
        reason="arrives after the previous event in event time",
        delay_ms=50,
    )
    return first, second


def scenario_extreme_skew(b: Builder) -> None:
    """A source whose offset is beyond the supported range.

    Nothing malicious happens here. The point is that the detector must refuse to
    claim an order involving this source rather than sort it confidently.
    """
    b.source_offsets["metrics"] = 900_000  # 15 minutes
    b.add(
        at=BASE_TIME + timedelta(days=1, hours=12), actor="hana.sato",
        source="metrics", target="index", action="read", role_before="reader",
        role_after="reader", outcome="allow", label="benign",
        reason="source offset far outside the orderable range",
    )


def scenario_hostile(b: Builder) -> None:
    """Hostile field values. These lines must be quarantined, never alerted on."""
    at = BASE_TIME + timedelta(days=1, hours=13)
    hostile = [
        "evil\nALERT forged",
        'quote"injection',
        '{"decision":"allow"}',
        "аdmin",                       # Cyrillic а
        "admin\u200b",
        "x" * 400,
        "actor with  double space",
        " leading-space",
        "-leading-dash",
    ]
    for index, value in enumerate(hostile):
        # Written directly, bypassing Builder.add's own quoting, so the *writer*
        # is exercised rather than the generator's validation.
        b.rows.append({
            "event_id": f"nw-hostile-{index:02d}",
            "event_time_utc": _stamp(at),
            "received_time_utc": _stamp(at),
            "source_clock_offset_ms": "0",
            "actor": value,
            "source_service": "gateway",
            "target_service": "directory",
            "action": "read",
            "role_before": "reader",
            "role_after": "reader",
            "outcome": "allow",
            "approval_id": "",
            "session_id": "s-hostile",
            "correlation_id": f"c-hostile-{index}",
        })
        b.labels.append({
            "event_id": f"nw-hostile-{index:02d}",
            "label": "benign",
            "category": "hostile_input",
            "incident_id": "",
            "reason": f"hostile actor value #{index}; expected to be quarantined",
        })


def scenario_early_bad_actor(b: Builder, *, actor: str) -> None:
    """An attacker who behaves badly *during the baseline*, poisoning it.

    The detector cannot catch this with novelty rules: by the time of the
    evaluation window the edge is "normal" for them. It is included so the
    limitation is measured rather than described.
    """
    incident = b.new_incident("baseline-poisoning")
    for day in range(2):
        b.add(
            at=BASE_TIME + timedelta(days=day, hours=3, minutes=10),
            actor=actor, source="gateway", target="vault", action="read",
            role_before="reader", role_after="reader", outcome="allow",
            label="malicious", incident=incident,
            reason="hostile access during the baseline window",
        )
    b.add(
        at=BASE_TIME + timedelta(days=1, hours=21), actor=actor, source="gateway",
        target="vault", action="read", role_before="reader", role_after="reader",
        outcome="allow", label="malicious", incident=incident,
        reason="same edge after the baseline; now 'normal' and expected to be missed",
    )


def build(seed: int = 20260302) -> Builder:
    """Two halves of the timeline, each carrying every scenario type.

    The doubling is not padding. The evaluator splits tuning and held-out by
    *identity parity and time*, so a log where every incident happened late would
    make the tuning half contain no positives at all -- the split would then prove
    nothing, because there would be nothing to hold out. Emitting each shape in
    both halves means both subsets contain positives, and the held-out number is a
    real out-of-sample measurement rather than an artefact of an empty set.
    """
    b = Builder(seed)
    scenario_routine(b, days=2, per_day=40)
    scenario_noise_denials(b)

    halves = [
        # (time, subject pool, worker, ticket ids) -- disjoint pools per half.
        (BASE_TIME + timedelta(days=1, hours=13),
         ["ana.petrova", "ben.okafor", "chen.wei", "ops.mirela"],
         "svc-notify", 2100),
        (BASE_TIME + timedelta(days=2, hours=13),
         ["dara.osei", "eli.ramirez", "farah.nasser", "ops.rhea"],
         "svc-cleanup", 2300),
    ]
    for at, pool, worker, ticket in halves:
        scenario_approved_admin(b, count=4, offset_hours=(at - BASE_TIME).total_seconds() / 3600)
        scenario_unapproved_admin(b, at=at, subject=pool[0])
        scenario_invalid_ticket(
            b, at=at + timedelta(hours=2), subject=pool[1],
            other_subject=pool[2], approval=f"chg-{ticket + 99}",
        )
        scenario_self_approval(
            b, at=at + timedelta(hours=4), subject=pool[3],
            approval=f"chg-{ticket + 100}",
        )
        scenario_role_mismatch(
            b, at=at + timedelta(hours=8), subject=pool[0],
            approval=f"chg-{ticket + 101}",
        )
        scenario_expired_ticket(
            b, at=at + timedelta(hours=10), subject=pool[1],
            approval=f"chg-{ticket + 102}",
        )
        scenario_lateral_chain(
            b, started=at + timedelta(hours=6), worker=worker,
            chain=[(worker.split("-")[1], "vault"), ("vault", "warehouse"),
                   ("warehouse", "directory")],
        )

    scenario_benign_variety(b)
    scenario_clock_skew(b)
    scenario_hostile(b)
    scenario_early_bad_actor(b, actor="gus.lindqvist")
    return b


def build_skewed(seed: int = 20260303) -> Builder:
    """The build() log plus a source beyond the supported offset range."""
    b = build(seed)
    scenario_extreme_skew(b)
    return b


def build_scaled(events: int, seed: int = 20260304) -> Builder:
    """A large log for throughput measurement. Same shapes, many more of them."""
    b = Builder(seed)
    rng = b.rng
    per = max(1, events // (len(BENIGN_IDENTITIES) * 4))
    n = 0
    day = 0
    while n < events:
        for identity in BENIGN_IDENTITIES:
            role = rng.choice(LOW_ROLES)
            home = rng.choice(["gateway", "directory", "reports", "metrics"])
            for _ in range(per):
                if n >= events:
                    break
                at = BASE_TIME + timedelta(
                    days=day, hours=rng.randint(0, 23), minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                b.add(
                    at=at, actor=identity, source=home,
                    target=rng.choice(["directory", "reports", "metrics", "index"]),
                    action="read", role_before=role, role_after=role,
                    outcome="allow", label="benign", reason="bulk routine read",
                )
                n += 1
        day += 1
    # A service account with a real history, so the chain is judged against a
    # baseline rather than against a cold start. Without this the account's first
    # chain hop *is* its first observation, which the detector counts as baseline by
    # design (see ``LateralDetector.build_baseline``) -- with only two hops left a
    # cold-start identity is deliberately not alerted, so the test would be
    # measuring the cold-start policy instead of throughput.
    for offset in range(20):
        b.add(
            at=BASE_TIME + timedelta(hours=offset),
            actor="svc-cleanup", source="scheduler", target="cleanup",
            action="read", role_before="service-reader",
            role_after="service-reader", outcome="allow", label="benign",
            reason="routine cleanup sweep",
        )

    # One malicious chain near the end, so the large log is not purely benign.
    incident = b.new_incident("scaled-lateral")
    start = BASE_TIME + timedelta(days=day + 1)
    # Three hops, not two: an identity with no baseline at all is held to the
    # stricter cold-start bar, so a two-hop chain is by design not enough.
    for index, (source, target) in enumerate(
        [("metrics", "vault"), ("vault", "warehouse"), ("warehouse", "directory")]
    ):
        b.add(
            at=start + timedelta(minutes=index), actor="svc-cleanup", source=source,
            target=target, action="read", role_before="service-reader",
            role_after="service-reader", outcome="allow", label="malicious",
            incident=incident, reason="lateral hop in a large log",
        )
    return b


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="directory to write into")
    parser.add_argument("--seed", type=int, default=20260302)
    parser.add_argument("--events", type=int, default=0,
                        help="if >0, emit a large log of this size instead")
    parser.add_argument("--skewed", action="store_true",
                        help="include a source beyond the supported offset range")
    args = parser.parse_args(argv)

    from pathlib import Path

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.events:
        b = build_scaled(args.events, seed=args.seed)
    elif args.skewed:
        b = build_skewed(seed=args.seed)
    else:
        b = build(seed=args.seed)

    (out / "events.csv").write_text(b.events_csv(), encoding="utf-8")
    (out / "labels.csv").write_text(b.labels_csv(), encoding="utf-8")
    (out / "approvals.json").write_text(b.approvals_json(), encoding="utf-8")
    print(f"wrote {len(b.rows)} events, {len(b.labels)} labels, "
          f"{len(b.approvals)} approvals to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
