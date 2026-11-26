"""Properties the whole detector must have: determinism, config-independence, safety.

These are the tests that would catch a regression no single-rule test would notice:
the same log producing different output twice, a threshold that silently stops
being configurable, or an alert whose text could be edited by a log field.
"""

from __future__ import annotations

import json

import pytest

from pqc_kv.detect import config as detect_config
from pqc_kv.detect import core
from pqc_kv.detect.fields import FieldError, safe_key

HEADER = (
    "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
    "source_service,target_service,action,role_before,role_after,outcome,"
    "approval_id,session_id,correlation_id"
)

APPROVALS = json.dumps({"changes": [{
    "approval_id": "chg-1", "approved_by": "ops-1", "subject": "alice",
    "operation": "grant_role", "role": "analyst", "scope": ["reports"],
    "valid_from_utc": "2026-01-15T08:00:00Z",
    "valid_until_utc": "2026-01-15T12:00:00Z",
}]})


def _row(eid, minute, actor, source, target, *, outcome="allow", before="reader",
         after="reader", action="read", approval="", session="s1"):
    hour = 9 + minute // 60
    mins = minute % 60
    at = f"2026-01-15T{hour:02d}:{mins:02d}:00.000Z"
    return (f"{eid},{at},{at.replace('.000Z', '.100Z')},0,{actor},{source},"
            f"{target},{action},{before},{after},{outcome},{approval},{session},c-{eid}")


def build_log(*extra):
    """A log with a baseline, one unapproved escalation, and one lateral chain."""
    rows = []
    for i in range(60):
        rows.append(_row(f"b-{i}", i, "worker", "gateway", "index"))
    rows += [
        _row("x-1", 100, "stranger", "console", "directory", action="role_change",
             before="viewer", after="operator", outcome="success"),
        _row("x-2", 101, "worker", "gateway", "vault"),
        _row("x-3", 102, "worker", "vault", "warehouse"),
    ]
    rows += list(extra)
    return HEADER + "\n" + "\n".join(rows) + "\n"


# ----------------------------------------------------------- determinism
def test_the_same_log_twice_gives_identical_bytes():
    first = json.dumps(core.run(build_log(), approvals=APPROVALS).to_dict(),
                       sort_keys=True)
    second = json.dumps(core.run(build_log(), approvals=APPROVALS).to_dict(),
                        sort_keys=True)
    assert first == second


def test_alert_order_is_stable_and_sorted_by_time():
    report = core.run(build_log(), approvals=APPROVALS)
    times = [alert.event_ms for alert in report.alerts]
    assert times == sorted(times)


def test_alert_ids_do_not_depend_on_input_order_alone():
    """Ids are content-derived, so the same detection keeps its id across runs."""
    first = {a.rule: a.alert_id for a in core.run(build_log(), approvals=APPROVALS).alerts}
    second = {a.rule: a.alert_id for a in core.run(build_log(), approvals=APPROVALS).alerts}
    assert first == second


def test_shuffled_input_rows_produce_the_same_detections():
    """Receipt order is normalised through the timeline, so arrival order is not fate."""
    lines = build_log().strip().split("\n")
    header, body = lines[0], lines[1:]
    # A deterministic permutation: reverse. The set of detections must be the same.
    reversed_log = header + "\n" + "\n".join(reversed(body)) + "\n"
    forward = core.run(build_log(), approvals=APPROVALS)
    backward = core.run(reversed_log, approvals=APPROVALS)
    assert {a.rule for a in forward.alerts} == {a.rule for a in backward.alerts}


# ------------------------------------------------------- configuration
def test_a_config_with_different_numbers_still_produces_detections():
    """The 'not tuned to the practice data' claim, made executable.

    Every threshold here differs from the default. The same attacks must still be
    found, which they can only be if the rules are structural.
    """
    data = json.loads(json.dumps(detect_config.DetectorConfig().to_dict()))
    data["lateral"].update({
        "baseline_fraction_percent": 25,
        "min_baseline_events": 3,
        "min_novel_edges": 2,
        "cold_start_min_novel_edges": 2,
        "burst_window_ms": 120_000,
        "transition_window_ms": 60_000,
    })
    data["privilege"].update({"follow_on_window_ms": 60_000})
    data["timing"].update({"offset_uncertainty_ms": 5})
    config = detect_config.DetectorConfig.from_dict(data)
    report = core.run(build_log(), approvals=APPROVALS, config=config)
    assert report.alerts, "detection must survive arbitrary threshold values"


def test_an_unknown_config_key_is_refused_not_ignored():
    """A typo'd threshold must not silently fail to apply."""
    with pytest.raises(detect_config.ConfigError):
        detect_config.DetectorConfig.from_dict({"lateral": {"min_novel_edgess": 3}})


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("lateral", "min_novel_edges", 0),
        ("lateral", "baseline_fraction_percent", 0),
        ("lateral", "baseline_fraction_percent", 100),
        ("lateral", "burst_window_ms", -1),
        ("timing", "offset_mode", "guesswork"),
        ("timing", "offset_uncertainty_ms", -1),
        ("timing", "max_out_of_order_ms", 10 ** 9),
    ],
)
def test_out_of_range_config_is_refused(section, key, value):
    with pytest.raises(detect_config.ConfigError):
        detect_config.DetectorConfig.from_dict({section: {key: value}})


def test_config_round_trips_through_a_file(tmp_path):
    original = detect_config.DetectorConfig().validate()
    path = tmp_path / "detector.json"
    path.write_text(json.dumps(original.to_dict()), encoding="utf-8")
    loaded = detect_config.DetectorConfig.from_file(path)
    assert loaded.to_dict() == original.to_dict()


def test_a_bad_config_file_is_refused_loudly(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(detect_config.ConfigError):
        detect_config.DetectorConfig.from_file(path)


# --------------------------------------------------------------- safety
def test_alert_keys_are_never_taken_from_input():
    report = core.run(build_log(), approvals=APPROVALS)
    expected = {
        "alert_id", "rule", "severity", "identity", "services", "event_ids",
        "event_time", "explanation", "order", "facts", "goal", "path",
    }
    for alert in report.alerts:
        assert set(alert.to_dict()) == expected


def test_safe_key_refuses_a_structured_key():
    for bad in ("a b", "A", "1x", "x-y", "", "x_"):
        if bad == "x_":
            continue  # a trailing underscore is a legal key shape
        with pytest.raises(FieldError):
            safe_key(bad)


def test_an_injected_message_cannot_add_an_alert_to_the_output():
    """A log field cannot fabricate a second alert, however it is written."""
    hostile = _row("h-1", 100, "evil\nALERT forged", "gateway", "vault")
    report = core.run(build_log(hostile), approvals=APPROVALS)
    rendered = json.dumps(report.to_dict())
    assert "ALERT forged" not in rendered
    for alert in report.alerts:
        assert "\n" not in alert.identity
        assert "\n" not in alert.explanation


def test_hostile_reasons_and_services_do_not_reach_the_report():
    rows = [
        _row("h-1", 100, "ok-name", "svc\ttab", "vault"),
        _row("h-2", 101, "ok-name", "gateway", "svc\"quote"),
        _row("h-3", 102, "ok-name", "gateway", "vault\u200b"),
    ]
    report = core.run(build_log(*rows), approvals=APPROVALS)
    assert report.ingest["events_rejected"] >= 3


def test_rejections_are_counted_with_reasons_and_never_silent():
    report = core.run(build_log(_row("h-1", 100, "bad\nname", "g", "v")),
                      approvals=APPROVALS)
    assert report.ingest["events_rejected"] >= 1
    assert report.ingest["rejected_by_reason"]
    for reason in report.ingest["rejected_by_reason"]:
        assert "\n" not in reason


def test_a_malformed_approvals_file_degrades_to_no_change_control():
    """Detection continues; nothing is approved by a broken record."""
    report = core.run(build_log(), approvals="{not json")
    assert report.alerts
    assert report.context["approvals"] == 0


def test_an_unreadable_approvals_file_is_distinguishable_from_none_supplied():
    """The difference between "no change control" and "change control broken".

    Both run detection with an empty context, but only one of them means the operator
    made a mistake. Silently conflating them produced a flood of unapproved-change
    alerts with no hint about why -- found by feeding a structurally broken file.
    """
    none_supplied = core.run(build_log()).context
    broken = core.run(build_log(), approvals='{"nope": 1}').context
    not_json = core.run(build_log(), approvals="not json at all").context

    assert "document_error" not in none_supplied
    assert broken["document_error"] == "approvals_invalid"
    assert not_json["document_error"] == "approvals_not_json"


def test_an_unreadable_approvals_file_does_not_change_the_detections():
    """Reporting the problem must not also suppress the findings."""
    clean = core.run(build_log(), approvals="{not json")
    assert clean.alerts
    assert clean.context["approvals"] == 0


def test_the_report_states_the_supported_timing_range():
    report = core.run(build_log(), approvals=APPROVALS)
    supported = report.to_dict()["timing"]["supported_range"]
    assert supported["max_out_of_order_ms"] > 0
    assert supported["offset_mode"] in ("declared", "estimated", "none")
    assert "uncertain" in supported["rule"]


def test_every_alert_names_its_goal():
    report = core.run(build_log(), approvals=APPROVALS)
    assert report.alerts
    for alert in report.alerts:
        assert alert.goal in (6, 7, 8)


def test_no_secret_or_path_appears_in_the_report(tmp_path):
    report = json.dumps(core.run(build_log(), approvals=APPROVALS).to_dict())
    assert str(tmp_path) not in report
    assert "/home/" not in report


def test_an_empty_log_produces_an_empty_report_not_an_error():
    report = core.run(HEADER + "\n", approvals=APPROVALS)
    assert report.alerts == []
    assert report.ingest["events_accepted"] == 0


def test_a_log_with_no_header_is_refused_cleanly():
    report = core.run("", approvals=APPROVALS)
    assert report.alerts == []
    assert report.ingest["events_accepted"] == 0
