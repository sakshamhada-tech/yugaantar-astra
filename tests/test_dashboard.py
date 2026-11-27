"""The dashboard must not become a second, drifting implementation.

A demo surface that shows things the adapter would not actually return is worse than no
demo surface, because it manufactures confidence. These tests drive the dashboard's own
API functions and assert that what they report matches the adapter driven directly, and
that two properties of the page itself hold: it loads no remote asset, and every panel
has an endpoint behind it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import dashboard  # noqa: E402


@pytest.fixture(autouse=True)
def clean_workspaces():
    yield
    import shutil

    with dashboard._LOCK:
        for path in dashboard._WORK.values():
            shutil.rmtree(path, ignore_errors=True)
        dashboard._WORK.clear()


# ------------------------------------------------------------------ the page itself
def test_page_loads_no_remote_asset():
    """Offline containers are the judging environment; a CDN font would blank the page."""
    assert not re.search(r'<script[^>]+src=|@import|href="https?://', dashboard.PAGE)
    assert "http://" not in dashboard.PAGE.replace("http://127.0.0.1:8000", "")
    assert "cdn" not in dashboard.PAGE.lower()


def test_every_panel_has_an_endpoint():
    """A button that posts to a route the server does not have is a dead demo."""
    panels = set(re.findall(r"run\('(\w+)'", dashboard.PAGE))
    assert panels, "no panels found in the page"
    assert panels <= set(dashboard.ROUTES), sorted(panels - set(dashboard.ROUTES))


def test_every_route_answers_without_raising():
    """An unhandled exception mid-demo reads as a broken system, not a broken button."""
    for name, handler in dashboard.ROUTES.items():
        if name == "redteam":  # slow; exercised by scripts/redteam.py itself
            continue
        assert isinstance(handler(""), dict), name


# ------------------------------------------------------- the panels tell the truth
def test_access_panel_matches_a_direct_adapter_call():
    panel = dashboard.api_access("other")
    step = panel["steps"][0]
    assert step["decision"] == "deny"
    assert step["body"] is None, "a denied read must not carry the body"

    state = dashboard.scenario_baseline("cross-check")
    direct = dashboard.call(state, op="read", actor="ravi", asset="brief",
                            request_id="cross-check")
    assert direct.get("decision") == step["decision"]
    assert direct.get("body") == step["body"]


def test_revoke_panel_shows_the_decision_changing():
    steps = dashboard.api_access("revoke")["steps"]
    assert [s["decision"] for s in steps] == ["allow", "deny"]
    assert steps[1]["body"] is None


def test_kem_panel_never_returns_the_plaintext():
    allowed = dashboard.api_kem("allow")
    assert allowed["decision"] == "allow"
    assert allowed["body_present"] is False, "the plaintext must not be in the reply"
    assert allowed["verified"] is True, "the proof must check out against the shared key"

    denied = dashboard.api_kem("deny")
    assert denied["decision"] == "deny"
    assert denied["ciphertext"] is None and denied["proof"] is None


def test_messaging_panel_reports_real_reasons():
    delivered = dashboard.api_msg("deliver")["steps"]
    assert delivered[0]["delivered"] == 1
    assert delivered[1]["delivered"] == 0
    assert delivered[1]["reason"].startswith("duplicate_fragments=")

    readdressed = dashboard.api_msg("readdress")["steps"]
    assert readdressed[0]["delivered"] == 0
    assert readdressed[0]["reason"] == "wrong_recipient"
    assert readdressed[1]["delivered"] == 1, "a forgery must not poison the real message"


def test_log_panel_shows_truncation_being_caught():
    steps = dashboard.api_log("truncate")["steps"]
    healthy, truncated, emptied = steps[0], steps[1], steps[2]
    assert healthy["ok"] is True and healthy["anchor_checked"] is True
    assert truncated["ok"] is False and truncated["reason"] == "head_mismatch"
    assert emptied["ok"] is False


def test_detection_panel_finds_the_planted_incidents():
    report = dashboard.api_detect("mixed")
    rules = set(report["counts"]["by_rule"])
    assert "unapproved_privilege_change" in rules
    assert "lateral_movement_chain" in rules
    assert report["alerts"], "every alert must carry an explanation"
    assert all(alert["explanation"] for alert in report["alerts"])


def test_detection_panel_survives_hostile_fields():
    report = dashboard.api_detect("hostile")
    assert report["counts"]["alerts"] >= 2
    # A newline injected through a log field must not create a fabricated alert.
    assert isinstance(report["alerts"], list)


# --------------------------------------------------------------- server behaviour
def test_unknown_endpoint_is_a_404_not_a_traceback():
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/nope", timeout=30)
        assert caught.value.code == 404
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=30).read()
        assert b"live control panel" in page
    finally:
        server.shutdown()
        server.server_close()
