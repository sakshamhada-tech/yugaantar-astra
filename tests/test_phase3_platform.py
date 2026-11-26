"""The acceptance gate must distinguish "cannot check here" from "check failed".

Regression for a real bug: on macOS `scripts/verify_container_contract.sh` failed the
whole Phase 1 gate because `unshare` is Linux-only. A missing capability is a SKIP; a
real finding is a FAIL. Conflating them trains the reader to ignore failures.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_gate():
    spec = importlib.util.spec_from_file_location(
        "phase1_acceptance", ROOT / "scripts" / "phase1_acceptance.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Fake:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_a_missing_unshare_is_a_skip_not_a_failure(monkeypatch):
    gate = load_gate()
    recorded = []
    monkeypatch.setattr(gate, "record", lambda *a: recorded.append(a))
    monkeypatch.setattr(gate, "run", lambda cmd, cwd: Fake(77, "SKIPPED: no unshare"))
    gate.gate_container_contract(None)
    assert recorded and recorded[0][0] == "SKIP"
    assert "unshare" in recorded[0][2]


def test_a_real_container_failure_is_still_a_failure(monkeypatch):
    gate = load_gate()
    recorded = []
    monkeypatch.setattr(gate, "record", lambda *a: recorded.append(a))
    monkeypatch.setattr(gate, "run",
                        lambda cmd, cwd: Fake(1, "", "ERROR: code directory is writable"))
    gate.gate_container_contract(None)
    assert recorded[0][0] == "FAIL"


def test_a_passing_check_is_a_pass(monkeypatch):
    gate = load_gate()
    recorded = []
    monkeypatch.setattr(gate, "record", lambda *a: recorded.append(a))
    monkeypatch.setattr(gate, "run",
                        lambda cmd, cwd: Fake(0, "== all container-contract checks passed"))
    gate.gate_container_contract(None)
    assert recorded[0][0] == "PASS"


def test_the_script_exits_77_and_says_so_when_unshare_is_absent():
    """Run the real script with a PATH that has no unshare."""
    import os
    import shutil
    import tempfile

    needed = ["bash", "python3", "mktemp", "cp", "mkdir", "rm", "dirname",
              "grep", "tail", "tee", "head", "cat", "chmod", "command"]
    with tempfile.TemporaryDirectory() as fakebin:
        for tool in needed:
            real = shutil.which(tool)
            if real:
                os.symlink(real, os.path.join(fakebin, tool))
        env = {"PATH": fakebin, "HOME": tempfile.gettempdir(), "PYTHON": "python3"}
        done = subprocess.run(
            ["bash", str(ROOT / "scripts" / "verify_container_contract.sh")],
            env=env, capture_output=True, text=True, timeout=120,
        )
    assert done.returncode == 77, done.stdout + done.stderr
    assert "SKIPPED" in done.stdout
    assert "NOT verified" in done.stdout, "a skip must not read like a pass"


def test_the_script_does_not_reference_unshare_unguarded():
    text = (ROOT / "scripts" / "verify_container_contract.sh").read_text()
    guard_at = text.index("command -v unshare")
    first_use = text.index("unshare -r -m")
    assert guard_at < first_use, "the availability guard must come before first use"
    assert "exit 77" in text


def test_the_gate_returns_nonzero_only_for_real_failures():
    """Phase 1 module must not treat SKIP as a failure in its exit status."""
    source = (ROOT / "scripts" / "phase1_acceptance.py").read_text()
    # The summary line distinguishes the three outcomes; SKIPs are listed separately.
    assert re.search(r"skipped \(not verified here, do not read as green\)", source)
