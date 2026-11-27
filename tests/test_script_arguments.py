"""A mistyped path must say so. It must not look like a failure of the system.

These tests exist because of a specific afternoon: the phase 4 evaluation was run on a
Mac with `--practice /toolkit/practice`, a path that only exists *inside* the Docker
container. Three things went wrong, and all three are the same bug — an argument error
being reported as a result:

* `phase4_eval.py` died with a raw `FileNotFoundError` traceback naming
  `events.csv`, which says nothing about the argument being wrong.
* `phase4_mutate.py` swallowed it into `metrics: {'error': ...}`, which reads as
  "the detector produced no alerts" — the opposite of the truth — and let every
  mutation appear to have succeeded.
* `phase1_acceptance.py` ran three dependent gates against a directory that could not
  work, then printed "PHASE 1 IS NOT VERIFIED. Fix the failures above", which reads
  as a security regression.

The rule these tests enforce: a bad path is an *argument* error. Exit 2, name the path,
say what to do instead, and do not emit a traceback.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MISSING = "/toolkit/practice"  # the container mount point; never exists on a host


def run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
             "HOME": "/tmp"},
    )


# ------------------------------------------------------------------ phase4_eval
@pytest.mark.parametrize("flag", ("--practice", "--synthetic"))
def test_eval_names_a_missing_corpus_directory(flag):
    done = run("phase4_eval.py", flag, MISSING)
    assert done.returncode == 2, done.stdout + done.stderr
    combined = done.stdout + done.stderr
    assert "Traceback" not in combined
    assert MISSING in combined, "the error must name the path that was wrong"
    assert "Docker" in combined, (
        "the error must say that /toolkit is a container mount point, because that is "
        "the misunderstanding that produced it"
    )


def test_eval_distinguishes_a_file_from_a_directory(tmp_path):
    stray = tmp_path / "events.csv"
    stray.write_text("event_id\n")
    done = run("phase4_eval.py", "--practice", str(stray))
    assert done.returncode == 2
    assert "not a directory" in done.stderr


def test_eval_names_the_files_missing_from_a_wrong_directory(tmp_path):
    """Pointing at the toolkit root instead of its practice/ subdirectory is the
    second most likely mistake, and a bare FileNotFoundError does not reveal it."""
    (tmp_path / "README.md").write_text("toolkit root\n")
    done = run("phase4_eval.py", "--practice", str(tmp_path))
    assert done.returncode == 2
    assert "events.csv" in done.stderr
    assert "practice" in done.stderr, "should suggest the practice/ subdirectory"


# ---------------------------------------------------------------- phase4_mutate
def test_mutate_does_not_report_a_missing_corpus_as_a_measurement(tmp_path):
    """The dangerous one: a swallowed error looked like a successful measurement."""
    missing = tmp_path / "nope.csv"
    done = run("phase4_mutate.py", "--log", str(missing), "--tests")
    assert done.returncode == 2, done.stdout + done.stderr
    assert "metrics:" not in done.stdout, (
        "a missing corpus must not be rendered as a measurement"
    )
    assert "baseline:" not in done.stdout, "no work should have been done"
    assert "Traceback" not in done.stdout + done.stderr
    assert "not found" in done.stderr


# ------------------------------------------------------------ phase1_acceptance
def test_phase1_refuses_a_toolkit_that_is_not_a_checkout():
    done = run("phase1_acceptance.py", "--toolkit", MISSING)
    assert done.returncode == 2, done.stdout + done.stderr
    combined = done.stdout + done.stderr
    assert "Traceback" not in combined
    assert "PHASE 1 IS NOT VERIFIED" not in combined, (
        "a mistyped path must not be reported as a failed security gate"
    )
    assert "validate.py" in combined, "say what was expected to be there"


def test_the_guard_only_applies_when_a_toolkit_is_given():
    """The default (no --toolkit) path must not be affected by the new guard.

    Deliberately does NOT run a full `phase1_acceptance.py`: that script runs the
    whole test suite as one of its own gates, so invoking it from a test makes the
    suite invoke itself — it hung until the 300 s timeout, which is a recursive test,
    not a slow one. `--help` exercises argument parsing and exits, so the guard's
    placement is still covered without the recursion.
    """
    done = run("phase1_acceptance.py", "--help")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "--toolkit" in done.stdout
    assert "Traceback" not in done.stdout + done.stderr
