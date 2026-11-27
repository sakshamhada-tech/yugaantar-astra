#!/usr/bin/env python3
"""Mutation testing: does removing a rule actually cost us detection?

A rule that can be deleted without any test or metric noticing is decoration. This
script deletes each rule in turn -- by monkeypatching the module in a subprocess, so
the source files are never edited -- and reports exactly which tests fail and how
the metrics move. Every claim in ``docs/DETECTION.md`` about a rule's value comes
from this output, not from intuition.

Why monkeypatching rather than editing files: editing and restoring source is one
interrupted run away from a corrupted tree. Patching at import time cannot leave
anything behind.

Each mutation is described by what it *removes*, not by the code it touches.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

#: name -> (description, python snippet that neuters one behaviour, config patch)
MUTATIONS = {
    "no_approval_check": (
        "Treat every privilege change as approved (skip change-control matching).",
        "_c = pqc_kv.detect.context\n"
        "pqc_kv.detect.context.check_change = lambda *a, **k: _c.Match(\n"
        "    status='approved', approval_id='', failed=(), matched=(),\n"
        "    explanation='mutated: everything approved')",
        {},
    ),
    "no_role_check": (
        "Match approvals on subject and time only (ignore the granted role).",
        "_c = pqc_kv.detect.context\n"
        "_orig = _c._check_one\n"
        "def _check_one(event, approval, timeline, config):\n"
        "    m = _orig(event, approval, timeline, config)\n"
        "    if 'role' in m.failed:\n"
        "        m.failed = tuple(f for f in m.failed if f != 'role')\n"
        "        m.matched = tuple(m.matched) + ('role',)\n"
        "        if not m.failed:\n"
        "            m.status = 'approved'\n"
        "    return m\n"
        "pqc_kv.detect.context._check_one = _check_one",
        {},
    ),
    "no_window_check": (
        "Ignore the approval validity window (any ticket covers any time).",
        "pqc_kv.detect.context._window = "
        "lambda *a, **k: ('inside', 'confirmed')",
        {},
    ),
    "no_novel_edge": (
        "Never report a first-seen service edge.",
        "pqc_kv.detect.lateral.LateralDetector._lone_edge_alert = "
        "lambda self, *a, **k: None\n"
        "pqc_kv.detect.lateral.LateralDetector._sensitive_alert = "
        "lambda self, *a, **k: None",
        {},
    ),
    "no_chain_rule": (
        "Never report a lateral movement chain.",
        "_L = pqc_kv.detect.lateral.LateralDetector\n"
        "_orig_judge = _L._judge_burst\n"
        "def _judge(self, burst):\n"
        "    alert = _orig_judge(self, burst)\n"
        "    return alert if alert and alert.rule == 'novel_service_edge' else None\n"
        "pqc_kv.detect.lateral.LateralDetector._judge_burst = _judge",
        {},
    ),
    "no_clock_tolerance": (
        "Claim every order regardless of clock uncertainty.",
        "pqc_kv.detect.timing.Timeline.compare = "
        "lambda self, a, b: 'before' if self.corrected.get(a, 0) <= "
        "self.corrected.get(b, 0) else 'after'",
        {},
    ),
    "no_cold_start_policy": (
        "Treat every identity as established, however little is known about it.",
        "_L = pqc_kv.detect.lateral.LateralDetector\n"
        "_orig = _L._judge_burst\n"
        "def _judge(self, burst):\n"
        "    graph = self.graphs.get(burst.identity)\n"
        "    self.config = _replace(self.config, lateral=_replace(\n"
        "        self.config.lateral, min_baseline_events=0))\n"
        "    return _orig(self, burst)\n"
        "_L._judge_burst = _judge\n"
        "from dataclasses import replace as _replace",
        {},
    ),
    "no_follow_on": (
        "Never tie post-change access back to the change.",
        "pqc_kv.detect.privilege.PrivilegeDetector._check_follow_on = "
        "lambda self, event, alerts: None",
        {},
    ),
    "no_self_approval_check": (
        "Accept an approval signed by its own subject.",
        "_c = pqc_kv.detect.context\n"
        "_orig = _c._check_one\n"
        "def _check_one(event, approval, timeline, config):\n"
        "    m = _orig(event, approval, timeline, config)\n"
        "    if 'self_approved' in m.failed:\n"
        "        m.failed = tuple(f for f in m.failed if f != 'self_approved')\n"
        "        if not m.failed:\n"
        "            m.status = 'approved'\n"
        "    return m\n"
        "pqc_kv.detect.context._check_one = _check_one",
        {},
    ),
    "no_ingest_validation": (
        "Accept any field value, however hostile (skip the identifier policy).",
        "pqc_kv.detect.fields.validate_ident = "
        "lambda value, **k: value if isinstance(value, str) else ''\n"
        "pqc_kv.detect.ingest.F.validate_ident = pqc_kv.detect.fields.validate_ident",
        {},
    ),
    "no_approvals_document_error": (
        "Swallow an unreadable approvals document, as the first version did.",
        "pqc_kv.detect.core._load_context = "
        "lambda approvals: pqc_kv.detect.context.Context()",
        {},
    ),
}

HARNESS = r'''
import json, sys
sys.path.insert(0, {root!r})
sys.path.insert(0, {root!r} + "/src")
# Import the package first so the mutations below apply to the loaded modules.
import pqc_kv.detect as _d
import pqc_kv.detect.context, pqc_kv.detect.lateral, pqc_kv.detect.config
import pqc_kv.detect.timing, pqc_kv.detect.privilege, pqc_kv.detect.fields
import pqc_kv.detect.ingest, pqc_kv.detect.core
{mutation}
# Reset anything cached from the pre-mutation defaults.
from pqc_kv.detect import core
from pathlib import Path
log = Path({log!r}).read_text()
appr = Path({appr!r}).read_text() if {appr!r} else None
report = core.run(log, approvals=appr)
print(json.dumps({{
    "alerts": len(report.alerts),
    "by_rule": report.counts["by_rule"],
}}))
'''


def run_metrics(mutation: str, snippet: str, log: Path, approvals: Path) -> dict:
    code = HARNESS.format(root=str(ROOT), mutation=snippet, log=str(log),
                          appr=str(approvals) if approvals.exists() else "")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                            text=True, timeout=300)
    if result.returncode != 0:
        return {"error": result.stderr.strip().splitlines()[-1][:200] if result.stderr else "failed"}
    return json.loads(result.stdout)


def run_tests(mutation: str, snippet: str) -> dict:
    """Run the Phase 4 suite under the mutation, in-process via a conftest hack.

    Uses ``-p`` to inject the patch before tests import the package, so the mutation
    applies to every test in the session.
    """
    plugin = ROOT / "scripts" / f"_mutant_{mutation}.py"
    plugin.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        f"sys.path.insert(0, {str(ROOT / 'src')!r})\n"
        "import pqc_kv.detect\n"
        "import pqc_kv.detect.context, pqc_kv.detect.lateral, pqc_kv.detect.config\n"
        "import pqc_kv.detect.timing, pqc_kv.detect.privilege, pqc_kv.detect.fields\n"
        "import pqc_kv.detect.ingest, pqc_kv.detect.core\n"
        f"{snippet}\n",
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest"] + _test_targets() + ["-q", "--no-header",
             "-p", f"_mutant_{mutation}", "--rootdir", str(ROOT),
             "--tb=no", "-rf"],
            capture_output=True, text=True, timeout=1800,
            cwd=str(ROOT),
            env={**_env(), "PYTHONPATH": f"{ROOT / 'scripts'}:{ROOT / 'src'}:{ROOT}"},
        )
    finally:
        plugin.unlink(missing_ok=True)
    tail = [line for line in result.stdout.splitlines() if line.strip()]
    failed = [line for line in tail if line.startswith("FAILED")]
    summary = tail[-1] if tail else "no output"
    return {"summary": summary, "failed_count": len(failed),
            "failed": [f.split("::")[-1][:90] for f in failed[:6]]}


def _test_targets() -> list:
    """Phase 4 tests by default: they are what the mutations must break.

    ``--all-tests`` widens it to the whole suite. The default keeps the run to a
    couple of minutes; the narrowed set is the meaningful one, because a Phase 1
    test failing under a Phase 4 mutation would mean the mutation was too broad.
    """
    if "--all-tests" in sys.argv:
        return ["tests/"]
    return [path for path in (
        "tests/test_phase4_ingest.py", "tests/test_phase4_timing.py",
        "tests/test_phase4_rules.py", "tests/test_phase4_lateral.py",
        "tests/test_phase4_properties.py",
    ) if (ROOT / path).exists()]


def _env() -> dict:
    import os

    return dict(os.environ)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--approvals", type=Path, default=Path(""))
    parser.add_argument("--tests", action="store_true",
                        help="also run the pytest suite under each mutation")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    # A missing corpus is an argument error, not a measurement. Without this check the
    # error is swallowed by the mutation harness and reported as
    # `metrics: {'error': ...}`, which reads as "the detector found nothing" -- the
    # opposite of the truth -- and lets every mutation appear to succeed.
    missing = [str(p) for p in (args.log, args.approvals) if str(p) and not p.exists()]
    if missing:
        print(f"error: corpus file(s) not found: {missing}", file=sys.stderr)
        print("    /toolkit is a Docker mount point, not a host path. Natively:\n"
              "      git clone --depth 1 "
              "https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git "
              "../Track-4-Toolkit\n"
              "      python scripts/phase4_mutate.py "
              "--log ../Track-4-Toolkit/practice/events.csv \\\n"
              "        --approvals ../Track-4-Toolkit/practice/approvals.json --tests",
              file=sys.stderr)
        return 2

    baseline = run_metrics("baseline", "pass", args.log, args.approvals)
    print(f"baseline: {baseline}")
    output = {"baseline": baseline, "mutations": {}}

    for name, (description, snippet, _) in MUTATIONS.items():
        metrics = run_metrics(name, snippet, args.log, args.approvals)
        entry = {"description": description, "metrics": metrics}
        if args.tests:
            entry["tests"] = run_tests(name, snippet)
        output["mutations"][name] = entry
        print(f"\n{name}: {description}")
        print(f"  metrics: {metrics}")
        if args.tests:
            tests = entry["tests"]
            print(f"  tests: {tests['summary'] if 'summary' in tests else tests['summary']}"
                  f"  ({tests['failed_count']} failing)")
            for name_failed in tests["failed"]:
                print(f"    - {name_failed}")

    if args.json:
        args.json.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
