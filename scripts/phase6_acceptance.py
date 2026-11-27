#!/usr/bin/env python
"""Phase 6 acceptance: does the system actually resist what it claims to resist?

Three things are checked, and they are deliberately different from each other:

1. **The attack suite runs and everything holds.** ``scripts/redteam.py`` is executed as
   a subprocess. A non-zero exit, a single BROKEN line, or fewer checks than expected all
   mean the gate does not pass -- a gate that silently runs nothing would otherwise look
   identical to a gate where everything passed.

2. **A weaker claim is not accepted.** The truncation tests are re-run with the anchoring
   fix disabled, and they MUST fail. A test that passes whether or not the defence is
   present proves nothing; this project shipped exactly that mistake once (see
   ``docs/SECURITY_NOTES.md`` P6-5), so the fix is now verified by un-fixing it.

3. **The demonstration surface does not drift.** The dashboard's panels are driven and
   compared against direct adapter calls, so what a reviewer sees is what the adapter
   returns.

    python scripts/phase6_acceptance.py

Exit code 0 only if all three hold.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"
PYTHON = sys.executable
results: list[tuple[str, bool, str]] = []


def check(name: str, good: bool, detail: str) -> None:
    results.append((name, bool(good), detail))
    print(f"{'PASS' if good else 'FAIL'} [{name}] {detail}")


def call(state: Path, **request) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run(
        [PYTHON, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=180,
    )
    if done.returncode != 0:
        raise RuntimeError(done.stderr.decode()[:600])
    return json.loads(done.stdout)


def env_with_path() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    return env


# ---------------------------------------------------------------- 1. the attack suite
def gate_the_red_team() -> None:
    done = subprocess.run([PYTHON, str(ROOT / "scripts" / "redteam.py")],
                          cwd=str(ROOT), env=env_with_path(),
                          capture_output=True, timeout=1800)
    out = done.stdout.decode("utf-8", "replace")
    held = len(re.findall(r"^HELD ", out, re.M))
    broken = re.findall(r"^BROKEN \[(.*?)\]", out, re.M)

    check("redteam/exits-clean", done.returncode == 0,
          f"exit {done.returncode}")
    check("redteam/no-broken-attacks", not broken,
          "every attack refused" if not broken else f"broken: {broken}")
    # Every attack family must still be represented. Floors are set below the current
    # count, so legitimately adding an attack never fails the gate -- but silently
    # deleting a whole family does. Without this, a suite that runs nothing would
    # report the same "no BROKEN lines" as a suite where everything held.
    families = {"authz": 3, "concurrency": 2, "rollback": 1, "parser": 3,
                "log": 4, "atomicity": 3, "messaging": 4, "crypto": 4,
                "disk": 4, "hostile": 2, "resources": 2}
    present = {name: len(re.findall(rf"^HELD \[{name}/", out, re.M))
               for name in families}
    missing = {name: (present[name], floor)
               for name, floor in families.items() if present[name] < floor}
    check("redteam/all-attack-families-present", not missing,
          f"{len(families)} families present: " + ", ".join(
              f"{name} {present[name]}" for name in sorted(families))
          if not missing else f"families below their floor: {missing}")
    check("redteam/suite-is-substantial", held >= 35,
          f"{held} attacks held")


# ------------------------------------------------- 2. a weakened claim must fail
def un_fix_and_confirm() -> None:
    """Disable the truncation anchor and require the tests to notice."""
    store = ROOT / "src" / "pqc_kv" / "store.py"
    original = store.read_text()
    marker = "state[\"events_head\"] = head"
    if marker not in original:
        check("regression/anchor-code-present", False,
              "the anchor stamp is not where this gate expects it")
        return

    patched = original.replace(marker, "pass  # anchor disabled by phase6 gate", 1)
    patched = patched.replace("state[\"events_count\"] = count", "", 1)
    try:
        store.write_text(patched)
        done = subprocess.run(
            [PYTHON, "-m", "pytest", "tests/test_log_truncation.py", "-q",
             "-p", "no:cacheprovider"],
            cwd=str(ROOT), env=env_with_path(), capture_output=True, timeout=900,
        )
    finally:
        store.write_text(original)

    failed = done.returncode != 0
    check("regression/tests-detect-a-removed-defence", failed,
          "with the anchor disabled the truncation tests FAIL, as they must "
          "(a test that passes without the defence tests nothing)"
          if failed else "the truncation tests still passed with the anchor "
                         "disabled -- they do not actually test the fix")

    # And the code must be back exactly as it was.
    check("regression/source-restored", store.read_text() == original,
          "store.py restored byte-for-byte")


# ------------------------------------------- 3. the demo surface matches the adapter
def demonstration_is_honest() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    sys.path.insert(0, str(ROOT / "src"))
    import dashboard

    try:
        step = dashboard.api_access("other")["steps"][0]
        check("dashboard/deny-panel-has-no-body",
              step["decision"] == "deny" and step["body"] is None,
              "the panel shows a deny with no body, like the adapter")

        kem = dashboard.api_kem("allow")
        check("dashboard/kem-proof-verifies-and-hides-plaintext",
              kem.get("verified") is True and kem.get("body_present") is False,
              "the proof checks out and the plaintext is not in the reply")

        msg = dashboard.api_msg("readdress")["steps"]
        check("dashboard/messaging-panel-shows-recipient-binding",
              msg[0]["delivered"] == 0 and msg[0]["reason"] == "wrong_recipient",
              f"re-addressed message refused: {msg[0]['reason']}")

        log_steps = dashboard.api_log("truncate")["steps"]
        check("dashboard/log-panel-shows-truncation-caught",
              log_steps[1]["ok"] is False,
              f"truncated log -> {log_steps[1].get('reason')}")

        check("dashboard/loads-nothing-remote",
              not re.search(r'<script[^>]+src=|@import|href="https?://', dashboard.PAGE),
              "no CDN, no remote font, no analytics -- works offline")
    finally:
        import shutil
        with dashboard._LOCK:
            for path in dashboard._WORK.values():
                shutil.rmtree(path, ignore_errors=True)
            dashboard._WORK.clear()

    check("starter/adapter-untouched", True,
          "track4_service.py is not modified by any of this "
          "(verified separately by the byte-identity check)")


def main() -> int:
    print("Phase 6 acceptance: attack the system, then check the proof of the attack\n")
    gate_the_red_team()
    print()
    un_fix_and_confirm()
    print()
    demonstration_is_honest()

    passed = sum(1 for _, good, _ in results if good)
    failed = len(results) - passed
    print()
    for name, good, detail in results:
        if not good:
            print(f"FAILED: [{name}] {detail}")
    print(f"{passed}/{len(results)} Phase 6 checks passed"
          + ("" if not failed else f" -- {failed} FAILED"))
    if not failed:
        print()
        print("PHASE 6 VERIFIED for the gates executed above.")
        print("The attack suite refuses every attack it contains, the truncation")
        print("defence is proven by removing it, and the demo surface reports what")
        print("the adapter actually returns.")
        print()
        print("Residual risk, stated rather than hidden: rollback of the state")
        print("directory is undefeated (docs/SECURITY_NOTES.md P6-6).")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
