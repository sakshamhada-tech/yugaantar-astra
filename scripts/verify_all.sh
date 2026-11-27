#!/usr/bin/env bash
# Run everything CI runs, in the same order, with the same paths.
#
#   ./scripts/verify_all.sh                 # clones the toolkit to a temp dir
#   ./scripts/verify_all.sh ../Track-4-Toolkit   # uses your checkout
#
# Why this exists: the CI `tests` job is fifteen steps, and reproducing it by hand means
# copying fifteen commands out of a YAML file. Every hand-copy is a chance to lose
# `PYTHONPATH=src:.` (the single most common failure) or to type `/toolkit`, which is a
# Docker mount point that does not exist on a laptop. This script sets the environment
# once and runs the steps in order.
#
# It keeps going after a failure and prints a summary at the end, because the useful
# question is "what is broken" rather than "what broke first". Exit code is non-zero if
# anything failed -- so it is still safe to chain with `&&`.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3.12 || command -v python3)"
fi
TOOLKIT_ARG="${1:-}"
WORK="$(mktemp -d)"
PASSED=0
FAILED=0
FAILED_NAMES=""

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if [ -z "$TOOLKIT_ARG" ]; then
  echo "== cloning the toolkit (not vendored in this repo) =="
  if git clone --depth 1 -q \
      https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git "$WORK/toolkit"; then
    TOOLKIT="$WORK/toolkit"
  else
    echo "   could not clone; the two toolkit steps will be skipped"
    TOOLKIT=""
  fi
else
  TOOLKIT="$(cd "$TOOLKIT_ARG" && pwd)"
fi

if [ -n "$TOOLKIT" ] && [ ! -f "$TOOLKIT/validate.py" ]; then
  echo "error: $TOOLKIT has no validate.py -- pass the toolkit checkout root" >&2
  exit 2
fi

# Set once, inherited by every step. Losing this is the most common way a step fails.
export PYTHONPATH="$REPO/src:$REPO"
cd "$REPO" || exit 2

step() {
  local name="$1"; shift
  printf '\n\033[1m== %s ==\033[0m\n' "$name"
  if "$@"; then
    PASSED=$((PASSED + 1))
    printf '\033[32m   PASS\033[0m  %s\n' "$name"
  else
    FAILED=$((FAILED + 1))
    FAILED_NAMES="$FAILED_NAMES\n  - $name"
    printf '\033[31m   FAIL\033[0m  %s\n' "$name"
  fi
}

echo "repo:       $REPO"
echo "python:     $($PY -V 2>&1)"
echo "toolkit:    ${TOOLKIT:-<none>}"
echo "PYTHONPATH: $PYTHONPATH"

step "interpreter / dependency smoke test" \
  "$PY" -c "import pytest, pqcrypto, cryptography; print('deps ok')"

step "test suite" "$PY" -m pytest tests -q
step "lost-device walkthrough" "$PY" scripts/demo_lost_device.py
step "phase 2 acceptance (goals 9-12)" "$PY" scripts/phase2_acceptance.py
step "phase 3 acceptance (goals 1-5)" "$PY" scripts/phase3_acceptance.py
step "phase 3 crash-recovery kills" "$PY" -m pytest tests/test_phase3_recovery.py -q
step "red team gate (38 attacks)" "$PY" scripts/redteam.py
step "phase 6 acceptance" "$PY" scripts/phase6_acceptance.py
step "phase 5 acceptance (goals 9-12, adversarial)" "$PY" scripts/phase5_acceptance.py
step "phase 4 acceptance (goals 6-8)" "$PY" scripts/phase4_acceptance.py

step "phase 4 synthetic corpus" "$PY" scripts/phase4_synth.py --out "$WORK/synth"

if [ -n "$TOOLKIT" ]; then
  step "phase 4 detector evaluation (practice + synthetic)" \
    "$PY" scripts/phase4_eval.py --practice "$TOOLKIT/practice" --synthetic "$WORK/synth"
else
  echo; echo "== phase 4 detector evaluation: SKIPPED (no toolkit) =="
fi

step "phase 4 mutation check (every rule must be caught)" \
  "$PY" scripts/phase4_mutate.py --log "$WORK/synth/events.csv" \
       --approvals "$WORK/synth/approvals.json" --tests

step "phase 1 acceptance" \
  bash -c "if [ -n '$TOOLKIT' ]; then '$PY' scripts/phase1_acceptance.py --toolkit '$TOOLKIT'; else '$PY' scripts/phase1_acceptance.py; fi"

if [ -n "$TOOLKIT" ]; then
  step "organizer validator (22 checks)" bash -c "cd '$TOOLKIT' && '$PY' validate.py --entry '$REPO/track4_service.py'"
else
  echo; echo "== organizer validator: SKIPPED (no toolkit) =="
fi

step "starter is byte-identical" bash -c "
  if [ -n '$TOOLKIT' ]; then
    cmp '$REPO/track4_service.py' '$TOOLKIT/starters/python/track4_service.py'
  else
    echo 'no toolkit to compare against; skipping'
  fi"

echo
echo "======================================================================"
printf 'steps passed: %s   failed: %s\n' "$PASSED" "$FAILED"
if [ "$FAILED" -ne 0 ]; then
  printf 'failed:%b\n' "$FAILED_NAMES"
  echo
  echo "NOT VERIFIED. Address the failures above, then re-run."
  exit 1
fi
echo "ALL STEPS PASSED -- this matches the CI 'tests' job step for step."
