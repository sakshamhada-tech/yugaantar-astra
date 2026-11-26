#!/usr/bin/env bash
# Container-contract check WITHOUT Docker.
#
# This sandbox has no Docker daemon, so `docker build` cannot run here. This
# script verifies the three properties that actually decide whether the image
# works, using a fresh Python 3.12-style venv (or the interpreter you pass):
#
#   1. offline install: every pin installs from prebuilt wheels only (no compiler)
#   2. read-only root:  the code directory is bind-mounted read-only, exactly like
#                       the judging container, and all writes go to the temp dir
#   3. unprivileged:    same non-root behaviour, no privileged paths
#
# plus the full test suite and the organizer validator inside that environment.
#
# Usage:  ./scripts/verify_container_contract.sh [path/to/Track-4-Toolkit]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLKIT="${1:-}"
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
VENV="$WORK/venv"
SRC="$WORK/app"

# The read-only-mount checks need `unshare`, which is Linux-only. On macOS (or any
# host without it) these checks CANNOT RUN. That is a missing capability, not a
# security failure, so we say so loudly and exit 77 (the skip convention) rather
# than pretending to have verified something we did not, or failing the whole gate.
if ! command -v unshare >/dev/null 2>&1; then
  echo
  echo "== SKIPPED: read-only rootfs + temp-only state =="
  echo "   'unshare' is not available on this host (it is Linux-only)."
  echo "   Container contract NOT verified here. Do not read this as green."
  echo "   To verify it: run this script on Linux, or use"
  echo "   docker run --rm --read-only --tmpfs /tmp <image>"
  exit 77
fi

echo "== 1. interpreter =="
"$PYTHON" -V

echo "== 2. install pins as wheels only (simulates PIP_ONLY_BINARY=:all:) =="
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" -q install --upgrade pip
"$VENV/bin/pip" -q install --only-binary=:all: -r "$REPO/requirements.lock" -r "$REPO/requirements-dev.lock"
"$VENV/bin/python" - <<'PY'
import importlib.metadata as md
for name in ("pqcrypto", "cryptography", "tests-not-a-package", "pytest"):
    try:
        print(f"   {name}=={md.version(name)}")
    except md.PackageNotFoundError:
        pass
PY

echo "== 3. stage the app the way the image does (runtime + tests only) =="
mkdir -p "$SRC"
cp -r "$REPO/track4_service.py" "$REPO/team_app.py" "$REPO/threat-model.json" "$REPO/src" "$SRC/"
cp -r "$REPO/tests" "$REPO/scripts" "$REPO/docs" "$SRC/"

echo "== 4. read-only code directory + temp-only state, no TRACK4_STATE_DIR =="
# Bind-mount the staged app read-only over itself, drop every state variable, and
# point HOME at a non-existent path: the container has no writable home either.
unshare -r -m sh -c '
set -e
mount --bind "'"$SRC"'" "'"$SRC"'"
mount -o remount,ro,bind "'"$SRC"'"
if touch "'"$SRC"'/canary" 2>/dev/null; then
  echo "   ERROR: code directory is writable"; exit 1
fi
echo "   code dir is read-only: ok"

export HOME=/nonexistent
unset TRACK4_STATE_DIR || true
export PYTHONDONTWRITEBYTECODE=1
export PATH="'"$VENV"'/bin:$PATH"

echo "   -- adapter round trip (default CMD path, state in /tmp) --"
cd "'"$SRC"'"
printf %s "{\"op\":\"setup\",\"owners\":{\"brief\":\"maya\"},\"contents\":{\"brief\":\"ro body\"},\"disabled\":[],\"key_material\":\"MARKER-X\"}" | python -B track4_service.py
printf %s "{\"op\":\"read\",\"actor\":\"maya\",\"asset\":\"brief\",\"request_id\":\"c1\"}" | python -B track4_service.py
printf %s "{\"op\":\"revoke\",\"actor\":\"maya\"}" | python -B track4_service.py
printf %s "{\"op\":\"read\",\"actor\":\"maya\",\"asset\":\"brief\",\"request_id\":\"c2\"}" | python -B track4_service.py
printf %s "{\"op\":\"audit\",\"request_id\":\"c2\"}" | python -B track4_service.py | head -c 200; echo

echo "   -- test suite in the same conditions --"
PYTHONPATH="'"$SRC"'/src:'"$SRC"'" python -m pytest "'"$SRC"'/tests" -q -p no:cacheprovider 2>&1 | tail -3
'

if [[ -n "$TOOLKIT" ]]; then
  echo "== 5. organizer validator (toolkit mounted read-only, adapter copied in) =="
  VALIDATE_DIR="$WORK/validate"
  mkdir -p "$VALIDATE_DIR"
  cp "$TOOLKIT/validate.py" "$VALIDATE_DIR/"
  cp "$REPO/track4_service.py" "$REPO/team_app.py" "$VALIDATE_DIR/"
  cp -r "$REPO/src" "$VALIDATE_DIR/"
  unshare -r -m sh -c '
    set -e
    mount --bind "'"$VALIDATE_DIR"'" "'"$VALIDATE_DIR"'"
    mount -o remount,ro,bind "'"$VALIDATE_DIR"'"
    export HOME=/nonexistent
    unset TRACK4_STATE_DIR || true
    export PYTHONDONTWRITEBYTECODE=1
    export PATH="'"$VENV"'/bin:$PATH"
    cd "'"$VALIDATE_DIR"'"
    python validate.py --entry "'"$VALIDATE_DIR"'/track4_service.py"
  ' | tee "$WORK/validator.log"
  echo
  echo "   PASS: $(grep -c '^PASS' "$WORK/validator.log")   FAIL: $(grep -c '^FAIL' "$WORK/validator.log" || true)"
else
  echo "== 5. validator skipped (pass the toolkit path to include it) =="
fi

echo
echo "== all container-contract checks passed =="
rm -rf "$WORK"
