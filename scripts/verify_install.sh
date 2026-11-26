#!/usr/bin/env bash
# Clean-machine check: create a throwaway venv, install the pins, run the suite,
# then run the toolkit validator against our adapter.
#
# Usage:  ./scripts/verify_install.sh [path/to/Track-4-Toolkit]
# The toolkit path is optional; that step is skipped when it is not given.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLKIT="${1:-}"
PYTHON="${PYTHON:-python3}"

echo "== interpreter =="
"$PYTHON" -V

VENV="$(mktemp -d)/venv"
echo "== fresh venv: $VENV =="
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" -q install --upgrade pip
echo "== installing requirements.lock =="
"$VENV/bin/pip" -q install -r "$REPO/requirements.lock"

echo "== import smoke test =="
"$VENV/bin/python" - <<'PY'
import importlib.metadata as md
for name in ("pqcrypto", "cryptography", "pytest"):
    print(f"  {name}=={md.version(name)}")
import sys
sys.path.insert(0, "src")
from pqc_kv.deps import BACKEND
print("  detected backend:", BACKEND.describe())
PY

echo "== test suite =="
cd "$REPO"
PYTHONPATH="$REPO/src:$REPO" "$VENV/bin/python" -m pytest tests -q

if [[ -n "$TOOLKIT" ]]; then
  echo "== toolkit validator =="
  cd "$TOOLKIT"
  "$VENV/bin/python" validate.py --entry "$REPO/track4_service.py"
else
  echo "== toolkit validator skipped (no toolkit path given) =="
fi

echo "== all checks passed =="
