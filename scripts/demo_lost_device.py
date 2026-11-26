#!/usr/bin/env python3
"""Phase 1 demoer: walk the lost-device scenario and show what is on disk.

Run:  python scripts/demo_lost_device.py
Everything is synthetic. State lives in a throwaway directory under /tmp.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def call(state: Path, **request) -> dict:
    env = dict(os.environ, TRACK4_STATE_DIR=str(state), PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run(
        [sys.executable, "-B", str(ROOT / "track4_service.py")],
        input=json.dumps(request).encode(),
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        timeout=60,
    )
    if done.returncode != 0:
        raise SystemExit(f"adapter failed: {done.stderr.decode()}")
    return json.loads(done.stdout)


def show(label: str, value) -> None:
    print(f"  {label:<34} {json.dumps(value) if not isinstance(value, str) else value}")


def main() -> int:
    state = Path(tempfile.mkdtemp(prefix="pqc-kv-demo-"))
    print("=" * 78)
    print("Phase 1 demo: lost-device scenario, encrypted at rest, audited")
    print(f"state directory: {state}")
    print("=" * 78)

    print("\n1. setup (keys generated at runtime, bodies sealed to disk)")
    show("setup", call(state, op="setup",
                      owners={"brief": "maya", "notes": "ravi"},
                      contents={"brief": "Synthetic board brief: Q4 numbers.",
                                "notes": "Synthetic peer note: launch checklist."},
                      disabled=[], key_material="synthetic-secret-value"))

    print("\n2. what the disk actually holds (base64 envelope, no plaintext)")
    for path in sorted((state / "pqc-kv-state" / "assets").glob("*.env")):
        blob = json.loads(path.read_text())["envelope"]
        parsed = json.loads(blob)
        print(f"  {path.name}: suite={parsed['suite']} mode={parsed['mode']} "
              f"ct={parsed['ct'][:24]}... sig={parsed['sig'][:16]}...")
    plaintext_hits = [
        str(p) for p in state.rglob("*")
        if p.is_file() and b"Q4 numbers" in p.read_bytes()
    ]
    show("plaintext files found", plaintext_hits or "none")

    print("\n3. owner reads their file (decrypt + verify signature)")
    show("maya reads brief", call(state, op="read", actor="maya", asset="brief", request_id="r01"))

    print("\n4. wrong owner is denied, with no content")
    show("maya reads notes", call(state, op="read", actor="maya", asset="notes", request_id="r02"))

    print("\n5. device lost -> revoke maya")
    call(state, op="revoke", actor="maya")
    show("revoke", "done")

    print("\n6. same owner is now denied")
    show("maya reads brief", call(state, op="read", actor="maya", asset="brief", request_id="r03"))

    print("\n7. audit explains the denial")
    show("audit r03", call(state, op="audit", request_id="r03"))

    print("\n8. second owner is unaffected")
    show("ravi reads notes", call(state, op="read", actor="ravi", asset="notes", request_id="r04"))

    print("\n9. audit chain integrity")
    from pqc_kv.store import StateStore

    ok, count = StateStore(state).verify_audit_chain()
    show("chain verifies", f"{ok} ({count} records)")

    print("\n10. file permissions")
    key_dir = state / "pqc-kv-state" / "keys"
    print(f"  keys dir:  {oct(key_dir.stat().st_mode & 0o777)}  files: "
          + ", ".join(f"{p.name}={oct(p.stat().st_mode & 0o777)}" for p in sorted(key_dir.glob('*.key'))))
    print("\nDone. Nothing above printed a private key or the key_material value.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
