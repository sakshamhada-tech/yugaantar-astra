#!/usr/bin/env python3
"""Phase 1 acceptance gate.

Answers one question: "is Phase 1 actually done?" It does not describe the work,
it *runs* the checks and prints a PASS/FAIL table. Every row maps to a command
you can also run by hand.

Usage:
    python scripts/phase1_acceptance.py                    # gates 1-5
    python scripts/phase1_acceptance.py --toolkit /path    # + toolkit gates

Exit code 0 only if every executed gate passes. Skipped gates print SKIP and do
not fail the run, but they are listed so nothing looks greener than it is.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS: list[tuple[str, str, str]] = []  # (status, gate, detail)


def record(status: str, gate: str, detail: str) -> None:
    RESULTS.append((status, gate, detail))
    icon = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[status]
    print(f"  [{icon}] {gate}: {detail}", flush=True)


def run(cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=merged, timeout=1800)


# ---------------------------------------------------------------- the 12 gates
def gate_environment() -> None:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    record("PASS" if sys.version_info[:2] == (3, 12) else "SKIP",
           "interpreter", f"Python {version}"
           + ("" if sys.version_info[:2] == (3, 12) else " (judging runtime is 3.12)"))

    sys.path.insert(0, str(ROOT / "src"))
    try:
        from pqc_kv.deps import BACKEND
    except Exception as exc:  # pragma: no cover
        record("FAIL", "import pqc_kv", f"{type(exc).__name__}")
        return
    info = BACKEND.describe()
    ok = info["aead"] and info["pqcrypto"] == "0.4.0"
    record("PASS" if ok else "FAIL", "crypto backends",
           f"pqcrypto={info['pqcrypto']} symmetric={info['symmetric']} aead={info['aead']}")


def gate_tests() -> None:
    env = {"PYTHONPATH": f"{ROOT / 'src'}:{ROOT}", "PYTHONDONTWRITEBYTECODE": "1"}
    done = run([sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], ROOT, env)
    tail = [l for l in done.stdout.strip().splitlines() if l.strip()][-1:] or ["no output"]
    record("PASS" if done.returncode == 0 else "FAIL", "test suite", tail[0])


def gate_adapter_matches_starter(toolkit: Path | None) -> None:
    """The brief says copy the starter; drifting from it is a silent mistake."""
    starter = (toolkit / "starters/python/track4_service.py") if toolkit else None
    ours = ROOT / "track4_service.py"
    if not starter or not starter.exists():
        record("SKIP", "adapter is the untouched starter", "toolkit not supplied")
        return
    same = hashlib.sha256(starter.read_bytes()).hexdigest() == hashlib.sha256(ours.read_bytes()).hexdigest()
    record("PASS" if same else "FAIL", "adapter is the untouched starter",
           "byte-identical" if same else "DIFFERS from the toolkit starter")


def gate_one_adapter() -> None:
    found = sorted(p.name for p in ROOT.glob("track4_service.*"))
    ok = len(found) == 1
    record("PASS" if ok else "FAIL", "exactly one adapter at root", ", ".join(found) or "none")


def gate_validator(toolkit: Path | None) -> None:
    if not toolkit:
        record("SKIP", "organizer validator", "toolkit not supplied (--toolkit PATH)")
        return
    done = run([sys.executable, "validate.py", "--entry", str(ROOT / "track4_service.py")], toolkit)
    passes = done.stdout.count("\nPASS") + done.stdout.startswith("PASS")
    fails = done.stdout.count("\nFAIL") + done.stdout.startswith("FAIL")
    ok = done.returncode == 0 and fails == 0
    record("PASS" if ok else "FAIL", "organizer validator", f"{passes} PASS / {fails} FAIL, exit {done.returncode}")


def gate_container_contract(toolkit: Path | None) -> None:
    script = ROOT / "scripts/verify_container_contract.sh"
    if not script.exists():
        record("SKIP", "container contract", "script missing")
        return
    cmd = [str(script)] + ([str(toolkit)] if toolkit else [])
    done = run(cmd, ROOT)
    ok = done.returncode == 0 and "all container-contract checks passed" in done.stdout
    record("PASS" if ok else "FAIL", "read-only rootfs + temp-only state",
           "code dir ro, state in temp, suite green" if ok else done.stderr.strip()[-120:] or "failed")


def gate_no_plaintext_at_rest() -> None:
    """Independent of the tests: seal a body, then grep the state dir for it."""
    sys.path.insert(0, str(ROOT / "src"))
    import tempfile

    from pqc_kv.store import StateStore

    with tempfile.TemporaryDirectory() as tmp:
        store = StateStore(Path(tmp))
        marker = "PLAINTEXT-PROBE-" + os.urandom(6).hex()
        store.setup({"owners": {"a": "u"}, "contents": {"a": marker}, "disabled": [],
                     "key_material": "KM-" + marker})
        hits = [str(p.relative_to(tmp)) for p in Path(tmp).rglob("*")
                if p.is_file() and marker.encode() in p.read_bytes()]
        record("PASS" if not hits else "FAIL", "no plaintext at rest",
               "case body + key_material absent from disk" if not hits else f"found in {hits}")


def gate_no_secrets_committed() -> None:
    done = run(["git", "ls-files"], ROOT)
    tracked = done.stdout.split()
    bad = [f for f in tracked if f.endswith((".key", ".pem", ".env")) or "/state/" in f or f.startswith("state/")]
    record("PASS" if not bad else "FAIL", "no keys/secrets in git",
           f"{len(tracked)} tracked files, none are keys/state" if not bad else f"tracked secrets: {bad}")


def gate_no_toolkit_vendored() -> None:
    marks = ["validate.py", "quickstart.py", "len(practice)"]  # last one never matches; placeholder
    found = [m for m in ("validate.py", "quickstart.py") if any(ROOT.rglob(m))]
    found += [str(p.relative_to(ROOT)) for p in ROOT.glob("starters")] + \
             [str(p.relative_to(ROOT)) for p in ROOT.glob("practice")]
    record("PASS" if not found else "FAIL", "organizer toolkit not vendored",
           "absent from the repo" if not found else f"found {found}")


def gate_tamper_detection() -> None:
    """Direct check that a one-bit change anywhere is rejected, for the record."""
    sys.path.insert(0, str(ROOT / "src"))
    from pqc_kv import dsa, envelope, kem

    kp, sp = kem.generate_keypair(), dsa.generate_keypair()
    env = envelope.seal(plaintext=b"probe", recipient_public=kp, sender_signing_secret=sp.secret_key,
                        recipient="r", envelope_id="e", context="c")
    fields = ["nonce", "ciphertext", "tag", "kem_ciphertext", "signature"]
    accepted = []
    for field in fields:
        data = bytearray(getattr(env, field))
        data[0] ^= 1
        tampered = envelope.Envelope(**{**env.__dict__, field: bytes(data)})
        try:
            envelope.open_envelope(tampered, recipient_secret=kp, sender_signing_public=sp.public_key)
            accepted.append(field)
        except envelope.EnvelopeError:
            pass
    record("PASS" if not accepted else "FAIL", "tamper detection",
           f"{len(fields)}/{len(fields)} single-bit flips rejected" if not accepted else f"accepted: {accepted}")


def gate_hybrid_needs_both() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from pqc_kv import hybrid

    transcript = hybrid.build_transcript(b"x" * 32, b"c" * 1088)
    keys = {
        hybrid.derive_key(b"a" * 32, b"b" * 32, transcript),
        hybrid.derive_key(b"A" * 32, b"b" * 32, transcript),
        hybrid.derive_key(b"a" * 32, b"B" * 32, transcript),
    }
    record("PASS" if len(keys) == 3 else "FAIL", "hybrid key needs both secrets",
           "x25519 or mlkem change each alter the key" if len(keys) == 3 else "components collide")


def gate_dockerfile_sources() -> None:
    dockerfile = ROOT / "Dockerfile"
    if not dockerfile.exists():
        record("SKIP", "Dockerfile COPY sources", "no Dockerfile")
        return
    missing, checked = [], 0
    for line in dockerfile.read_text().splitlines():
        line = line.strip()
        if not line.upper().startswith("COPY ") or line.startswith("#"):
            continue
        parts = line.split()[1:]
        for src in parts[:-1]:
            checked += 1
            if not (ROOT / src).exists():
                missing.append(src)
    record("PASS" if not missing else "FAIL", "Dockerfile COPY sources",
           f"{checked} sources present" if not missing else f"missing {missing}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolkit", type=Path, default=None,
                        help="path to the Track-4-Toolkit checkout (enables 3 extra gates)")
    args = parser.parse_args()
    toolkit = args.toolkit.resolve() if args.toolkit else None
    if toolkit and not (toolkit / "validate.py").exists():
        print(f"warning: {toolkit} does not look like the toolkit; validator gate will fail")

    print("=" * 74)
    print("Phase 1 acceptance gate — each line is a check that actually ran")
    print("=" * 74)
    for gate in (gate_environment, gate_one_adapter, gate_no_secrets_committed,
                 gate_no_toolkit_vendored, gate_dockerfile_sources, gate_tamper_detection,
                 gate_hybrid_needs_both, gate_no_plaintext_at_rest, gate_tests):
        try:
            gate()
        except Exception as exc:  # a broken gate is a failure, not a crash
            record("FAIL", getattr(gate, "__name__", "gate"), f"{type(exc).__name__}: {exc}")

    for gate in (lambda: gate_adapter_matches_starter(toolkit),
                 lambda: gate_validator(toolkit),
                 lambda: gate_container_contract(toolkit)):
        try:
            gate()
        except Exception as exc:
            record("FAIL", "gate", f"{type(exc).__name__}: {exc}")

    failed = [r for r in RESULTS if r[0] == "FAIL"]
    skipped = [r for r in RESULTS if r[0] == "SKIP"]
    passed = [r for r in RESULTS if r[0] == "PASS"]
    print("-" * 74)
    print(f"{len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped")
    if skipped:
        print("skipped (not verified here, do not read as green):")
        for _, gate, detail in skipped:
            print(f"  - {gate}: {detail}")
    if failed:
        print("FAILED:")
        for _, gate, detail in failed:
            print(f"  - {gate}: {detail}")
        print("\nPHASE 1 IS NOT VERIFIED. Fix the failures above.")
        return 1
    print("\nPHASE 1 VERIFIED for the gates executed above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
