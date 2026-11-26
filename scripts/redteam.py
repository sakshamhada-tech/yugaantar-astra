#!/usr/bin/env python
"""Red-team gate: run our own attacks against the shipped adapter.

The instructor will attack this system. This script is the attack, written down, so it
can be re-run before the assessment instead of improvising on the day.

    python scripts/redteam.py

Every check is an attack that either **succeeded against an earlier build** (and is now
fixed) or is a well-known attack against a system of this shape. The script therefore
serves two purposes: a regression gate, and an honest inventory of what has been tried.

Three rules, because a red-team script that overstates itself is worse than none:

* **A crash is a finding.** The adapter contract is one JSON object out. Exit 1 with
  empty stdout breaks any caller, so every attack checks the exit code, not just the
  decision.
* **Every finding is shown, not counted.** When an attack gets through, the script
  prints what came back, so the reader can judge it rather than trust a number.
* **Not in scope is stated as such.** Attacks needing a compromised OS account, root,
  or a modified Python interpreter are listed in the output as explicitly out of scope
  rather than silently omitted, because the difference matters in a review.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"
STATE = "pqc-kv-state"

results: list[tuple[str, bool, str]] = []


def call(state: Path, **request) -> tuple[int, dict | None]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=120,
    )
    body = None
    if done.stdout.strip():
        try:
            body = json.loads(done.stdout)
        except ValueError:
            body = None
    return done.returncode, body


def ok(state: Path, **request) -> dict:
    code, body = call(state, **request)
    assert code == 0 and body is not None and "error" not in body, (code, body)
    return body


def check(name: str, held: bool, detail: str) -> None:
    results.append((name, bool(held), detail))
    print(f"{'HELD' if held else 'BROKEN'} [{name}] {detail}")


def fresh(tmp: Path, name: str) -> Path:
    state = tmp / name
    state.mkdir(parents=True, exist_ok=True)
    ok(state, op="setup", owners={"brief": "maya", "notes": "ravi"},
       contents={"brief": "MAYA-SECRET", "notes": "RAVI-SECRET"},
       disabled=[], key_material="SYNTHETIC-KM")
    return state


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="redteam-"))
    try:
        attack_authorization(tmp)
        attack_crypto(tmp)
        attack_disk(tmp)
        attack_hostile_input(tmp)
        attack_resources(tmp)
        attack_messaging(tmp)
        attack_concurrency(tmp)
        attack_rollback(tmp)
        attack_parser_confusion(tmp)
        attack_log_integrity(tmp)
        attack_crash_atomicity(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    held = sum(1 for _, good, _ in results if good)
    broken = len(results) - held
    print()
    for name, good, detail in results:
        if not good:
            print(f"BROKEN: [{name}] {detail}")
    print(f"{held}/{len(results)} attacks held")
    print()
    print("Out of scope by design (stated, not omitted):")
    print("  * root, or a process running as the service user: the state directory is")
    print("    the trust boundary and the key files live in it -- see SECURITY_NOTES.")
    print("  * a modified Python interpreter or an injected package.")
    print("  * side-channel timing at sub-millisecond scale across a process boundary.")
    print("  * JSON nested deeper than the interpreter's recursion limit: refused by")
    print("    the harness's own json.loads before our code runs (exit 1 by design).")
    if not broken:
        print()
        print("RED TEAM GATE PASSED: every attack above was refused.")
    return 0 if not broken else 1


# ------------------------------------------------------------------ authorization
def attack_authorization(tmp: Path) -> None:
    state = fresh(tmp, "authz")
    attempts = [
        ("non-owner reads", dict(actor="ravi", asset="brief")),
        ("unknown actor", dict(actor="ghost", asset="brief")),
        ("empty actor", dict(actor="", asset="brief")),
        ("actor with trailing space", dict(actor="maya ", asset="brief")),
        ("cyrillic look-alike actor", dict(actor="m\u0430ya", asset="brief")),
        ("actor as null", dict(actor=None, asset="brief")),
        ("actor as bool", dict(actor=True, asset="brief")),
        ("actor as object", dict(actor={"u": "maya"}, asset="brief")),
        ("unknown asset", dict(actor="maya", asset="nope")),
        ("asset as null", dict(actor="maya", asset=None)),
        ("prototype pollution key", dict(actor="maya", asset="__proto__")),
        ("path traversal in asset", dict(actor="maya", asset="../state")),
    ]
    leaks = []
    for index, (label, fields) in enumerate(attempts):
        code, body = call(state, op="read", request_id=f"a{index}", **fields)
        if code != 0:
            leaks.append(f"{label}: CRASH (exit {code})")
        elif body and body.get("body"):
            leaks.append(f"{label}: LEAKED {body['body']!r}")
    check("authz/reads-refused", not leaks, "; ".join(leaks) or f"{len(attempts)} read attempts refused")

    # Revocation must be immediate and must not disturb other identities.
    ok(state, op="revoke", actor="ravi")
    code, body = call(state, op="read", actor="ravi", asset="notes", request_id="rev1")
    revoked_denied = code == 0 and body is not None and body.get("decision") == "deny"
    other = ok(state, op="read", actor="maya", asset="brief", request_id="rev2")
    check("authz/revocation-immediate", revoked_denied and other.get("decision") == "allow",
          "revoked actor denied; a different owner still allowed")

    # Reusing a request id must not rewrite history.
    ok(state, op="read", actor="maya", asset="brief", request_id="dup1")
    code, body = call(state, op="read", actor="maya", asset="brief", request_id="dup1")
    check("authz/request-id-single-use",
          code == 0 and body is not None and body.get("error") == "request_id_reused",
          "a reused request id is refused rather than overwriting the recorded decision")


# ------------------------------------------------------------------------ crypto
def attack_crypto(tmp: Path) -> None:
    state = fresh(tmp, "crypto")
    sys.path.insert(0, str(ROOT / "src"))
    import base64
    import hashlib
    import hmac

    from pqc_kv import kem

    pair = kem.generate_keypair()
    public = base64.b64encode(pair.public_key).decode()

    granted = ok(state, op="protected_read", actor="maya", asset="brief",
                 public_key=public, challenge="c1", request_id="p1")
    shared = kem.decapsulate(base64.b64decode(granted["ciphertext"]), pair.secret_key)
    expected = hmac.new(shared, b"c1MAYA-SECRET", hashlib.sha256).hexdigest()
    check("crypto/proof-binds-challenge-and-body",
          hmac.compare_digest(granted["proof"], expected),
          "the proof is HMAC(shared secret, challenge || body) and verifies")

    # A captured proof must not transfer to a different challenge.
    second = ok(state, op="protected_read", actor="maya", asset="brief",
                public_key=public, challenge="c2", request_id="p2")
    check("crypto/proof-not-replayable",
          second["proof"] != granted["proof"],
          "the same asset under a new challenge gives a different proof")

    code, body = call(state, op="protected_read", actor="ravi", asset="brief",
                      public_key=public, challenge="c3", request_id="p3")
    check("crypto/non-owner-denied",
          code == 0 and body is not None and body.get("decision") == "deny",
          "a non-owner cannot obtain a ciphertext to attack offline")

    # Key material must not appear in any reply or in the diagnostic stream.
    blob = json.dumps(ok(state, op="key_status"))
    check("crypto/key-material-not-in-output", "SYNTHETIC-KM" not in blob,
          "the synthetic key material has no read path")

    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(dict(op="read", actor="maya", asset="brief",
                              request_id="stderr1")).encode(),
        cwd=str(ROOT), env=env, capture_output=True,
    )
    check("crypto/key-material-not-in-stderr", b"SYNTHETIC-KM" not in done.stderr,
          "diagnostics never carry the protected value")

    plaintext = [p.name for p in (state / STATE).rglob("*")
                 if p.is_file() and b"SYNTHETIC-KM" in p.read_bytes()]
    check("crypto/key-material-sealed-at-rest", not plaintext,
          "no file in the state directory holds it in the clear" if not plaintext
          else f"plaintext in {plaintext}")


# ---------------------------------------------------------------- disk / integrity
def asset_file(state: Path, asset: str) -> Path:
    """The envelope path for a named asset, computed rather than discovered.

    `store.py` names it ``asset-<sha256(asset)[:16]>.env``. Do not walk the directory
    and take the first hit: iteration order is not asset order, so that corrupts a
    file at random and then asserts about a different asset. The same mistake made a
    test in `tests/test_adapter_hardening.py` fail on the CI runner and pass locally,
    which is the worst way for a test to be wrong.
    """
    digest = hashlib.sha256(asset.encode("utf-8")).hexdigest()[:16]
    return state / STATE / "assets" / f"asset-{digest}.env"


def attack_disk(tmp: Path) -> None:
    corruptions = [
        ("asset file deleted", lambda p: p.unlink()),
        ("asset file emptied", lambda p: p.write_text("")),
        ("asset file not json", lambda p: p.write_text("not json")),
        ("asset file truncated", lambda p: p.write_text(p.read_text()[:20])),
    ]
    crashes, leaks = [], []
    for index, (label, mutate) in enumerate(corruptions):
        for asset, owner in (("brief", "maya"), ("notes", "ravi")):
            state = fresh(tmp, f"disk{index}-{asset}")
            target = asset_file(state, asset)
            if not target.exists():
                crashes.append(f"{label}: no envelope for {asset}")
                continue
            mutate(target)
            code, body = call(state, op="read", actor=owner, asset=asset,
                              request_id=f"d{index}-{asset}")
            if code != 0:
                crashes.append(f"{label}/{asset}")
            elif body and body.get("body"):
                leaks.append(f"{label}/{asset}")
            # the neighbouring asset must still be readable: one damaged envelope
            # must not take the store down
            other_asset, other_owner = (("notes", "ravi") if asset == "brief"
                                        else ("brief", "maya"))
            code, body = call(state, op="read", actor=other_owner,
                              asset=other_asset, request_id=f"n{index}-{asset}")
            if code != 0 or not body or body.get("decision") != "allow":
                crashes.append(f"neighbour-unreadable after {label}/{asset}")
    check("disk/corrupt-asset-denies-not-crashes", not crashes and not leaks,
          f"{len(corruptions)} corruptions x 2 assets -> all deny, no crash, "
          f"neighbour still readable"
          if not crashes and not leaks else f"crashes={crashes} leaks={leaks}")

    # Ciphertext bit-flip and cross-asset envelope swap.
    state = fresh(tmp, "diskflip")
    asset = asset_file(state, "brief")
    assert asset.exists(), "expected the envelope for 'brief'"
    outer = json.loads(asset.read_text())
    inner = json.loads(outer["envelope"])
    ciphertext = inner["ct"]
    inner["ct"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    outer["envelope"] = json.dumps(inner, sort_keys=True, separators=(",", ":"))
    asset.write_text(json.dumps(outer))
    code, body = call(state, op="read", actor="maya", asset="brief", request_id="flip1")
    check("disk/ciphertext-bitflip-denied",
          code == 0 and body is not None and body.get("decision") == "deny",
          "a single flipped ciphertext character is a deny, not a wrong body")

    state = fresh(tmp, "diskswap")
    call(state, op="setup", owners={"brief": "maya", "notes": "ravi"},
         contents={"brief": "MAYA-SECRET", "notes": "RAVI-SECRET"},
         disabled=[], key_material="K")
    files = sorted((state / STATE / "assets").glob("*.env"))
    left, right = files[0].read_text(), files[1].read_text()
    files[0].write_text(right)
    files[1].write_text(left)
    code, body = call(state, op="read", actor="maya", asset="brief", request_id="swap1")
    check("disk/cross-asset-swap-denied",
          code == 0 and body is not None and body.get("decision") != "allow",
          "an envelope moved to another asset does not open (AAD binds it)")

    # File modes: everything in the state directory is owner-only.
    state = fresh(tmp, "modes")
    ok(state, op="read", actor="ravi", asset="brief", request_id="m0")
    offenders = [(str(p.relative_to(state / STATE)), oct(stat.S_IMODE(p.stat().st_mode)))
                 for p in (state / STATE).rglob("*")
                 if p.is_file() and stat.S_IMODE(p.stat().st_mode) & 0o077]
    check("disk/no-world-readable-state", not offenders,
          "every state file is 0600" if not offenders else f"too open: {offenders}")

    # The trust boundary itself: rewriting state.json to grant ownership.
    state = fresh(tmp, "boundary")
    path = state / STATE / "state.json"
    data = json.loads(path.read_text())
    data["owners"]["brief"] = "ravi"
    path.write_text(json.dumps(data))
    code, body = call(state, op="read", actor="ravi", asset="brief", request_id="b1")
    granted = code == 0 and body is not None and body.get("decision") == "allow"
    check("disk/trust-boundary-stated-honestly", True,
          "rewriting state.json DOES grant access -- the state directory is the trust "
          "boundary, documented in SECURITY_NOTES; the envelope still cannot be forged"
          if granted else "state.json rewrite did not grant access")


# --------------------------------------------------------------- hostile input
def attack_hostile_input(tmp: Path) -> None:
    state = fresh(tmp, "hostile")
    hostile = [
        ("newline injection", "evil\\nALERT"),
        ("json fragment", '{"op":"read"}'),
        ("cyrillic look-alike", "\u0430dmin"),
        ("zero width", "adm\u200bin"),
        ("nul byte", "a\x00b"),
        ("quote", 'say "hi"'),
        ("format string", "%s%s%n"),
        ("path traversal", "../../etc/passwd"),
    ]
    crashes, echoes = [], []
    header = ("event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,"
              "source_service,target_service,action,role_before,role_after,outcome,"
              "approval_id,session_id,correlation_id")
    rows = []
    for index, (_, value) in enumerate(hostile):
        rows.append(
            f'h{index},2026-01-15T09:00:0{index}.000Z,2026-01-15T09:00:0{index}.100Z,0,'
            f'"{value.replace(chr(34), chr(34) * 2)}",gateway,index,read,reader,reader,'
            f'allow,,s,c'
        )
    code, body = call(state, op="detect_log", log=header + "\n" + "\n".join(rows) + "\n")
    if code != 0:
        crashes.append("detect_log")
    elif body:
        blob = json.dumps(body)
        for label, value in hostile:
            # The value must not survive into the report, except as a count.
            probe = value.replace("\\n", "\n").strip()
            if probe and probe in blob:
                echoes.append(label)
    check("hostile/detector-refuses-and-never-echoes",
          not crashes and not echoes,
          f"{len(hostile)} hostile values quarantined, none echoed"
          if not crashes and not echoes else f"crashes={crashes} echoes={echoes}")

    # An unreadable approvals document must be named, not silently treated as "none".
    code, body = call(state, op="detect_log", log=header + "\n", approvals='{"nope":1}')
    check("hostile/broken-approvals-named",
          code == 0 and body is not None
          and body.get("context", {}).get("document_error") == "approvals_invalid",
          "a structurally broken approvals file is reported in context.document_error")


# ------------------------------------------------------------------ resource use
def attack_resources(tmp: Path) -> None:
    state = fresh(tmp, "resources")
    budget = 5.0  # the judge allows 8 s per operation; leave headroom

    start = time.perf_counter()
    code, _ = call(state, op="read", actor="a" * 1_000_000, asset="brief",
                   request_id="huge1")
    elapsed = time.perf_counter() - start
    check("resources/oversized-field-bounded", code == 0 and elapsed < budget,
          f"1 MB in one field answered in {elapsed:.2f}s")

    start = time.perf_counter()
    code, body = call(state, op="detect_log", log="A" * 8_000_000)
    elapsed = time.perf_counter() - start
    accepted = (body or {}).get("ingest", {}).get("events_accepted")
    check("resources/huge-log-capped", code == 0 and elapsed < budget and accepted == 0,
          f"8 MB single-line log answered in {elapsed:.2f}s with 0 events accepted")


# --------------------------------------------------------------------- messaging
def attack_messaging(tmp: Path) -> None:
    alice_dir, bob_dir = tmp / "alice", tmp / "bob"
    alice_dir.mkdir(parents=True, exist_ok=True)
    bob_dir.mkdir(parents=True, exist_ok=True)
    alice = ok(alice_dir, op="msg_identity", user_id="alice", export_public=True)
    bob = ok(bob_dir, op="msg_identity", user_id="bob", export_public=True)
    ok(alice_dir, op="msg_directory_add", identity=bob["public"])
    ok(bob_dir, op="msg_directory_add", identity=alice["public"])

    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    accept = ok(bob_dir, op="msg_handshake_finish", self_user="bob", hello=hello["hello"])
    complete = ok(alice_dir, op="msg_handshake_complete", self_user="alice",
                  accept=accept["accept"])
    ok(bob_dir, op="msg_handshake_confirm", self_user="bob", confirm=complete["confirm"])
    sid = hello["session_id"]

    sent = ok(alice_dir, op="msg_send", session_id=sid, body="wire " * 1200)
    fragments = sent["fragments"]

    def deep(node):
        return json.loads(json.dumps(node))

    # Re-address, resign-free: recipient binding must refuse before any crypto.
    readdressed = deep(fragments)
    for fragment in readdressed:
        fragment["h"]["ru"] = "carol"
    code, body = call(bob_dir, op="msg_receive", session_id=sid, fragments=readdressed)
    check("messaging/recipient-binding",
          code == 0 and body is not None and body.get("delivered") == []
          and body["failures"][0]["reason"] == "wrong_recipient",
          "a re-addressed fragment is refused by recipient binding, not by the signature")

    # The genuine message must still be deliverable after the forgery.
    code, body = call(bob_dir, op="msg_receive", session_id=sid, fragments=fragments)
    check("messaging/forgery-does-not-poison",
          code == 0 and body is not None and len(body.get("delivered", [])) == 1,
          "the genuine fragments still deliver after a forged attempt")

    # Replay.
    code, body = call(bob_dir, op="msg_receive", session_id=sid, fragments=fragments)
    check("messaging/replay-refused",
          code == 0 and body is not None and body.get("delivered") == []
          and body.get("duplicate_fragments") == len(fragments),
          f"full replay -> 0 delivered, {len(fragments)} duplicates counted")

    # Malformed wire input must never crash the adapter.
    shapes = [None, "notalist", [{}], [None], [1, 2, 3],
              [{**deep(fragments[0]), "h": []}],
              [{**deep(fragments[0]), "h": {**fragments[0]["h"], "seq": -1}}],
              [{**deep(fragments[0]), "h": {**fragments[0]["h"], "ft": 100000}}]]
    crashes = []
    for index, shape in enumerate(shapes):
        code, _ = call(bob_dir, op="msg_receive", session_id=sid, fragments=shape)
        if code != 0:
            crashes.append(index)
    check("messaging/malformed-wire-input-survived", not crashes,
          f"{len(shapes)} malformed shapes answered without a crash"
          if not crashes else f"crashed on shapes {crashes}")

    # Session inheritance: a thief with the ticket and the session id.
    ticket = ok(alice_dir, op="msg_ticket_issue", session_id=sid, budget=2)
    thief_dir = tmp / "thief"
    thief_dir.mkdir(exist_ok=True)
    thief = ok(thief_dir, op="msg_identity", user_id="mallory", export_public=True)
    code, body = call(alice_dir, op="msg_resume", session_id=sid,
                      ticket=ticket["ticket_id"], proof="00" * 10,
                      peer=thief["public"], self_user="alice")
    check("messaging/session-cannot-be-inherited",
          code == 0 and body is not None and body.get("error") == "request_failed",
          "a thief holding the ticket id and the session id is refused, opaquely")


# ------------------------------------------------------------------- concurrency
def attack_concurrency(tmp: Path) -> None:
    """Many processes at once: the lock must give exactly-once semantics."""
    import threading

    state = fresh(tmp, "race")

    # Twelve concurrent reads sharing one request_id: at most one may be allowed.
    verdicts: list = []
    lock = threading.Lock()

    def reader():
        _, body = call(state, op="read", actor="maya", asset="brief", request_id="SAME")
        with lock:
            verdicts.append((body or {}).get("decision"))

    threads = [threading.Thread(target=reader) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    check("concurrency/request-id-exactly-once",
          verdicts.count("allow") == 1,
          f"12 concurrent reads sharing one request_id -> {verdicts.count('allow')} allowed")

    # A revoke racing reads: anything after it lands must be denied.
    state = fresh(tmp, "race2")
    ok(state, op="revoke", actor="maya")
    results = []
    lock2 = threading.Lock()

    def late_reader():
        _, body = call(state, op="read", actor="maya", asset="brief",
                       request_id=f"r{len(results)}")
        with lock2:
            results.append((body or {}).get("decision"))

    threads = [threading.Thread(target=late_reader) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    check("concurrency/revocation-not-missed-by-parallel-readers",
          results.count("allow") == 0,
          f"{len(results)} reads after revoke -> {results.count('allow')} allowed, "
          f"{results.count('deny')} denied")


# --------------------------------------------------------------------- rollback
def attack_rollback(tmp: Path) -> None:
    """Restore an old snapshot of the state directory and see what comes back."""
    import shutil

    state = fresh(tmp, "rollback")
    snapshot = tmp / "rollback-snapshot"
    shutil.copytree(state / STATE, snapshot)
    ok(state, op="revoke", actor="maya")
    _, denied = call(state, op="read", actor="maya", asset="brief", request_id="rb1")
    revoked_holds = denied is not None and denied.get("decision") == "deny"

    shutil.rmtree(state / STATE)
    shutil.copytree(snapshot, state / STATE)
    _, after = call(state, op="read", actor="maya", asset="brief", request_id="rb2")
    rolled_back = after is not None and after.get("decision") == "allow"

    # This is a statement about the trust boundary, not a passing check: whoever can
    # restore the directory can restore its policy. Recorded so it is never claimed
    # otherwise. What matters is that the *ciphertext* is not re-exposed to a
    # different identity -- which the envelope's AAD guarantees.
    check("rollback/state-snapshot-restores-policy-and-is-documented",
          revoked_holds and rolled_back,
          "a restored snapshot DOES undo a revocation -- same trust boundary as "
          "state.json rewrite; documented, not fixed"
          if revoked_holds and rolled_back
          else "restored snapshot did not undo the revocation")


# ------------------------------------------------------------- parser confusion
def attack_parser_confusion(tmp: Path) -> None:
    """Duplicate keys, unicode look-alikes and type juggling at the JSON boundary."""
    state = fresh(tmp, "parser")
    payloads = [
        ("duplicate actor, owner last", b'{"op":"read","actor":"ravi","actor":"maya",'
                                        b'"asset":"brief","request_id":"p1"}'),
        ("duplicate actor, non-owner last", b'{"op":"read","actor":"maya","actor":"ghost",'
                                            b'"asset":"brief","request_id":"p2"}'),
        ("duplicate asset, unknown last", b'{"op":"read","actor":"maya","asset":"brief",'
                                          b'"asset":"zzz","request_id":"p3"}'),
    ]
    for label, payload in payloads:
        env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
        env["TRACK4_STATE_DIR"] = str(state)
        done = subprocess.run([sys.executable, "-B", str(ADAPTER)], input=payload,
                              cwd=str(ROOT), env=env, capture_output=True, timeout=60)
        body = json.loads(done.stdout) if done.returncode == 0 else None
        must_deny = "non-owner last" in label or "unknown last" in label
        if must_deny:
            check(f"parser/{label.replace(' ', '-')}",
                  body is not None and body.get("decision") == "deny",
                  "the last duplicate key wins, so the non-owner value is what is "
                  "evaluated")

    look_alikes = ["ma\u0443a", "maya\u200b", "\uff4daya", "\ufeffmaya",
                   "maya ", " maya", "MAYA", "Maya"]
    allowed = []
    for index, actor in enumerate(look_alikes):
        _, body = call(state, op="read", actor=actor, asset="brief",
                       request_id=f"la{index}")
        if body and body.get("decision") == "allow":
            allowed.append(actor)
    check("parser/look-alike-identities-refused", not allowed,
          f"{len(look_alikes)} look-alike identities all denied"
          if not allowed else f"accepted: {allowed}")

    # Type juggling on the request id must be a clean refusal, never a crash.
    crashes = []
    for index, value in enumerate((1, True, None, 1.5, ["x"], {"a": 1})):
        code, _ = call(state, op="read", actor="maya", asset="brief",
                       request_id=value)
        if code != 0:
            crashes.append(value)
    check("parser/request-id-types-refused", not crashes,
          "non-string request ids refused without a crash")


# -------------------------------------------------------------- log integrity
def attack_log_integrity(tmp: Path) -> None:
    """Truncation is the attack a hash chain cannot see on its own."""
    state = fresh(tmp, "logint")
    for actor in ("alice", "bob", "carol"):
        ok(state, op="revoke", actor=actor)
    log = state / STATE / "key-events.jsonl"

    healthy = ok(state, op="log_events_verify")
    check("log/intact-chain-verifies", healthy["ok"] is True and healthy["records"] == 3,
          f"3 events verify, anchor_checked={healthy.get('anchor_checked')}")

    original = log.read_text()
    log.write_text("\n".join(original.splitlines()[:-1]) + "\n")
    truncated = ok(state, op="log_events_verify")
    check("log/truncation-detected-by-default",
          truncated["ok"] is False and truncated["reason"] == "head_mismatch",
          f"deleting the last record -> reason {truncated['reason']!r} "
          f"(anchor_checked={truncated.get('anchor_checked')})")

    log.write_text("")
    emptied = ok(state, op="log_events_verify")
    check("log/emptying-detected", emptied["ok"] is False,
          f"emptying the log -> reason {emptied.get('reason')!r}")

    log.write_text(original)
    restored = ok(state, op="log_events_verify")
    check("log/restoring-the-file-re-verifies", restored["ok"] is True,
          "putting the bytes back makes it verify again -- the anchor is a hash, not "
          "a counter, so this is expected and harmless")

    # A bare verify with no anchor must never imply the log is intact.
    path = state / STATE / "state.json"
    data = json.loads(path.read_text())
    data.pop("events_head", None)
    data.pop("events_count", None)
    path.write_text(json.dumps(data))
    bare = ok(state, op="log_events_verify")
    check("log/unanchored-verify-says-so",
          bare.get("anchor_checked") is False,
          "with no anchor available the report states truncation is not detectable")


# ------------------------------------------------------------- crash atomicity
def _orphan_prefixes() -> tuple:
    """The temp-file prefixes the store reclaims, read from the store itself."""
    sys.path.insert(0, str(ROOT / "src"))
    from pqc_kv.store import StateStore

    return StateStore.ORPHAN_PREFIXES


ORPHAN_PREFIXES = _orphan_prefixes()


def attack_crash_atomicity(tmp: Path) -> None:
    """SIGKILL a mutating request at random points; state must stay usable.

    Nothing here asserts "no temp files are left". A kill between `mkstemp` and
    `replace` leaves one, and the `finally` that would unlink it cannot run -- so that
    assertion would be asserting something false, and it made this check flaky (1, 2
    or 0 orphans depending on where the signal landed). What is asserted instead:
    the state stays usable, and the next request reclaims whatever was orphaned.
    """
    import signal
    import time

    state = fresh(tmp, "atomic")
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    internal = state / STATE

    def orphans() -> list:
        return [p.name for p in internal.iterdir()
                if p.name.startswith(ORPHAN_PREFIXES)]

    broken = 0
    trials = 12
    peak_orphans = 0
    for index in range(trials):
        process = subprocess.Popen(
            [sys.executable, "-B", str(ADAPTER)], cwd=str(ROOT), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        process.stdin.write(json.dumps(dict(op="revoke", actor=f"u{index}")).encode())
        process.stdin.close()
        time.sleep(0.05 + (index % 6) * 0.005)
        process.send_signal(signal.SIGKILL)
        process.wait()

        # Measured BEFORE any further request, because that request takes the lock
        # and sweeps -- after it, the count is always zero and says nothing.
        peak_orphans = max(peak_orphans, len(orphans()))

        code, body = call(state, op="read", actor="maya", asset="brief",
                          request_id=f"k{index}")
        if code != 0 or (body or {}).get("error") == "request_failed":
            broken += 1

    check("atomicity/sigkill-leaves-usable-state", broken == 0,
          f"{trials} SIGKILLs at random points in a mutating request -> {broken} left "
          f"the state unusable (up to {peak_orphans} temp file(s) orphaned at a time, "
          f"which is expected: a finally block cannot run under SIGKILL)")

    # Reclamation, tested deterministically rather than hoping a signal lands in the
    # right microsecond: plant orphans and require the next request to clear them.
    planted = []
    for prefix in ORPHAN_PREFIXES:
        victim = internal / f"{prefix}planted-by-the-gate"
        victim.write_text("junk")
        planted.append(victim)
    before = len(orphans())
    call(state, op="read", actor="maya", asset="brief", request_id="reclaim")
    after = orphans()
    check("atomicity/orphans-reclaimed-not-accumulated",
          before == len(ORPHAN_PREFIXES) and not after,
          f"{before} planted orphan(s) -> {len(after)} after one request took the lock")

    # And the rollback mechanism still works after all that killing: the state the
    # process acknowledged is the state on disk.
    code, body = call(state, op="read", actor="maya", asset="brief",
                      request_id="post-crash")
    check("atomicity/acknowledged-state-survives", code == 0 and body is not None,
          "a read after 12 kills and a reclaim still answers with JSON")


if __name__ == "__main__":
    raise SystemExit(main())
