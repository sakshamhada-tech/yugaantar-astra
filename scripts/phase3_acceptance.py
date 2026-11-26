#!/usr/bin/env python
"""Phase 3 acceptance: goals 1-5, end to end, with measured numbers.

Everything here runs through the real adapter, one process per request, exactly as
the judging worker does. Numbers are measured with perf_counter_ns; nothing is
estimated. Where a number has a caveat (local processes, no network) the caveat is
printed next to it rather than hidden in a doc.

    python scripts/phase3_acceptance.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"
SECRET = b"phase3-acceptance-backup-key-0001"

results: list[tuple[str, bool, str]] = []


def call(state_dir: Path, cluster_dir: Path | None = None, **request):
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state_dir)
    if cluster_dir is not None:
        env["TRACK4_CLUSTER_DIR"] = str(cluster_dir)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=180,
    )
    if done.returncode != 0:
        raise RuntimeError(done.stderr.decode()[:400])
    return json.loads(done.stdout)


def ok(state_dir: Path, cluster_dir: Path | None = None, **request):
    response = call(state_dir, cluster_dir, **request)
    assert "error" not in response, response
    return response


def check(name: str, condition: bool, detail: str) -> None:
    results.append((name, bool(condition), detail))
    print(f"{'PASS' if condition else 'FAIL'} [{name}] {detail}")


def setup_payload(assets=("brief", "notes")):
    owners = {asset: ("maya" if asset == "brief" else "ravi") for asset in assets}
    contents = {asset: f"{asset} body" for asset in assets}
    return dict(op="setup", owners=owners, contents=contents, disabled=[], key_material="M")


# --------------------------------------------------------------------- goal 1
def goal1(tmp: Path) -> None:
    state = tmp / "g1"
    state.mkdir()
    ok(state, **setup_payload())

    before = ok(state, op="read", actor="maya", asset="brief", request_id="g1-a")
    check("goal1/readable-before", before == {"decision": "allow", "body": "brief body"},
          "owner reads the asset before rotation")

    start = time.perf_counter_ns()
    rotated = ok(state, op="rotate", grace=2)
    elapsed_ms = (time.perf_counter_ns() - start) / 1e6
    check("goal1/rotated", rotated["active_version"] == 2 and rotated["resealed"] == 2,
          f"rotation v1->v2 re-wrapped {rotated['resealed']} assets in {elapsed_ms:.1f} ms "
          f"(2 assets)")

    after = ok(state, op="read", actor="maya", asset="brief", request_id="g1-b")
    check("goal1/readable-after", after == before,
          "same read succeeds after rotation; data readable under the new key")

    # The documented cutoff, both sides of the boundary.
    first = ok(state, op="read", actor="maya", asset="brief", request_id="g1-c", key_version=1)
    second = ok(state, op="read", actor="maya", asset="brief", request_id="g1-d", key_version=1)
    third = call(state, op="read", actor="maya", asset="brief", request_id="g1-e", key_version=1)
    check("goal1/grace-before-cutoff", first["decision"] == "allow" and
          second["decision"] == "allow",
          "old key accepted twice inside a grace of 2 -> in-flight transfers complete")
    check("goal1/grace-at-cutoff", third == {"decision": "deny"},
          "third old-key request at the boundary is refused, with no reason disclosed")
    status = ok(state, op="key_status")
    check("goal1/retired", status["versions"][0]["state"] == "retired",
          f"version 1 state is now '{status['versions'][0]['state']}'")

    # Rotation must not be setup() in disguise.
    revoked = tmp / "g1b"
    revoked.mkdir()
    ok(revoked, **setup_payload())
    ok(revoked, op="revoke", actor="maya")
    ok(revoked, op="rotate", grace=2)
    survivor = ok(revoked, op="read", actor="maya", asset="brief", request_id="g1-f")
    check("goal1/not-destructive", survivor == {"decision": "deny"},
          "revocation survives rotation; rotate() never runs the setup() wipe path")


# --------------------------------------------------------------------- goal 2
def goal2(tmp: Path) -> None:
    base = tmp / "g2"
    nodes = []
    for i in range(3):
        state = base / f"node{i}"
        state.mkdir(parents=True)
        ok(state, base, **setup_payload())
        nodes.append(state)

    publisher = ok(
        nodes[0], base, op="cluster_publish", kind="revoke", payload={"actor": "maya"},
    )
    check("goal2/published", publisher["published"] is True,
          f"signed revocation notice published, seq {publisher['seq']}")

    from pqc_kv.keystore import KeyStore, b64e  # noqa: E402  (after ROOT is on sys.path)

    pair = KeyStore(nodes[0] / "pqc-kv-state" / "cluster-identity").signing_keypair(
        "cluster-publisher"
    )
    public = b64e(pair.public_key)

    samples = []
    for _ in range(3):
        start = time.perf_counter_ns()
        for index in range(1, len(nodes)):
            while True:
                ok(nodes[index], base, op="cluster_sync", publisher_public=public)
                decision = ok(nodes[index], base, op="read", actor="maya",
                              asset="brief", request_id=f"g2-{index}-{time.time_ns()}")["decision"]
                if decision == "deny":
                    break
        samples.append((time.perf_counter_ns() - start) / 1e6)

    worst = max(samples)
    median = sorted(samples)[len(samples) // 2]
    enforced = all(
        ok(nodes[i], base, op="read", actor="maya", asset="brief",
           request_id=f"g2-final-{i}")["decision"] == "deny"
        for i in range(3)
    )
    check("goal2/all-nodes-enforce", enforced,
          "the revoked actor is denied on all 3 nodes")
    check("goal2/propagation", worst < 60_000,
          f"revoke -> LAST node enforcing: median {median:.1f} ms, worst {worst:.1f} ms "
          f"over 3 runs. LOWER BOUND: local processes, no network delay")

    peer = ok(nodes[2], base, op="read", actor="ravi", asset="notes",
              request_id="g2-peer")
    check("goal2/peers-unaffected", peer["decision"] == "allow",
          "another actor still reads their own asset on the far node")

    # Offline catch-up.
    offline = base / "node3"
    offline.mkdir()
    ok(offline, base, **setup_payload())
    stale = ok(offline, base, op="read", actor="maya", asset="brief", request_id="g2-stale")
    ok(offline, base, op="cluster_sync", publisher_public=public)
    caught_up = ok(offline, base, op="read", actor="maya", asset="brief",
                   request_id="g2-caught")
    check("goal2/offline-catchup", stale["decision"] == "allow" and
          caught_up["decision"] == "deny",
          "a node that missed the notice accepts until it syncs, then rejects")

    # Forgery and replay.
    outbox = offline / ".." / "cluster-outbox"
    forged = {
        "magic": "pqc-kv-notice", "version": 1, "kind": "revoke", "seq": 999,
        "signer_fp": "f" * 64, "payload": {"actor": "ravi"},
        "signature": b64e(b"\x00" * 64),
    }
    (outbox / "forged.json").write_text(json.dumps({"notice": forged}))
    applied = ok(offline, base, op="cluster_sync", publisher_public=public)
    still_ok = ok(offline, base, op="read", actor="ravi", asset="notes",
                  request_id="g2-forge")
    check("goal2/forged-refused", applied["rejected"] >= 1 and
          still_ok["decision"] == "allow",
          f"forged notice rejected ({applied['rejected']}) and ravi is untouched")

    # Re-enrolment: the old device key stays rejected everywhere.
    ok(nodes[0], base, op="cluster_publish", kind="enrol",
       payload={"actor": "maya", "device": "maya-laptop-2"})
    for i in range(3):
        ok(nodes[i], base, op="cluster_sync", publisher_public=public)
    still_denied = all(
        ok(nodes[i], base, op="read", actor="maya", asset="brief",
           request_id=f"g2-re{i}")["decision"] == "deny"
        for i in range(3)
    )
    check("goal2/re-enrol", still_denied,
          "after re-enrolment the revoked device key is still rejected on every node")


# --------------------------------------------------------------------- goal 3
POINTS = ["before_intent", "after_intent", "mid_rewrap", "before_commit", "after_commit"]


def goal3(tmp: Path) -> None:
    kills = 0
    consistent = 0
    worst_ms = 0.0
    for point in POINTS:
        state = tmp / f"g3-{point}"
        state.mkdir()
        # maya owns "brief" and is then revoked; ravi owns the other two, so the
        # recovery check has assets that must stay readable by a live actor.
        ok(state, **setup_payload(("brief", "notes", "extra")))
        ok(state, op="revoke", actor="maya")

        env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
        env["TRACK4_STATE_DIR"] = str(state)
        env["TRACK4_FAULT_AT"] = point
        done = subprocess.run(
            [sys.executable, "-B", str(ADAPTER)],
            input=json.dumps({"op": "rotate", "grace": 2}).encode(),
            cwd=str(ROOT), env=env, capture_output=True, timeout=180,
        )
        if done.returncode == 97:
            kills += 1

        start = time.perf_counter_ns()
        ok(state, op="recover")
        worst_ms = max(worst_ms, (time.perf_counter_ns() - start) / 1e6)

        status = ok(state, op="key_status")
        active = [v for v in status["versions"] if v["state"] == "active"]
        readable = all(
            ok(state, op="read", actor="ravi", asset=asset,
               request_id=f"g3-{point}-{asset}")["decision"] == "allow"
            for asset in ("notes", "extra")
        )
        revoked_held = ok(state, op="read", actor="maya", asset="brief",
                          request_id=f"g3-{point}-rev")["decision"] == "deny"
        if len(active) == 1 and readable and revoked_held:
            consistent += 1

    check("goal3/kills", kills == len(POINTS),
          f"{kills}/{len(POINTS)} real subprocesses killed at named points")
    check("goal3/consistency", consistent == len(POINTS),
          f"{consistent}/{len(POINTS)} runs recovered to exactly one active version, "
          f"all assets readable, revocations intact")
    check("goal3/recovery-time", worst_ms < 30_000,
          f"worst recovery time {worst_ms:.1f} ms (single process, local disk)")


# --------------------------------------------------------------------- goal 4
def goal4(tmp: Path) -> None:
    state = tmp / "g4"
    state.mkdir()
    ok(state, **setup_payload())

    key = base64.b64encode(SECRET).decode()
    blob = ok(state, op="backup_create", backup_key=key)["backup"]

    sys.path.insert(0, str(ROOT / "src"))
    from pqc_kv.store import StateStore

    public = base64.b64encode(
        StateStore(state).ring.dsa_pair(1).public_key
    ).decode()

    restored = ok(state, op="backup_restore", backup_key=key, backup=blob,
                  signing_public=public)
    good = ok(state, op="read", actor="maya", asset="brief", request_id="g4-a")
    check("goal4/restore", restored["count"] > 0 and good["decision"] == "allow",
          f"good backup restored {restored['count']} key files; reads still work")

    # Bit flip in each region.
    def flip(region: str):
        out = json.loads(json.dumps(blob))
        if region in ("nonce", "ciphertext", "tag", "signature"):
            raw = bytearray(base64.b64decode(out[region]))
            raw[len(raw) // 2] ^= 0x01
            out[region] = base64.b64encode(bytes(raw)).decode()
        elif region == "salt":
            raw = bytearray(base64.b64decode(out["manifest"]["salt"]))
            raw[0] ^= 0x01
            out["manifest"]["salt"] = base64.b64encode(bytes(raw)).decode()
        elif region == "manifest_hash":
            out["manifest"]["manifest_hash"] = "0" * 64
        else:
            out["manifest"][region] = 9999
        return out

    regions = ["nonce", "ciphertext", "tag", "signature", "salt", "manifest_hash",
               "key_version", "revocation_seq"]
    refused = 0
    for region in regions:
        response = call(state, op="backup_restore", backup_key=key,
                        backup=flip(region), signing_public=public)
        if response == {"error": "backup_refused"}:
            refused += 1
    check("goal4/damage-detection", refused == len(regions),
          f"{refused}/{len(regions)} single-bit mutations refused (nonce, ciphertext, "
          f"tag, signature, salt, manifest hash, key version, revocation seq)")

    truncated = json.loads(json.dumps(blob))
    truncated["ciphertext"] = truncated["ciphertext"][: len(truncated["ciphertext"]) // 2]
    check("goal4/truncation",
          call(state, op="backup_restore", backup_key=key, backup=truncated,
               signing_public=public) == {"error": "backup_refused"},
          "truncated backup refused")

    # Rollback: take a backup, then revoke, then replay the old backup.
    stale_blob = ok(state, op="backup_create", backup_key=key)["backup"]
    ok(state, op="revoke", actor="maya")
    replay = call(state, op="backup_restore", backup_key=key, backup=stale_blob,
                  signing_public=public)
    still_denied = ok(state, op="read", actor="maya", asset="brief",
                      request_id="g4-replay")["decision"] == "deny"
    check("goal4/rollback", replay == {"error": "backup_refused"} and still_denied,
          "a genuine but older backup is refused as stale; the revoked key stays revoked")


# --------------------------------------------------------------------- goal 5
def goal5(tmp: Path) -> None:
    state = tmp / "g5"
    state.mkdir()
    ok(state, **setup_payload())
    ok(state, op="revoke", actor="maya")
    ok(state, op="rotate", grace=2)

    head = ok(state, op="log_events_head")
    verified = ok(state, op="log_events_verify")
    check("goal5/signed-chain", verified["ok"] is True and head["events"] >= 2,
          f"signed chain verifies over {verified['records']} key events "
          f"(revoke, rotate)")

    path = state / "pqc-kv-state" / "key-events.jsonl"
    original = path.read_text()
    lines = [line for line in original.splitlines() if line.strip()]

    # Edit
    import copy

    tampered = json.loads(lines[1])
    tampered["actor"] = "ravi"
    sys.path.insert(0, str(ROOT / "src"))
    from pqc_kv.logsign import encode_line

    lines[1] = encode_line(tampered)
    path.write_text("\n".join(lines) + "\n")
    edited = ok(state, op="log_events_verify")
    check("goal5/edit-detected", edited["ok"] is False and edited["first_bad"] == 2,
          f"edited record detected at record {edited['first_bad']}")

    # Truncate: internally valid, caught only by the anchored head.
    path.write_text(lines[0] + "\n")
    unanchored = ok(state, op="log_events_verify")
    anchored = ok(state, op="log_events_verify", expected_head=head["events_head"])
    check("goal5/truncation-detected", anchored["ok"] is False,
          f"truncation invisible to the bare chain ({unanchored['ok']}) but caught by "
          f"the remembered head")

    # Delete / reorder on a fresh log.
    state2 = tmp / "g5b"
    state2.mkdir()
    ok(state2, **setup_payload())
    for actor in ("maya", "ravi"):
        ok(state2, op="revoke", actor=actor)
    path2 = state2 / "pqc-kv-state" / "key-events.jsonl"
    lines2 = [line for line in path2.read_text().splitlines() if line.strip()]
    path2.write_text("\n".join([lines2[1]]) + "\n")
    deleted = ok(state2, op="log_events_verify")
    path2.write_text("\n".join([lines2[1], lines2[0]]) + "\n")
    reordered = ok(state2, op="log_events_verify")
    check("goal5/delete-reorder", deleted["ok"] is False and reordered["ok"] is False,
          "deleted and reordered records both detected")

    # Hostile actor text must not forge an event.
    state3 = tmp / "g5c"
    state3.mkdir()
    ok(state3, **setup_payload())
    hostile = 'maya","action":"revoke","actor":"ravi'
    ok(state3, op="revoke", actor=hostile)
    events = json.loads((state3 / "pqc-kv-state" / "key-events.jsonl").read_text()
                        .splitlines()[0])
    events_ok = ok(state3, op="log_events_verify")
    check("goal5/injection", events["actor"] == "" and events_ok["records"] == 1,
          "hostile actor name cannot create a second event; it is dropped, not merged")


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    tmp = Path(tempfile.mkdtemp(prefix="phase3-"))
    print(f"state under {tmp}\n")
    for goal in (goal1, goal2, goal3, goal4, goal5):
        print(f"--- {goal.__name__.replace('goal', 'goal ')} ---")
        try:
            goal(tmp)
        except Exception as error:  # noqa: BLE001 - report and keep going
            results.append((goal.__name__, False, f"raised {type(error).__name__}"))
            print(f"FAIL [{goal.__name__}] raised {type(error).__name__}: {error}")
        print()

    passed = sum(1 for _, good, _ in results if good)
    print(f"{passed}/{len(results)} Phase 3 checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
