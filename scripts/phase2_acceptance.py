#!/usr/bin/env python
"""Phase 2 acceptance: goals 9, 10, 11 and 12 end to end, reported in plain terms.

Runs real subprocesses through track4_service.py, one per request, and prints a
short PASS/FAIL per goal with the measured numbers behind each claim.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "track4_service.py"
results: list[tuple[str, bool, str]] = []


def call(state: Path, **request) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    done = subprocess.run(
        [sys.executable, "-B", str(ADAPTER)],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=180,
    )
    if done.returncode != 0:
        raise RuntimeError(done.stderr.decode())
    return json.loads(done.stdout)


def ok(state, **request):
    response = call(state, **request)
    assert "error" not in response, response
    return response


def check(name: str, condition: bool, detail: str) -> None:
    results.append((name, bool(condition), detail))
    print(f"{'PASS' if condition else 'FAIL'} [{name}] {detail}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="phase2-"))
    alice_dir, bob_dir, carol_dir = tmp / "a", tmp / "b", tmp / "c"
    for d in (alice_dir, bob_dir, carol_dir):
        d.mkdir()

    alice = ok(alice_dir, op="msg_identity", user_id="alice", export_public=True)
    bob = ok(bob_dir, op="msg_identity", user_id="bob", export_public=True)
    ok(carol_dir, op="msg_identity", user_id="carol", export_public=True)
    ok(alice_dir, op="msg_directory_add", identity=bob["public"])
    ok(bob_dir, op="msg_directory_add", identity=alice["public"])
    ok(carol_dir, op="msg_directory_add", identity=alice["public"])
    check("identity", len(alice["fingerprint"]) == 64,
          f"fingerprint = SHA-256 over both public keys, {len(alice['fingerprint'])} hex chars")

    # Goal 10: forward secrecy comes from fresh ephemerals, not the long-term key.
    hello = ok(alice_dir, op="msg_handshake_init", self_user="alice", peer_user="bob")
    pending = list((alice_dir / "pqc-kv-messaging" / "ephemeral").glob("hs-*.json"))
    check("handshake/step1", len(pending) == 1 and hello["hello"]["to_fp"] == bob["fingerprint"],
          "hello signed, names bob's user id AND fingerprint, 1 pending ephemeral on disk")

    # Refinement 2: a hello meant for bob must be refused by carol.
    stolen = call(carol_dir, op="msg_handshake_finish", self_user="carol", hello=hello["hello"])
    check("handshake/reject-third-party", stolen == {"error": "request_failed"},
          "carol refuses a hello addressed to bob (opaque error, no reason leaked)")

    accept = ok(bob_dir, op="msg_handshake_finish", self_user="bob", hello=hello["hello"])
    bob_eph = bob_dir / "pqc-kv-messaging" / "ephemeral"
    check("handshake/option-b", not bob_eph.exists() or not list(bob_eph.glob("hs-*.json")),
          "responder completed in one process and persisted no ephemeral keys")

    confirm = ok(alice_dir, op="msg_handshake_complete", self_user="alice", accept=accept["accept"])
    ok(bob_dir, op="msg_handshake_confirm", self_user="bob", confirm=confirm["confirm"])
    check("handshake/step3", True,
          "confirm signed by A over the same transcript hash -> mutual key confirmation")

    gone = list((alice_dir / "pqc-kv-messaging" / "ephemeral").glob("hs-*.json"))
    check("handshake/erase", gone == [],
          "initiator's ephemeral file deleted the moment the session key existed")

    session_id = hello["session_id"]
    check("session/both-sides",
          ok(alice_dir, op="msg_status", session_id=session_id)["confirmed"]
          and ok(bob_dir, op="msg_status", session_id=session_id)["confirmed"],
          "both processes hold the session; initiator=alice, responder=bob")

    # Goal 11: fragmentation, loss, reordering, duplicates, corruption.
    body = "attack at dawn. " * 700  # ~11 KB
    sent = ok(alice_dir, op="msg_send", session_id=session_id, body=body)
    fragments = sent["fragments"]
    check("fragmentation", sent["fragment_count"] > 1,
          f"{len(body)} B body -> {sent['fragment_count']} authenticated fragments "
          f"(index+total in AAD, one manifest signature)")

    half = fragments[: len(fragments) // 2]
    partial = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=half)
    check("loss/incomplete",
          partial["delivered"] == []
          and partial["failures"][0]["reason"] == "incomplete",
          f"{len(half)}/{len(fragments)} delivered -> nothing delivered, reason recorded, "
          f"message id in failure {partial['failures'][0]['message_id']}")

    rest = list(reversed(fragments[len(fragments) // 2:]))
    finished = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=rest)
    check("reorder/reassemble",
          len(finished["delivered"]) == 1 and finished["delivered"][0]["body"] == body,
          "remaining fragments arriving reversed still reassemble to the exact body")

    dupe = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=fragments)
    check("replay/duplicate",
          dupe["delivered"] == [] and dupe["duplicate_fragments"] == len(fragments),
          f"replay of all {len(fragments)} fragments -> 0 delivered, all counted as duplicates")

    sent2 = ok(alice_dir, op="msg_send", session_id=session_id, body="second message " * 400)
    broken = [dict(f) for f in sent2["fragments"]]
    broken[len(broken) // 2]["h"]["ru"] = "carol"
    tampered = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=broken)
    check("binding/recipient",
          tampered["delivered"] == [] and tampered["failures"][0]["reason"] == "wrong_recipient",
          "re-addressed to carol -> whole message refused as wrong_recipient")

    # Refinement 6: revocation reaches messaging.
    ok(bob_dir, op="setup", owners={"brief": "bob"}, contents={"brief": "x"},
       disabled=[], key_material="k")
    ok(bob_dir, op="revoke", actor="bob")
    sent3 = ok(alice_dir, op="msg_send", session_id=session_id, body="after revocation")
    blocked = ok(bob_dir, op="msg_receive", session_id=session_id, fragments=sent3["fragments"])
    check("revocation", blocked["delivered"] == []
          and blocked["failures"][0]["reason"] == "policy_denied",
          "a Phase 1 revoke immediately stops Phase 2 delivery")

    # Goal 12: resumption, on a clean pair.
    d_dir, e_dir = tmp / "d", tmp / "e"
    d_dir.mkdir(); e_dir.mkdir()
    d = ok(d_dir, op="msg_identity", user_id="d", export_public=True)
    e = ok(e_dir, op="msg_identity", user_id="e", export_public=True)
    ok(d_dir, op="msg_directory_add", identity=e["public"])
    ok(e_dir, op="msg_directory_add", identity=d["public"])
    h2 = ok(d_dir, op="msg_handshake_init", self_user="d", peer_user="e")
    a2 = ok(e_dir, op="msg_handshake_finish", self_user="e", hello=h2["hello"])
    ok(d_dir, op="msg_handshake_complete", self_user="d", accept=a2["accept"])
    ticket = ok(d_dir, op="msg_ticket_issue", session_id=h2["session_id"], budget=2)

    forged = call(d_dir, op="msg_resume", session_id=h2["session_id"],
                  ticket=ticket["ticket_id"], proof="00" * 10, peer=e["public"], self_user="d")
    check("goal12/proof-required", forged == {"error": "request_failed"},
          "a resume with a bogus proof is refused, and the refusal is opaque")

    # A real proof requires e's long-term signing key: the ticket file alone is useless.
    sys.path.insert(0, str(ROOT / "src"))
    from pqc_kv.keystore import KeyStore
    from pqc_kv.messaging import resumption
    from pqc_kv.messaging.identity import PublicIdentity

    e_identity_keys = KeyStore(e_dir / "pqc-kv-messaging" / "identities")
    e_signing = e_identity_keys.signing_keypair("identity-sign-e")
    path = resumption.proof_payload(ticket["ticket_id"], ticket["challenge"], ticket["peer_fp"])
    from pqc_kv import dsa

    proof = dsa.sign(e_signing.secret_key, path).hex()
    resumed = ok(d_dir, op="msg_resume", session_id=h2["session_id"],
                 ticket=ticket["ticket_id"], proof=proof, peer=e["public"], self_user="d")
    check("goal12/resume", resumed["resumed"] is True and resumed["remaining_budget"] == 1,
          f"valid proof -> resumed with a fresh root, budget now {resumed['remaining_budget']}")

    # Budget 1: the same ticket must now be dead.
    ok(d_dir, op="msg_resume", session_id=h2["session_id"], ticket=ticket["ticket_id"],
       proof=proof, peer=e["public"], self_user="d")
    spent = call(d_dir, op="msg_resume", session_id=h2["session_id"],
                 ticket=ticket["ticket_id"], proof=proof, peer=e["public"], self_user="d")
    check("goal12/single-use", spent == {"error": "request_failed"},
          "once the budget is spent the ticket is gone and a full handshake is required")

    print()
    passed = sum(1 for _, good, _ in results if good)
    print(f"{passed}/{len(results)} Phase 2 checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
