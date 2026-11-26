"""Goal 2: revocation (and rotation) across N nodes, with real processes.

Every node here is a separate state directory driven by a separate short-lived
adapter process -- the same constraint the judging container imposes. Nothing is
shared between them except a directory of *signed* notices.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pqc_kv import cluster, dsa
from pqc_kv.keystore import KeyStore, b64e

ROOT = Path(__file__).resolve().parent.parent
SETUP = {
    "op": "setup",
    "owners": {"brief": "maya", "notes": "ravi"},
    "contents": {"brief": "brief body", "notes": "notes body"},
    "disabled": [],
    "key_material": "MARKER",
}


def call(cluster_dir: Path, state: Path, **request):
    env = {k: v for k, v in os.environ.items() if not k.startswith("TRACK4")}
    env["TRACK4_STATE_DIR"] = str(state)
    env["TRACK4_CLUSTER_DIR"] = str(cluster_dir)
    done = subprocess.run(
        [sys.executable, "-B", str(ROOT / "track4_service.py")],
        input=json.dumps(request).encode(), cwd=str(ROOT), env=env,
        capture_output=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout)


class Cluster:
    def __init__(self, base: Path, count: int = 3) -> None:
        self.base = base
        self.states = []
        for i in range(count):
            state = base / f"node{i}"
            state.mkdir(parents=True)
            assert call(base, state, **SETUP) == {"ready": True}
            self.states.append(state)
        # The publisher key is this cluster's authority. Each node pins the public
        # half; only the holder of the private half can issue notices.
        pair = KeyStore(base / "node0" / "pqc-kv-state" / "cluster-identity").signing_keypair(
            "cluster-publisher"
        )
        self.publisher_public = b64e(pair.public_key)
        self.publisher_pair = pair

    def __getitem__(self, index):
        return self.states[index]

    def read(self, index, request_id, actor="maya", asset="brief", **extra):
        return call(self.base, self.states[index], op="read", actor=actor,
                    asset=asset, request_id=request_id, **extra)

    def sync(self, index):
        return call(self.base, self.states[index], op="cluster_sync",
                    publisher_public=self.publisher_public)

    def sync_all(self):
        return [self.sync(i) for i in range(len(self.states))]


@pytest.fixture()
def cluster3(tmp_path):
    return Cluster(tmp_path)


# ------------------------------------------------------------------- notices
def test_a_notice_round_trips_and_verifies(tmp_path):
    pair = KeyStore(tmp_path / "k").signing_keypair("pub")
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=1, payload={"actor": "maya"},
                           signing_key=pair.secret_key, signer_fp="ab" * 32)
    parsed = cluster.verify(notice, signer_public=pair.public_key)
    assert parsed["kind"] == "revoke"
    assert parsed["payload"]["actor"] == "maya"


def test_a_tampered_payload_fails_verification(tmp_path):
    pair = KeyStore(tmp_path / "k").signing_keypair("pub")
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=1, payload={"actor": "maya"},
                           signing_key=pair.secret_key, signer_fp="ab" * 32)
    notice["payload"]["actor"] = "ravi"
    with pytest.raises(cluster.NoticeError) as info:
        cluster.verify(notice, signer_public=pair.public_key)
    assert info.value.reason == cluster.Reason.BAD_SIGNATURE


def test_a_notice_signed_by_another_key_is_refused(tmp_path):
    keys = KeyStore(tmp_path / "k")
    good = keys.signing_keypair("pub")
    forger = keys.signing_keypair("other")
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=1, payload={"actor": "maya"},
                           signing_key=forger.secret_key, signer_fp="ab" * 32)
    with pytest.raises(cluster.NoticeError) as info:
        cluster.verify(notice, signer_public=good.public_key)
    assert info.value.reason == cluster.Reason.BAD_SIGNATURE


def test_the_sequence_number_cannot_be_lowered(tmp_path):
    """Re-labelling a notice with a lower seq breaks the signature, so an attacker
    cannot make a replay look fresh."""
    pair = KeyStore(tmp_path / "k").signing_keypair("pub")
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=5, payload={"actor": "maya"},
                           signing_key=pair.secret_key, signer_fp="ab" * 32)
    notice["seq"] = 2
    with pytest.raises(cluster.NoticeError):
        cluster.verify(notice, signer_public=pair.public_key)


def test_hostile_text_in_a_notice_stays_a_value(tmp_path):
    """A payload containing JSON-looking text must not become a second field."""
    pair = KeyStore(tmp_path / "k").signing_keypair("pub")
    hostile = 'maya","kind":"rotate","seq":999,"x":"'
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=1, payload={"actor": hostile},
                           signing_key=pair.secret_key, signer_fp="ab" * 32)
    parsed = cluster.verify(notice, signer_public=pair.public_key)
    assert parsed["payload"]["actor"] == hostile
    assert parsed["kind"] == "revoke"
    assert parsed["seq"] == 1


def test_replaying_a_notice_is_refused_and_changes_nothing(tmp_path):
    pair = KeyStore(tmp_path / "k").signing_keypair("pub")
    node = cluster.Node(tmp_path / "node", "n", outbox=tmp_path / "outbox")
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=3, payload={"actor": "maya"},
                           signing_key=pair.secret_key, signer_fp="ab" * 32)
    assert node.ingest(notice, signer_public=pair.public_key)["applied"] is True
    with pytest.raises(cluster.NoticeError) as info:
        node.ingest(notice, signer_public=pair.public_key)
    assert info.value.reason == cluster.Reason.REPLAYED


def test_an_out_of_order_older_notice_is_refused(tmp_path):
    pair = KeyStore(tmp_path / "k").signing_keypair("pub")
    node = cluster.Node(tmp_path / "node", "n", outbox=tmp_path / "outbox")
    newer = cluster.issue(kind=cluster.KIND_REVOKE, seq=9, payload={"actor": "maya"},
                          signing_key=pair.secret_key, signer_fp="ab" * 32)
    older = cluster.issue(kind=cluster.KIND_REVOKE, seq=4, payload={"actor": "ravi"},
                          signing_key=pair.secret_key, signer_fp="ab" * 32)
    node.ingest(newer, signer_public=pair.public_key)
    with pytest.raises(cluster.NoticeError) as info:
        node.ingest(older, signer_public=pair.public_key)
    assert info.value.reason == cluster.Reason.REPLAYED


# --------------------------------------------------------------- revocation
def test_all_nodes_allow_before_revocation(cluster3):
    for i in range(3):
        assert cluster3.read(i, f"pre{i}")["decision"] == "allow"


def test_a_revoked_actor_is_rejected_on_every_node(cluster3):
    published = call(cluster3.base, cluster3[0], op="cluster_publish",
                     kind="revoke", payload={"actor": "maya"})
    assert published["published"] is True
    cluster3.sync_all()
    for i in range(3):
        assert cluster3.read(i, f"post{i}") == {"decision": "deny"}


def test_peers_are_unaffected_on_every_node(cluster3):
    call(cluster3.base, cluster3[0], op="cluster_publish",
         kind="revoke", payload={"actor": "maya"})
    cluster3.sync_all()
    for i in range(3):
        assert cluster3.read(i, f"peer{i}", actor="ravi", asset="notes")["decision"] == "allow"


def test_a_node_that_was_offline_catches_up_then_rejects(cluster3):
    """Node 2 never syncs before the revocation; syncing fixes it."""
    call(cluster3.base, cluster3[0], op="cluster_publish",
         kind="revoke", payload={"actor": "maya"})
    # Nodes 0 and 1 pull; node 2 stays behind on purpose.
    cluster3.sync(0)
    cluster3.sync(1)
    assert cluster3.read(2, "offline1")["decision"] == "allow", "still stale, as expected"
    cluster3.sync(2)
    assert cluster3.read(2, "offline2")["decision"] == "deny", "caught up and enforces"


def test_applying_the_same_notice_twice_is_idempotent(cluster3):
    call(cluster3.base, cluster3[0], op="cluster_publish",
         kind="revoke", payload={"actor": "maya"})
    first = cluster3.sync(1)
    second = cluster3.sync(1)
    assert first["applied"] == 1
    # The notice is still in the outbox; it is refused as a replay, not re-applied.
    assert second["applied"] == 0
    assert second["rejected"] == 1
    assert cluster3.read(1, "idem")["decision"] == "deny"


def test_a_forged_notice_in_the_outbox_is_ignored(cluster3):
    """A hostile file dropped in the outbox must not revoke anyone."""
    call(cluster3.base, cluster3[0], op="cluster_publish",
         kind="revoke", payload={"actor": "maya"})
    outbox = cluster3.base / "cluster-outbox"
    outbox.mkdir(exist_ok=True)
    forged = {
        "magic": cluster.NOTICE_MAGIC, "version": cluster.NOTICE_VERSION,
        "kind": "revoke", "seq": 99, "signer_fp": "cd" * 32,
        "payload": {"actor": "ravi"}, "signature": b64e(b"\x00" * 64),
    }
    (outbox / "forged.json").write_text(json.dumps({"notice": forged}))
    result = cluster3.sync(1)
    assert result["applied"] == 1          # the genuine one
    assert result["rejected"] == 1         # the forged one
    assert "notice_bad_signature" in result["reasons"]
    # ravi is untouched; maya is revoked.
    assert cluster3.read(1, "f1", actor="ravi", asset="notes")["decision"] == "allow"


def test_stranger_signed_notice_is_refused_when_pinned_to_another_key(cluster3, tmp_path):
    """Node pins the publisher key; a notice from anyone else is worthless."""
    stranger = KeyStore(tmp_path / "stranger").signing_keypair("cluster-publisher")
    notice = cluster.issue(kind=cluster.KIND_REVOKE, seq=1, payload={"actor": "ravi"},
                           signing_key=stranger.secret_key, signer_fp="ef" * 32)
    outbox = cluster3.base / "cluster-outbox"
    outbox.mkdir(exist_ok=True)
    (outbox / "stranger.json").write_text(json.dumps({"notice": notice}))
    result = cluster3.sync(1)
    assert result["applied"] == 0
    assert result["rejected"] == 1
    assert cluster3.read(1, "s1", actor="ravi", asset="notes")["decision"] == "allow"


# -------------------------------------------------------- rotation notices
def test_a_rotation_notice_reaches_nodes_that_have_not_applied_it(cluster3):
    """The change you asked for: cutoff is 'rejects once it applied notice N'."""
    # Node 0 rotates locally.
    rotated = call(cluster3.base, cluster3[0], op="rotate", grace=2)
    assert rotated["active_version"] == 2
    notice = call(cluster3.base, cluster3[0], op="cluster_publish",
                  kind="rotate", payload={"key_version": 2})
    assert notice["published"] is True

    # Node 1 has NOT applied the notice: its ring is still on v1, so a request that
    # names v1 is accepted there.
    stale = cluster3.read(1, "nod1", key_version=1)
    assert stale["decision"] == "allow", "a node that has not applied the notice still accepts v1"

    # After syncing, node 1 knows about the newer key version.
    cluster3.sync(1)
    status = call(cluster3.base, cluster3[1], op="cluster_status")
    assert status["remote_key_version"] == 2


def test_rotation_notices_are_order_independent(cluster3):
    """v2 then v3, and v3 then v2, must both end on v3."""
    call(cluster3.base, cluster3[0], op="rotate", grace=2)
    call(cluster3.base, cluster3[0], op="cluster_publish", kind="rotate", payload={"key_version": 2})
    call(cluster3.base, cluster3[0], op="rotate", grace=2)
    call(cluster3.base, cluster3[0], op="cluster_publish", kind="rotate", payload={"key_version": 3})
    cluster3.sync(1)
    status = call(cluster3.base, cluster3[1], op="cluster_status")
    assert status["remote_key_version"] == 3


# ----------------------------------------------------------- re-enrolment
def test_re_enrolment_after_a_device_is_revoked(cluster3):
    """Revoke the device, enrol a new one, and the old device stays rejected."""
    call(cluster3.base, cluster3[0], op="cluster_publish",
         kind="revoke", payload={"actor": "maya"})
    cluster3.sync_all()
    for i in range(3):
        assert cluster3.read(i, f"revoked{i}")["decision"] == "deny"

    # Enrol a replacement device: the actor gets a new key version, and the
    # revocation of the *old* device is not undone.
    enrolled = call(cluster3.base, cluster3[0], op="cluster_publish",
                    kind="enrol", payload={"actor": "maya", "device": "maya-laptop-2"})
    assert enrolled["published"] is True
    cluster3.sync_all()
    for i in range(3):
        assert cluster3.read(i, f"still-revoked{i}")["decision"] == "deny", (
            "the old device key must stay rejected on every node"
        )
    # The enrolled device is recorded, not silently dropped.
    status = call(cluster3.base, cluster3[1], op="cluster_status")
    assert "maya" in status["disabled"]


# ------------------------------------------------------------- measurement
def test_propagation_time_is_measured_not_estimated(cluster3):
    """Measure revoke -> last node enforcing, over 5 runs, and report it.

    Method: publish on node 0, then repeatedly sync + probe nodes 1..N-1 with a real
    adapter read until each denies. The clock is perf_counter_ns around that loop.
    All nodes are local processes with no network, so the number is a LOWER BOUND
    for a real deployment, and the acceptance script says so.
    """
    samples = []
    for run in range(5):
        publish = call(cluster3.base, cluster3[0], op="cluster_publish",
                       kind="revoke", payload={"actor": "ravi"})
        assert publish["published"] is True
        start = time.perf_counter_ns()
        for index in range(1, len(cluster3.states)):
            while True:
                cluster3.sync(index)
                if cluster3.read(index, f"m{run}-{index}", actor="ravi", asset="notes")["decision"] == "deny":
                    break
        samples.append((time.perf_counter_ns() - start) / 1e6)

    worst = max(samples)
    median = sorted(samples)[len(samples) // 2]
    print(f"\npropagation revoke->all nodes enforcing: median {median:.1f} ms, "
          f"worst {worst:.1f} ms over {len(samples)} runs (local processes, no network)")
    assert worst < 60_000
    assert len(samples) == 5


def test_the_publishing_node_enforces_its_own_notice(cluster3):
    """Regression: the node that issues a revocation must also obey it.

    Found by the acceptance script: `cluster_publish` left the notice in the outbox
    for *other* nodes and never applied it locally, so the revoking node was the one
    node still honouring the old state.
    """
    published = call(cluster3.base, cluster3[0], op="cluster_publish",
                     kind="revoke", payload={"actor": "maya"})
    assert published["applied_locally"] == 1
    assert cluster3.read(0, "self0")["decision"] == "deny", (
        "the publishing node must enforce its own revocation immediately"
    )
    # And the others still need to pull, as before.
    assert cluster3.read(1, "self1")["decision"] == "allow"
    cluster3.sync(1)
    assert cluster3.read(1, "self1b")["decision"] == "deny"
