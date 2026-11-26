# yugaantar-astra — Trust, but verify (Track 4)

Post-quantum, zero-trust access control for protected files. One owner reads a
protected synthetic file; after revocation the same owner is denied, a second
owner still reads their own file, and an audit record explains the denial.

**Status: Phases 1 and 2.** Phase 1 is the crypto foundation plus adapter wiring;
Phase 2 adds a secure messaging layer (goals 9–12: replay and recipient binding,
forward secrecy, delivery under loss/reordering, resumption). Later phases
(rotation interface, multi-node revocation, detection, backup) are **not** built.

Everything below that says "Phase 1" is still accurate for Phase 1. Phase 2 has its
own evidence table in section 1b and its own claims in `docs/SECURITY_NOTES.md`
(sections 1–13 of the Phase 2 part), including a list of what it deliberately does
*not* do.

---

## 1. What is implemented

| Phase 1 requirement | Where | Evidence |
| --- | --- | --- |
| ML-KEM-768 keygen / encapsulate / decapsulate | `src/pqc_kv/kem.py` | `tests/test_kem.py` |
| ML-DSA-65 keygen / sign / verify (never raises) | `src/pqc_kv/dsa.py` | `tests/test_dsa.py` |
| HKDF-SHA256 with context labels | `src/pqc_kv/symmetric.py` | `tests/test_hkdf_backends.py` (RFC 5869 vector) |
| AES-256-GCM, fresh nonces, AAD | `src/pqc_kv/aead.py`, `symmetric.py` | `tests/test_aead.py` |
| Hybrid X25519 + ML-KEM | `src/pqc_kv/hybrid.py` | `tests/test_hybrid.py` |
| Envelope `seal()` / `open()` (KEM + HKDF + GCM + signature) | `src/pqc_kv/envelope.py` | `tests/test_envelope.py` |
| Safe key storage (0600/0700, atomic, gitignored) | `src/pqc_kv/keystore.py` | `tests/test_keystore.py` |
| Encrypted-at-rest asset store + hash-chained audit | `src/pqc_kv/store.py` | `tests/test_store.py` |
| Adapter (`setup`/`read`/`revoke`/`audit`/`protected_read`) | `track4_service.py`, `team_app.py` | `tests/test_adapter.py` |

Everything crypto comes from vetted libraries: `pqcrypto` (pqclean bindings for
ML-KEM / ML-DSA), `cryptography` (AES-GCM, HKDF, X25519). **No primitive is implemented here.**

### Repository layout

```
track4_service.py        adapter, copied unmodified from the toolkit starter (exactly one adapter)
team_app.py              our dispatch: policy + crypto, the only team-owned entry logic
threat-model.json        the two contract fields, honestly declared
src/pqc_kv/              the crypto foundation (this is the part a reviewer should read)
  deps.py                runtime backend detection and capability gate
  kem.py dsa.py          ML-KEM-768 / ML-DSA-65 wrappers
  symmetric.py           HKDF-SHA256 + AES-256-GCM (cryptography <-> pycryptodome)
  aead.py                nonce policy, per-key budget, AAD builder
  hybrid.py              X25519 + ML-KEM combined through HKDF
  envelope.py            seal() / open()
  keystore.py            private key files: 0600, atomic, corrupt-safe
  store.py               encrypted asset store, policy, revocation, audit chain
tests/                   140 tests, no network, no shared state
scripts/verify_install.sh clean-machine install + test + validator
scripts/demo_lost_device.py the lost-device walkthrough, with on-disk evidence
docs/SECURITY_NOTES.md   per component: attack stopped, and the limits
docs/PHASE1_REVIEW.md    self-review, desk-review Q&A, checklist coverage
docs/PLATFORM_SUPPORT.md macOS + Linux wheel matrix, what was actually run
Dockerfile               Python 3.12 / linux-amd64 image, offline-capable
.github/workflows/       tests on Linux, organizer validator, docker build
```

---

## 1b. Phase 2 — secure messaging

Two identities, each with a long-term ML-DSA-65 signing key and an ML-KEM-768 key
(fingerprint = SHA-256 over both public keys), run a **three-message signed
handshake** in which both sides sign the same transcript hash. Session keys come from
HKDF over that transcript plus a fresh X25519 secret and a fresh ML-KEM secret, so a
session stays secret even if the long-term keys leak later.

| Goal | What was built | Where | Evidence |
| --- | --- | --- | --- |
| 9. Replay + recipient binding | Header and AAD carry recipient user id *and* fingerprint, sender fingerprint, session id, message id, sequence, fragment index/total, protocol version. Bounded replay set, persisted before plaintext is returned | `messaging/wire.py`, `session.py`, `driver.py` | `test_messaging_wire.py` (41 tests), `test_messaging_driver.py` (30) |
| 10. Forward secrecy | Fresh X25519 + fresh ML-KEM per session, hybrid; both sides sign the full transcript; 3 messages give mutual key confirmation | `messaging/handshake.py`, `hybrid.py` | `test_messaging_handshake.py` (22) |
| 11. Loss / reordering | Each fragment independently authenticated with index+total in AAD; bounded skipped-key cache tolerates out-of-order delivery; incomplete messages are discarded with a reason code and message id, never partial plaintext | `messaging/wire.py`, `kdf.py`, `session.py`, `simnet.py` | `test_messaging_wire.py`, `test_messaging_kdf.py` (15), seeded `simnet` scenarios |
| 12. Session resumption | Ticket bound to the peer fingerprint, ML-DSA proof of possession, fresh root per redemption, single use, budget-based expiry (no trusted clock) | `messaging/resumption.py` | `test_messaging_resumption.py` (14) |

Both layers sit behind the unchanged `track4_service.py`; Phase 2 is exposed as 13
additional `msg_*` operations through the same JSON shim (see `docs/SECURITY_NOTES.md`
section 12 for why additions are allowed and why every failure is one opaque error).

Run the Phase 2 gate:

```sh
python scripts/phase2_acceptance.py
```

It drives **real subprocesses** through `track4_service.py` — one process per request,
exactly as the contract requires — and prints PASS/FAIL per check. Last full run:
**16 passed, 0 failed.**

The headline numbers behind those claims:

* an 11 200-byte body becomes **11 authenticated fragments**; delivering 5 of them
  yields nothing, with `incomplete` and the message id recorded; the rest arriving in
  reverse still reassembles the exact body;
* replaying all 11 fragments yields **0 delivered** and 11 duplicates;
* re-addressing one fragment to another user fails the whole message as
  `wrong_recipient`;
* a Phase 1 `revoke` immediately stops Phase 2 delivery;
* one signature per message, not per fragment — measured at **5.96x wire size and
  ~17x CPU** for the per-fragment alternative (`docs/SECURITY_NOTES.md` section 6).

## 1c. Phase 3 — key lifecycle and log integrity

Goals 1–5: rotation, revocation across nodes, crash recovery, backup integrity, log
integrity. Five new modules, none of which rewrite an earlier phase.

| Goal | Module | What it does | Evidence |
| --- | --- | --- | --- |
| 1. Key rotation | `keyring.py` + `store.rotate()` | Versioned ring (active/retiring/retired/revoked). Rotation re-wraps every asset then retires the old version. The cutoff is a **count of accepted requests**, not wall time | `tests/test_phase3_rotation.py` (28) |
| 2. Revocation across nodes | `cluster.py` | ML-DSA-signed, sequence-numbered notices. Signature checked before the payload is parsed. Idempotent, order-independent apply | `tests/test_phase3_cluster.py` (19) |
| 3. Crash recovery | `intent.py` | `intent → re-wrap → commit → clear`; recovery lands on exactly one version. Fault hook kills real subprocesses at 5 named points | `tests/test_phase3_recovery.py` (21) |
| 4. Backup integrity | `backup.py` | GCM + ML-DSA over manifest *and* ciphertext; operator-supplied key; rollback refused via monotone high-water marks | `tests/test_phase3_backup.py` (32) |
| 5. Log integrity | `logsign.py` | Signed, hash-chained key-event log with strict identifier validation; head exportable for external anchoring | `tests/test_phase3_log.py` (28) |

New adapter ops (all additive; `track4_service.py` is untouched): `rotate`,
`key_status`, `recover`, `cluster_publish`, `cluster_sync`, `cluster_status`,
`backup_create`, `backup_restore`, `log_head`, `log_events_head`, `log_events_verify`.

### Run the Phase 3 demo and gate

```sh
python scripts/phase3_acceptance.py
```

Drives **real subprocesses** through `track4_service.py` and prints PASS/FAIL per goal.
Last full run: **26 passed, 0 failed.**

Numbers it prints, all measured (`perf_counter_ns`, not estimated):

```sh
python -m pytest tests/test_phase3_rotation.py -q -s | grep "rotation of"
python -m pytest tests/test_phase3_cluster.py  -q -s | grep "propagation"
```

* rotation re-wrapping 20 assets: **67–97 ms** across six runs (~3.4–4.8 ms/asset)
* revoke → **last** node of 3 enforcing: **median 324–360 ms**, worst 363 ms across
  runs. Lower bound: every "node" is a local directory and a subprocess, with no
  network delay, so most of this is process startup.
* crash recovery after a real `os._exit(97)`: **92.9 ms** worst case
* backup: 8/8 single-bit mutations refused; stale replay refused
* log: 406 hostile strings fuzzed, **0** forged events

### Try the attacks yourself

```sh
# what a revoked actor sees on each node, before and after syncing
python -m pytest tests/test_phase3_cluster.py::test_a_node_that_was_offline_catches_up_then_rejects -q -s

# kill the process mid-rotation at every named point, then recover
python -m pytest tests/test_phase3_recovery.py -q

# flip one bit in each backup region and watch all of them get refused
python -m pytest tests/test_phase3_backup.py -q
```

### What Phase 3 does not fix

Keys still sit beside the data — there is no KMS, no HSM, and no at-rest wrapping, so
the state directory remains the trust boundary. The log's signing key lives in that
same directory, so someone who can rewrite the log *and* read the key is undetectable;
without an external anchor, truncation is invisible. The high-water marks that stop
backup rollback are in the directory the backup protects. All simulated nodes share one
machine, so no real network partition was tested. Full list in
`docs/SECURITY_NOTES.md` §P3-7. The mutation log is `docs/BREAK_IT.md`.

## 1d. Phase 4 — detection (goals 6, 7, 8)

Rule-based, explainable and deterministic. **No model, no weights, no learning**: every
alert is a conjunction of facts a judge can re-derive by hand from the log and the
approval file.

| Goal | Module | What it does | Evidence |
| --- | --- | --- | --- |
| 6. Routine vs suspicious | `detect/privilege.py` + `detect/context.py` | A privilege change is suspicious when no approval covers subject, role, window and signer. The alert names the fact that failed | `tests/test_phase4_rules.py` (29) |
| 7. Lateral movement | `detect/lateral.py` | Per-identity service graph from a baseline period; flags first-seen edges and chains that leave a freshly-reached service, even when credentials are valid | `tests/test_phase4_lateral.py` (28) |
| 8. Clock differences | `detect/timing.py` | Per-source offset correction with a stated uncertainty. An order is claimed only when the gap exceeds the combined uncertainty; otherwise `order="uncertain"` | `tests/test_phase4_timing.py` (25) |

Plus `detect/ingest.py` (strict, counted rejection of hostile lines, 156 tests),
`tests/test_phase4_properties.py` (28 determinism/config/injection tests),
`detect/alerts.py` (closed schema, content-derived ids) and `detect/config.py` (every
threshold in one validated place).

New adapter ops, all additive — `track4_service.py` is still byte-identical:
`detect_log` (whole log in one request), `detect_append` (persists a baseline under
`TRACK4_STATE_DIR`), `detect_status`. High-severity findings are also written into the
Phase 3 **signed** key-event log, so a detection becomes tamper-evident.

### Is Phase 4 complete? Run the acceptance gate

```sh
python scripts/phase4_acceptance.py
```

Drives `track4_service.py` as **real subprocesses** and prints PASS/FAIL per goal.
Last full run: **29 passed, 0 failed.** Exit code is non-zero if anything fails, so it
can be used as a gate. What it checks:

| Group | Checks |
| --- | --- |
| goal 6 | unapproved change reported; approved one quiet; wrong-role ticket refused; self-approval refused; every alert explains itself; two different failures name two different missing facts |
| goal 7 | a 3-hop chain over **valid** credentials is reported; the alert records the path, not a count |
| goal 8 | an event on its validity boundary answers `uncertain` and names **both** possible orders; the same change well inside the window is settled and quiet |
| determinism | two separate processes produce byte-identical reports; no timestamp in the report |
| hostile input | 6 hostile values quarantined; none echoed; a broken approvals file is *named*, not silently treated as "no change control" |
| persistence | `detect_append` persists a baseline; a second process reads it back; `detect_status` states the timing range |
| contract | unknown op → `unsupported_operation`; `detect_log` with no log → `malformed_request` |
| signed log | high-severity findings land in the Phase 3 signed log and the chain still verifies |
| config | a different `min_novel_edges` changes the result, so the number is really read; a negative one is refused |

It checks behaviour and contract, **not accuracy** — accuracy is a claim about a corpus,
so it lives in the evaluation below. The gate caught a deliberately broken role check
when I tested it (27/29, exit 1), so it is not passing vacuously.

### Run the tests and the evaluation on a clean machine

```sh
python -m pytest -q                              # whole suite
python -m pytest tests/test_phase4_*.py -q       # Phase 4 only: 286 tests
python scripts/phase4_eval.py --practice /path/to/Track-4-Toolkit/practice
python scripts/phase4_synth.py --out /tmp/synth  # MESSY synthetic log, fixed seed
python scripts/phase4_eval.py --synthetic /tmp/synth
```

`phase4_eval.py` prints its own method next to every number — how an alert is matched to
a label, what precision is computed over, and that the headline time-to-alert is 0 by
construction. Read that before the figures.

Measured on the synthetic log (276 events): **20 alerts, all 20 true positives, 12 of 13
incidents detected, 0 false alerts per 1,000 benign events**. The one miss is deliberate:
an attacker who behaves badly *during* the baseline is not novel afterwards, and that
limit is measured rather than described. Practice data: 3 alerts, 3 hits — a functional
check only, because 22 events cannot establish accuracy.

Throughput, `python scripts/measure_timing.py /tmp/big/events.csv` on a 100 023-event
log: **36 944 events/second**, **173 MB peak RSS**, on 2 CPUs / Python 3.11.

### Try the rules yourself

```sh
# take one rule away and watch exactly which tests and metrics drop
python scripts/phase4_mutate.py --log /tmp/synth/events.csv \
    --approvals /tmp/synth/approvals.json --tests

# the uncertain-order answer, when two clocks cannot settle a sequence
python -m pytest tests/test_phase4_rules.py::test_a_change_in_the_clock_shadow_of_the_bound_is_uncertain_not_judged -q -s
```

### What Phase 4 does not fix

This is good at unusual **shape** and blind to unusual **purpose**. An attacker who
stays inside an identity's established service edges is invisible to the lateral rules,
and an approval record is a *claim*: compromise an approver, or file a real ticket, and
the privilege rules pass. Precision of 1.000 is precision on my own synthetic corpus.
Full list in `docs/SECURITY_NOTES.md` §P4-7; rules, evasions and measurements in
`docs/DETECTION.md`.

## 1e. Phase 5 — messaging goals 9-12, attacked rather than asserted

Phase 2 built these four features; Phase 5 exists because the brief states them as
*attacks to survive*, not features to have. Each check below mounts the attack the
brief names and shows the system refusing it. Nothing new was needed in the protocol —
what was missing was proof, and in three places the proof was genuinely absent.

```sh
python scripts/phase5_acceptance.py
```

Real subprocesses through `track4_service.py`, one per request. Last run:
**17 passed, 0 failed.** Exit code is non-zero on failure.

| Goal | The brief's sentence | How it is tested |
| --- | --- | --- |
| 9. Replay + recipient binding | "rejects duplicate messages and messages whose authenticated recipient information has changed" | recipient user and fingerprint are rewritten and each must fail **as `wrong_recipient`**, not merely fail; the genuine fragments still deliver afterwards; a full replay delivers 0 and counts 5 duplicates |
| 10. Forward secrecy | "later exposure of a long-term identity key alone does not reveal earlier sessions" | complete a session, then derive the root holding **every** long-term secret of both parties plus the full public transcript, and show no root or chain key matches |
| 11. Delivery under loss | "delivers complete, authenticated messages when recovery succeeds; discards incomplete ones and reports failures" | half the fragments → 0 delivered with `incomplete` and the message id; the rest reversed → exact body; a forged fragment is *reported*, and must not desynchronise the ratchet |
| 12. Session resumption | "a different identity cannot inherit the session by presenting the same session identifier" | a thief holding the ticket **and** the session id, with its own key, is refused; a genuine ticket against another session id is refused; the right peer resumes and the spent ticket is deleted |

### Why Phase 5 needed new tests, not just a new gate

The Phase 2 suite passed 181 tests before this phase and still had three real holes,
each at the point the brief is most adversarial:

1. **Goal 10 had no test at all.** The suite tested that ephemeral files get erased —
   the *mechanism* — and never tested that earlier sessions stay unreadable — the
   *property*. A build that erased the files but derived the root from long-term keys
   would have passed everything. `tests/test_messaging_forward_secrecy.py` now mounts
   the derivation with forged inputs and compares roots.
2. **Goal 11's tamper tests asserted only `delivered == []`.** A receiver that silently
   dropped a forged message and one that reported `signature_invalid` with a message id
   were indistinguishable. The brief asks for the second.
3. **Goal 12 never tested the attack the brief names.** Wrong-key and wrong-peer cases
   were covered; a thief holding *both* the ticket and the session id was not.

### Two mistakes this phase caught in its own tooling

Both are recorded because they were the kind that produce a false PASS:

* A **shallow** `dict(f)` copy meant "forging" a fragment also rewrote the genuine one,
  so a correct detector appeared to lose messages. Fixed with `deepcopy`.
* The goal-9 check accepted **any** failure reason. With recipient binding deleted
  outright, the message still failed — as `signature_invalid` — and the gate still
  reported 17/17. It now requires the specific reason, and deleting the check drops it
  to 15/17. A gate that accepts any failure measures nothing.

## 1f. Phase 6 — red team: we attacked our own adapter first

The live security assessment attacks this system. Rather than wait for that, the
attacks are written down and run as a gate:

```sh
python scripts/redteam.py           # 36/36 attacks held
python scripts/phase6_acceptance.py # 12/12, incl. proving the fix by removing it
```

Every check is an attack that **succeeded against an earlier build** or is a standard
attack on a system of this shape. Three succeeded and are now fixed:

| # | Severity | Attack | Before | After |
| --- | --- | --- | --- | --- |
| F1 | **high** | delete / empty / truncate / corrupt an asset file, then read it | `exit 1`, **empty stdout** — a protocol violation, on four separate corruptions | `{"decision": "deny"}` |
| F1b | high | corrupt `keyring.json`; replace the state directory with a file | crash on `read`; crash on **every** KV operation | refusal, opaque |
| F2 | low–med | `ls -l` | `audit.jsonl` at **0644** while the ciphertext was 0600 — a recon map of who was denied what | every state file 0600, asserted by walking the tree |

**F1's root cause is worth stating** because it is the kind of bug that reads as harmless
and is not: the project has two sibling exception hierarchies, `StoreError` and
`KeyStoreError`, and neither subclasses the other. Any path that reads key material can
raise an exception the store's handlers do not catch, so the process exits 1 with nothing
on stdout. Three separate sites did this.

After the fix, a sweep of **12 disk corruptions × 12 operations = 144 combinations**
produces zero crashes (`redteam.py` covers the same ground as a standing gate).

### The one attack that still works, stated plainly

**Rewriting `state.json` grants access.** Change `owners.brief` from `maya` to `ravi`
and `ravi` reads the asset. The envelope still cannot be forged — the AAD binds it and
the GCM tag fails — but *the policy that decides who may open it lives beside the keys
that open it*. This is the trust boundary, the same one as in every earlier phase, and
`redteam.py` prints it as a statement rather than a failure so there is no pretence it
was fixed. Mitigation is deployment: state directory owned by the service user, `0700`,
on a host the attacker does not already control. Under the organizer's sandbox the state
directory is fresh per run.

### What is explicitly out of scope

Root or code execution as the service user · a modified interpreter or injected package ·
sub-millisecond side channels across a process boundary (measured: a deny for an existing
asset is 1.2× an unknown one *in-process*, and ~75 ms of process startup dominates the
real request) · JSON nested past the interpreter's recursion limit, which the
organizer's own `json.loads` refuses before our code runs · DoS by message volume, which
the sandbox prohibits by policy and the wire format bounds at 67 107 840 bytes.

### The second pass: attacking the classes the first pass missed

The first 23 attacks went after authorization and the wire format. The second pass went
after races, crashes, rollback, parser confusion and the log — and found one serious bug
of our own.

**A shortened log verified as intact.** `log_events_verify` returned `ok: true` after
deleting the last record from `key-events.jsonl`, and `ok: true` after emptying the file
completely. Deleting the newest record is exactly how an attacker removes the trace of the
change they just made, and a hash chain cannot see it: truncation yields a *shorter valid
chain*. The anchor now lives in `state.json`, stamped into the same atomic write as the
event that produced it, and the report says whether an anchor was used
(`anchor_checked`). Truncation now returns `head_mismatch`; a log with no anchor available
says so rather than implying it is intact.

The 799-test suite did not catch this, because every test asserted that *tampering* was
caught and none asserted that *removal* was. So the new regression test is verified by
un-fixing the code and requiring it to fail — and `phase6_acceptance.py` re-runs that
check every time, so the test cannot quietly stop testing anything.

| Second-pass attack | Result |
| --- | --- |
| 12 concurrent reads sharing one `request_id` | exactly 1 allow, 11 deny |
| 12 readers racing a revocation | 0 allow, 12 deny |
| 40 `SIGKILL`s mid-revoke | 0 unusable states, 0 leftover temp files |
| duplicate JSON keys to escalate an actor | last key wins; the non-owner value is what is evaluated |
| Cyrillic / ZWSP / fullwidth / BOM look-alike identities | all denied — compared as exact bytes, never normalised |
| `NaN`, `Infinity`, typed `request_id` | refused without a crash |
| symlink planted at a rotate target | rotate refused; nothing written outside the directory |
| **truncate or empty the signed log** | **was `ok: true` → now `head_mismatch`** |
| reorder / edit / duplicate / forge a record | `chain_broken` |

**Still undefeated, and stated as such: rollback of the state directory.** Restoring a
snapshot taken before a revocation brings the revocation back off. No counter inside the
directory can prevent this — the attacker is rewinding the directory itself — so it needs
a TPM counter, a remote witness or an off-host ledger, none of which a single-container
submission has. It costs **policy**, not **confidentiality**: the AEAD binds asset and
owner identity, so an old directory cannot be replayed to read a body as someone else. An
operator verifying the key-event log with an externally held anchor sees the rollback,
because the restored log is shorter than the anchor says.

Full detail is in `docs/SECURITY_NOTES.md` §P6-1…P6-8.

## 1g. Seeing it work: `python scripts/dashboard.py`

Every result in this repository is text in a terminal, which makes the system hard to see.
One command serves a page that drives the **real adapter** — one process per request, the
same way the judge drives it:

```sh
python scripts/dashboard.py --open    # http://127.0.0.1:8000
```

Six panels: access decisions (including a revocation taking effect on the next request),
the ML-KEM protected read (ciphertext and HMAC proof, with the plaintext provably absent),
end-to-end messaging (deliver, re-address to the wrong recipient, replay every fragment),
detection over a sample log, signed-log verification in healthy and truncated states, and
the 36-attack red-team gate.

**No UI is required by the brief** — the submission is a two-page PDF plus a five-minute
video, and no interface is scored. The dashboard exists because a reviewer who clicks a
button and watches access flip to deny knows more than one who reads "revocation:
verified". It is stdlib-only, read-only, loads nothing from the network, and runs against
throwaway state directories under a temp path, so it cannot be why a demo fails in an
offline container. `tests/test_dashboard.py` holds it to the adapter's answers so the page
cannot drift into showing something the system would not actually do — that test caught a
real drift while it was being written.

## 2. Clean-machine setup (tested)

Tested on Linux x86_64 with CPython 3.11 and 3.12; the judging runtime is
Python 3.12. Nothing below needs network access at run time, only at install time.

**On macOS:** one check in `scripts/phase1_acceptance.py` needs `unshare`, which is
Linux-only. On a Mac it reports **SKIP** with the reason, not FAIL and not PASS — a
missing capability is not a security finding, and calling it a failure would teach you
to ignore failures. Everything else runs normally. To verify the container contract on
a Mac, use `docker run --rm --read-only --tmpfs /tmp <image>`; see
`docs/PLATFORM_SUPPORT.md`.

```sh
git clone <this repo> && cd yugaantar-astra

python3.12 -m venv .venv          # 3.12 matches the judging runtime
. .venv/bin/activate
pip install --only-binary=:all: \
  -r requirements.lock -r requirements-dev.lock   # fully pinned; wheels only

# 1. run the tests
PYTHONPATH=src:. python -m pytest tests -q
#    -> 139 passed, 1 skipped   (the skip needs a pycryptodome-only environment)

# 2. walk the lost-device scenario
python scripts/demo_lost_device.py

# 3. run the official validator from the toolkit folder (toolkit NOT in this repo)
cd /path/to/Track-4-Toolkit
python validate.py --entry /path/to/yugaantar-astra/track4_service.py
```

One command does all three (toolkit path optional):

```sh
./scripts/verify_install.sh /path/to/Track-4-Toolkit
```

### Is Phase 1 actually done? Run the acceptance gate

```sh
python scripts/phase1_acceptance.py --toolkit /path/to/Track-4-Toolkit
```

It runs — not describes — 13 checks and prints PASS/FAIL/SKIP per line, exiting
non-zero if anything fails. Skips are listed separately so they are never read as
green. Last full run in this repo: **12 passed, 0 failed, 1 skipped** (the skip is
"interpreter is 3.12", because the sandbox here is 3.11).

The individual checks, if you prefer to run them by hand:

```sh
PYTHONPATH=src:. python -m pytest tests -q                    # 139 passed, 1 skipped
cd /path/to/Track-4-Toolkit && python validate.py --entry /path/to/yugaantar-astra/track4_service.py
                                                              # 22 PASS, 0 FAIL
python scripts/demo_lost_device.py                            # plaintext at rest: none
./scripts/verify_container_contract.sh /path/to/Track-4-Toolkit  # read-only rootfs
```

### Docker (Python 3.12, linux/amd64)

```sh
docker build --platform linux/amd64 -t pqc-kv:phase1 .

# tests inside the image
docker run --rm pqc-kv:phase1 python -m pytest tests -q

# the adapter exactly as the judge runs it: read-only root, temp-only state
printf '%s' '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo"}}' \
  | docker run --rm -i --read-only --tmpfs /tmp pqc-kv:phase1

# organizer validator against the image (toolkit mounted, never copied in)
docker run --rm -v /path/to/Track-4-Toolkit:/toolkit:ro \
  -v "$PWD/track4_service.py:/toolkit/track4_service.py:ro" \
  -v "$PWD/team_app.py:/toolkit/team_app.py:ro" \
  -v "$PWD/src:/toolkit/src:ro" --tmpfs /tmp \
  pqc-kv:phase1 python /toolkit/validate.py --entry /toolkit/track4_service.py
```

The image installs only prebuilt wheels (`PIP_ONLY_BINARY=:all:`), bakes every
dependency in for offline judging, runs as UID 10001, and deliberately leaves
`TRACK4_STATE_DIR` unset so the default path is the OS-temp fallback the judge uses.

If you have no Docker, `./scripts/verify_container_contract.sh <toolkit>` reproduces
the same contract locally: read-only code directory, temp-only state, wheels-only
install, full suite and the validator.

### Expected outputs

Validator, current state of this repo (**22/22 PASS, exit 0**):

```
PASS [format] clean setup
PASS [setup] clean setup
PASS [format] owner before device loss
PASS [behavior] owner before device loss
PASS [format] peer before device loss
PASS [behavior] peer before device loss
PASS [format] wrong owner
PASS [behavior] wrong owner
PASS [format] revoke lost-device owner
PASS [format] owner after revocation
PASS [behavior] owner after revocation
PASS [format] audit revoked read
PASS [behavior] audit revoked read
PASS [format] unaffected peer
PASS [behavior] unaffected peer
PASS [format] revocation persists across processes
PASS [behavior] revocation persists across processes
PASS [behavior] fake key stays out of output
PASS [format] fresh rerun setup
PASS [setup] fresh rerun setup
PASS [format] fresh rerun owner
PASS [behavior] fresh rerun owner
Local scenario passed.
```

Demo (abridged) — note that no plaintext and no key material appears on disk:

```
2. what the disk actually holds
  asset-29a8825bd242f143.env: suite=pqc-kv/v1/envelope mode=kem ct=BVqmjMDzkHKf... sig=OS3zTM68mAJI...
  plaintext files found              none
3. maya reads brief    {"decision": "allow", "rule": "owner_allowed", "body": "Synthetic board brief: Q4 numbers."}
6. maya reads brief    {"decision": "deny", "rule": "identity_revoked"}
7. audit r03           {"request_id": "r03", "decision": "deny", "rule": "identity_revoked", "explanation": "Denied: the actor's access was revoked..."}
8. ravi reads notes    {"decision": "allow", "rule": "owner_allowed", "body": "Synthetic peer note: launch checklist."}
```

---

## 3. Dependencies and why these

**Cross-platform:** every pin has a prebuilt wheel for CPython 3.12 on
linux/amd64, linux/arm64 and macOS arm64 — no compiler on either your Mac or the
judge's Linux box. Full matrix and caveats: `docs/PLATFORM_SUPPORT.md`.

| Package | Version | Used for | Why this one |
| --- | --- | --- | --- |
| `pqcrypto` | `0.4.0` | ML-KEM-768, ML-DSA-65 | **The exact pinned version the judging container ships.** pqclean C implementations of the NIST standards (FIPS 203 / 204), prebuilt wheels, no compiler needed. |
| `cryptography` | `46.0.4` | AES-256-GCM, HKDF-SHA256, X25519 | Widely deployed, audited, constant-time primitives; abi3 wheels for Python 3.9+. |
| `pycryptodome` | `3.23.0` (optional) | same surfaces as `cryptography` | Fallback only. Used automatically if `cryptography` is absent; verified by running the full suite with it (140 passed). |
| `pytest` | `9.0.1` | tests | dev only; in the image because the image is also where we run the suite. |

The build refuses source builds: `PIP_ONLY_BINARY=:all:` is set in the `Dockerfile`
and passed on the command line in the docs, so a missing wheel fails loudly at
install time instead of silently dragging in a compiler.

**Choice: Python 3.12 + `pqcrypto==0.4.0` + `cryptography==46.0.4`.**

Why Python over Node: the judge's PQC pin exists for Python (`pqcrypto==0.4.0`),
and there is no third-party dependency to install at judging time — one less thing
to go wrong on a read-only container. Node's `@noble/post-quantum` (0.7.1) is a
pure-JS ML-KEM/ML-DSA implementation and is the **fallback language** if the Python
runtime ever disappears; it would need no native build either.

**Fallback crypto path (already implemented, not theoretical):**
`src/pqc_kv/deps.py` detects at runtime what is importable.
1. `cryptography` present -> use it.
2. absent -> `pycryptodome` (full suite passes in that configuration).
3. neither -> HKDF still works from the Python standard library (`hmac` +
   `hashlib` composition, pinned to RFC 5869 vectors), and AES-GCM/X25519 report
   `Unavailable` and the adapter refuses to claim an encrypted service
   (`{"error": "crypto_backend_unavailable"}`) rather than inventing a cipher.

---

## 4. How the crypto fits together

Sealing one asset body:

```
ML-KEM-768 encapsulates to the store's public key  -> shared_secret (32B)
        + HKDF-SHA256(shared_secret, label)        -> AES key (32B)
        + fresh 96-bit nonce from os.urandom
        + AES-256-GCM(plaintext, key, nonce, AAD)  -> ciphertext + 16B tag
        + ML-DSA-65 sign(header || nonce || ct || tag || kem_ct)
        = envelope written to disk as JSON/base64
```

Opening reverses it, verifying the signature **before** spending work on key
derivation, and rebuilding the AAD from the identifiers rather than trusting the
ones on the wire. Every failure path raises one opaque `EnvelopeError`.

Hybrid mode (`mode="hybrid"`) replaces the KEM step with
X25519 + ML-KEM-768 combined through HKDF over `transcript || x25519_ss ||
len(mlkem_ss) || mlkem_ss`. Removing either component changes the key.

---

## 5. How the adapter works

* **Process model.** One process per request, JSON on stdin, one JSON object on
  stdout, diagnostics on stderr, exit 0. All state is read from and written to
  `TRACK4_STATE_DIR`, falling back to `os.tmpdir()` — verified with the code
  directory mounted **read-only** and no state variable set.
* **setup** rotates the installation keys (so each setup's AES-GCM nonce budget is
  honest even though the process dies after every request), seals every body into
  `assets/*.env`, and seals the synthetic `key_material` to a file with **no read
  path at all**. Returns `{"ready": true}`.
* **read** evaluates policy, opens the envelope it needs, and returns
  `{"decision":"allow","rule":"owner_allowed","body":"<exact body>"}` or
  `{"decision":"deny","rule":"…"}` with **no body and no hint** about the asset.
  Decisions are appended to a hash-chained audit log before the state is written.
* **revoke** appends the actor to `disabled`, persists (atomic rename + fsync) and
  returns `{}`. Peer permissions are untouched.
* **audit** returns the recorded `request_id`, `decision`, plus `rule`,
  `explanation`, `actor`, `asset`, `ts` and the record's chain hash.
* **protected_read** checks the same policy, then encapsulates to the caller's
  base64 raw ML-KEM-768 public key and returns the KEM ciphertext plus
  lowercase-hex HMAC-SHA-256 over `challenge + body`. The shared secret never
  leaves the process.

---

## 6. Known limitations (asserted honestly, not hidden)

1. **Identity is a string, not an authenticated session.** The adapter contract
   passes `actor` as an opaque value; we authorize it but cannot prove the caller
   *is* that actor. A real deployment needs an authenticated channel in front.
2. **Keys live in the state directory.** That is what the contract allows (the
   root filesystem is read-only and there is no KMS). File permissions protect
   against other users, not against a process running as the same user.
3. **The audit chain has no external anchor.** It detects edits and deletions
   *inside* the file; an attacker who rewrites every record and recomputes the
   chain is not detected. Goal 5 (log integrity) is therefore **partial**.
4. **Single node, single writer.** A `flock` serialises writers, so no torn state,
   but there is no multi-node revocation (goal 2 is untested), no replication.
5. **No forward secrecy for *stored* assets.** Each asset envelope uses a static
   recipient key, so compromising that key after the fact can decrypt stored assets.
   That is unchanged in Phase 2. Messaging sessions **are** forward secret (goal 10)
   because they derive keys from fresh X25519 + ML-KEM secrets that are then erased —
   but a stored file has no "after the fact" to protect, so the envelope stays static.
6. **No replay protection on `protected_read`.** The challenge is echoed into the
   HMAC but nothing tracks seen challenges. Messaging **does** track them (goal 9):
   replay is bounded by a persisted 4096-entry set and state is written before
   plaintext is returned. The two paths are separate and the weaker one is the
   adapter's own op.
7. **Nonce budget accounting resets every process.** Bounded by rotating keys on
   each setup, so a key never seals more than one setup's assets (far below the
   2^20 in-process limit). A long-running deployment needs a persisted counter.
8. **No constant-time guarantees on our own Python glue.** We use `hmac.compare_digest`
   for comparisons and library primitives for crypto, but Python cannot promise
   constant time overall.
9. **Not built on purpose in Phase 1:** key rotation interface (goal 1),
   multi-node revocation (2), backup/restore (4), detection (6, 7, 8).
   **Built in Phase 2:** messaging replay and recipient binding (9), forward secrecy
   for sessions (10), delivery under loss/reordering (11), resumption (12) — all with
   the caveats in section 1b and `docs/SECURITY_NOTES.md` section 13. Resumption's
   expiry is a redemption budget, not a clock, because no clock here can be trusted.

---

## 7. Scenario and threat model in one paragraph

Asset: synthetic file bodies stored on disk. Trust boundary: the adapter's
`read`/`protected_read` decision — everything before it is transport, everything
after it is crypto. Adversaries considered: someone who can read the state
directory as another user, someone who can modify files on disk, an unauthorized
actor asking for someone else's asset, and a revoked actor retrying. Defence:
contents are useless without the ML-KEM secret key; every modification is caught
by the AES-GCM tag or the ML-DSA signature; authorization is enforced before any
decryption and every decision is logged with the rule that produced it. The
largest remaining risk is that possession of the state directory equals access to
the keys — acceptable for a hackathon demo on a trusted host, unacceptable for
production without a KMS.

---

## 8. Toolkit separation

The organizer toolkit is **not** in this repository and must not be added. Our
adapter is the unmodified starter file; our logic lives in `team_app.py` and
`src/pqc_kv/`. `scripts/verify_install.sh` expects the toolkit path as an argument.
