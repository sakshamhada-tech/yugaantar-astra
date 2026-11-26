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
