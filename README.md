# yugaantar-astra — Trust, but verify (Track 4)

**Team Name: Astra**

**Team Members:**
1. Anurag Tiwari(Team Leader)
2. Saksham Hada
3. Shivam Kumar Gupta

Post-quantum, zero-trust access control for protected files. An owner reads a protected
synthetic file; after revocation the same owner is denied, a second owner still reads their
own file, and an audit record explains the denial.

All twelve goals are built, attacked and gated. **834 tests pass, 38 attacks against our
own shipped adapter are refused, and the organizer validator passes 22/22.**

| | |
| --- | --- |
| Status | Phases 1–6 complete; all 12 goals implemented |
| Tests | 834 passed, 3 skipped (`PYTHONPATH=src:. python -m pytest tests -q`) |
| Red team | 38/38 attacks held (`python scripts/redteam.py`) |
| Validator | 22/22 PASS, exit 0 |
| Adapter | `track4_service.py` byte-identical to the organizer starter |
| Runtime | Python 3.12, `pqcrypto==0.4.0`, `cryptography==46.0.4` |

---

## Quick start

```sh
git clone <this repo> && cd yugaantar-astra
git clone --depth 1 https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git ../Track-4-Toolkit

python3.12 -m venv .venv && . .venv/bin/activate
pip install --only-binary=:all: -r requirements.lock -r requirements-dev.lock

./scripts/verify_all.sh ../Track-4-Toolkit     # everything CI runs: 16 steps
```

`verify_all.sh` runs the same sixteen steps as the CI `tests` job, in order: the suite, the
lost-device walkthrough, phases 2/3/5/4/6 acceptance, the crash-recovery kills, the
38-attack red team, the phase 4 evaluation and mutation check, phase 1, the organizer
validator, and a byte-identity check on the starter. It sets `PYTHONPATH` once, keeps going
after a failure so one run shows every problem, and exits non-zero if anything failed. Pass
it no argument and it clones the toolkit to a temp directory.

**See it work:** `python scripts/dashboard.py --open` — a stdlib-only page that drives the
real adapter, one process per request, in six panels.

---

## What is implemented

| Goal | Module | What it does | Evidence |
| --- | --- | --- | --- |
| 1. Key rotation | `keyring.py`, `store.rotate()` | Versioned ring (active/retiring/retired/revoked). Rotation re-wraps every asset, then retires the old version. The cutoff is a **count of accepted requests**, not wall time | `test_phase3_rotation.py` (28) |
| 2. Revocation across nodes | `cluster.py` | ML-DSA-signed, sequence-numbered notices; signature checked before the payload is parsed; idempotent, order-independent apply | `test_phase3_cluster.py` (19) |
| 3. Crash recovery | `intent.py` | `intent → re-wrap → commit → clear`; recovery lands on exactly one version. Fault hook kills real subprocesses at 5 named points | `test_phase3_recovery.py` (21) |
| 4. Backup integrity | `backup.py` | GCM + ML-DSA over manifest *and* ciphertext; operator-supplied key; rollback refused via monotone high-water marks | `test_phase3_backup.py` (32) |
| 5. Log integrity | `logsign.py` | Signed, hash-chained event log with strict identifier validation; head exportable for external anchoring, and remembered in `state.json` so truncation is caught | `test_phase3_log.py`, `test_log_truncation.py` |
| 6. Routine vs suspicious | `detect/privilege.py`, `detect/context.py` | A privilege change is suspicious when no approval covers subject, role, window and signer. The alert names the fact that failed | `test_phase4_rules.py` (29) |
| 7. Lateral movement | `detect/lateral.py` | Per-identity service graph from a baseline period; flags first-seen edges and chains leaving a freshly-reached service, even with valid credentials | `test_phase4_lateral.py` (28) |
| 8. Clock differences | `detect/timing.py` | Per-source offset correction with stated uncertainty. An order is claimed only when the gap exceeds combined uncertainty; otherwise `order="uncertain"` | `test_phase4_timing.py` (25) |
| 9. Replay + recipient binding | `messaging/wire.py`, `session.py` | Recipient user id *and* fingerprint, sender, session, message id, sequence and fragment index/total all in the AAD; bounded replay set persisted before plaintext is returned | `test_messaging_wire.py` (41) |
| 10. Forward secrecy | `messaging/handshake.py`, `hybrid.py` | Fresh X25519 + fresh ML-KEM per session; both sides sign the full transcript; ephemeral secrets erased once the root exists | `test_messaging_forward_secrecy.py` |
| 11. Loss / reordering | `messaging/wire.py`, `kdf.py` | Each fragment independently authenticated with index+total in AAD; bounded skipped-key cache; incomplete messages discarded with a reason code and message id, never partial plaintext | `test_messaging_kdf.py` (15), seeded `simnet` scenarios |
| 12. Session resumption | `messaging/resumption.py` | Ticket bound to the peer fingerprint, ML-DSA proof of possession, fresh root per redemption, single use, budget-based expiry (no trusted clock) | `test_messaging_resumption.py` (14) |

Phase 1 — the crypto foundation — is `kem.py`, `dsa.py`, `symmetric.py`, `aead.py`,
`hybrid.py`, `envelope.py`, `keystore.py` and `store.py`. Every primitive comes from
vetted libraries: `pqcrypto` (pqclean bindings for ML-KEM / ML-DSA) and `cryptography`
(AES-GCM, HKDF, X25519). **No primitive is implemented here.**

New adapter operations are all additive — the starter file stays byte-identical:
`rotate`, `key_status`, `recover`, `cluster_*`, `backup_*`, `log_head`,
`log_events_head`, `log_events_verify`, `detect_*`, and 13 `msg_*` operations.

---

## Repository layout

```
track4_service.py        adapter, copied unmodified from the starter (exactly one adapter)
team_app.py              our dispatch: policy + crypto, the only team-owned entry logic
threat-model.json        the two contract fields, honestly declared
src/pqc_kv/              the crypto foundation — the part a reviewer should read
  deps.py                runtime backend detection and capability gate
  kem.py dsa.py          ML-KEM-768 / ML-DSA-65 wrappers
  symmetric.py aead.py   HKDF-SHA256, AES-256-GCM, nonce policy, AAD builder
  hybrid.py envelope.py  X25519 + ML-KEM; seal() / open()
  keystore.py            private key files: 0600, atomic, corrupt-safe
  store.py               encrypted asset store, policy, revocation, audit chain
  keyring.py cluster.py  key versions; signed multi-node revocation notices
  intent.py backup.py    crash recovery; authenticated backups with rollback refusal
  logsign.py             signed key-event log
  detect/                goals 6-8: ingest, privilege, lateral, timing, alerts, config
  messaging/             goals 9-12: identity, handshake, wire, session, kdf, resumption
tests/                   834 tests, no network, no shared state
scripts/                 acceptance gates, red team, dashboard, evaluations, verify_all.sh
docs/SECURITY_NOTES.md   per component: the attack stopped, and the limits
docs/BRIEF.md            the two-page submission brief (PDF via scripts/build_brief.py)
docs/                    DETECTION.md, EVIDENCE.md, BREAK_IT.md, PLATFORM_SUPPORT.md
Dockerfile               Python 3.12 / linux-amd64, offline-capable
.github/workflows/       tests on Linux, organizer validator, docker build
```

---

## The gates

Each gate drives **real subprocesses** through `track4_service.py` — one process per
request, exactly as the contract requires — and exits non-zero on any failure.

| Command | Last run | What it proves |
| --- | --- | --- |
| `python -m pytest tests -q` | 834 passed, 3 skipped | unit and adversarial tests |
| `python scripts/phase1_acceptance.py --toolkit ../Track-4-Toolkit` | PASS/SKIP per check | crypto foundation, no plaintext at rest, tamper detection, read-only rootfs |
| `python scripts/phase2_acceptance.py` | 16/16 | goals 9–12 as features |
| `python scripts/phase3_acceptance.py` | 26/26 | goals 1–5: rotation, revocation, recovery, backup, log |
| `python scripts/phase4_acceptance.py` | 29/29 | goals 6–8: rules, chains, uncertain ordering, hostile input |
| `python scripts/phase5_acceptance.py` | 17/17 | goals 9–12 against the attacks the brief names |
| `python scripts/redteam.py` | 38/38 | attacks on the shipped adapter |
| `python scripts/phase6_acceptance.py` | 12/12 | the attack suite, a fix proven by removing it, dashboard honesty |
| `python ../Track-4-Toolkit/validate.py --entry ./track4_service.py` | 22/22 | the organizer's own checks |

`phase1_acceptance.py` reports **SKIP** for checks that cannot run on this host: the
read-only-rootfs check needs `unshare`, which is Linux-only, and the interpreter check wants
Python 3.12. A skip is printed separately and never counted as green — a missing capability
is not a security finding. Numbers in the table are from the last full run; the per-check
count for phase 1 varies with the host, so it is stated as PASS/SKIP rather than a figure.

### Measured numbers

Every figure below was produced by a script in this repository; the command is next to it.

* rotation re-wrapping 20 assets: **67–97 ms** across six runs (~3.4–4.8 ms/asset)
* revoke → **last** node of 3 enforcing: **median 324–360 ms**, worst 363 ms — a lower
  bound, since every "node" is a local directory and a subprocess with no network delay
* crash recovery after a real `os._exit(97)`: **92.9 ms** worst case
* backup: 8/8 single-bit mutations refused; stale replay refused
* log: 406 hostile strings fuzzed, **0** forged events
* detection throughput: **36 944–38 481 events/second**, 170–173 MB peak RSS, on a
  100 000-event log, 2 CPUs (`python scripts/measure_timing.py /tmp/big.csv`)
* detector accuracy on the synthetic corpus (276 events): **20 alerts, all 20 true
  positives, 12 of 13 incidents detected (event-level recall 0.870), 0 false alerts per
  1,000 benign events** (`python scripts/phase4_eval.py --synthetic /tmp/synth`). The one
  miss is deliberate: an attacker who behaves badly *during* the baseline is not novel
  afterwards, and that limit is measured rather than described.
* messaging: an 11 200-byte body becomes **11 authenticated fragments**; one signature per
  message rather than per fragment — the per-fragment alternative measured **5.96× wire
  size and ~17× CPU** (`docs/SECURITY_NOTES.md` §6)

`phase4_eval.py` prints its own method next to every number — how an alert is matched to a
label, what precision is computed over, and that the headline time-to-alert is 0 by
construction. Read that before the figures. Where a slice contains zero incidents, recall
and F1 are undefined and the script now says so rather than printing `0.000`.

---

## How the crypto fits together

Sealing one asset body:

```
ML-KEM-768 encapsulates to the store's public key  -> shared_secret (32B)
        + HKDF-SHA256(shared_secret, label)        -> AES key (32B)
        + fresh 96-bit nonce from os.urandom
        + AES-256-GCM(plaintext, key, nonce, AAD)  -> ciphertext + 16B tag
        + ML-DSA-65 sign(header || nonce || ct || tag || kem_ct)
        = envelope written to disk as JSON/base64
```

Opening reverses it, verifying the signature **before** spending work on key derivation, and
rebuilding the AAD from the identifiers rather than trusting the ones on the wire. Every
failure path raises one opaque `EnvelopeError`.

Hybrid mode (`mode="hybrid"`) replaces the KEM step with X25519 + ML-KEM-768 combined
through HKDF over `transcript || x25519_ss || len(mlkem_ss) || mlkem_ss`. Removing either
component changes the key.

---

## How the adapter works

* **Process model.** One process per request, JSON on stdin, one JSON object on stdout,
  diagnostics on stderr, exit 0. All state is read from and written to
  `TRACK4_STATE_DIR`, falling back to `os.tmpdir()` — verified with the code directory
  mounted **read-only** and no state variable set.
* **setup** rotates the installation keys (so each setup's AES-GCM nonce budget is honest
  even though the process dies after every request), seals every body into `assets/*.env`,
  and seals the synthetic `key_material` to a file with **no read path at all**.
* **read** evaluates policy, opens the envelope it needs, and returns the exact body — or a
  deny carrying **no body and no hint** about the asset. The policy check and the audit
  record commit under one lock, so a revocation landing mid-request cannot be missed.
* **revoke** appends the actor to `disabled` and persists atomically (mkstemp → fsync →
  replace). Peer permissions are untouched.
* **protected_read** encapsulates to the caller's ML-KEM-768 public key and returns the KEM
  ciphertext plus lowercase-hex HMAC-SHA-256 over `challenge + body`. The shared secret
  never leaves the process.

---

## Red team: what we attacked, and what is still broken

`scripts/redteam.py` is a standing gate of 38 attacks; `scripts/phase6_acceptance.py` runs
it and additionally proves the log-truncation fix by removing it and requiring the tests to
fail. Attacks that succeeded against an earlier build and are now fixed:

| Severity | Attack | Before | After |
| --- | --- | --- | --- |
| **high** | delete / empty / truncate / corrupt an asset file, then read | `exit 1`, **empty stdout** — a protocol violation | `{"decision": "deny"}` |
| high | corrupt `keyring.json`; replace the state dir with a file | crash on `read`; crash on **every** KV operation | refusal, opaque |
| **high** | truncate or empty the signed key-event log | `{"ok": true}` | `head_mismatch` |
| low–med | `ls -l` | `audit.jsonl` at **0644** while the ciphertext was 0600 | every state file 0600 |

Two of those are worth understanding, because both were invisible to a green suite.

**The crash class.** The project has two sibling exception hierarchies, `StoreError` and
`KeyStoreError`, and neither subclasses the other. Any path that reads key material could
raise an exception the store's handlers did not catch, so the process exited 1 with nothing
on stdout. Three sites did this. A sweep of 12 disk corruptions × 12 operations now
produces zero crashes.

**The truncation class.** A hash chain cannot see truncation — deleting the newest record
leaves a *shorter valid chain*. The anchor now lives in `state.json`, stamped into the same
atomic write as the event that produced it, and the report says whether an anchor was used
(`anchor_checked`). The 799-test suite missed this because every test asserted that
*tampering* was caught and none asserted that *removal* was.

### Still broken, stated plainly

**Rollback of the state directory.** Restoring a snapshot taken before a revocation brings
the revocation back off; one taken before a rotation reactivates the retired key. No counter
*inside* the directory can defeat this — the attacker is rewinding the directory itself — so
it needs a TPM counter, a remote witness or an off-host ledger, none of which a
single-container submission has. It costs **policy, not confidentiality**: the AEAD binds
asset and owner identity, so an old directory cannot be replayed to read a body as someone
else, and an operator holding the log head outside the directory sees the shorter log.

**Rewriting `state.json` grants access.** Change `owners.brief` from `maya` to `ravi` and
`ravi` reads the asset. The envelope still cannot be forged — AAD binding and the GCM tag
prevent it — but the policy that decides who may open it lives beside the keys that open it.
This is the trust boundary, identical in every phase. Mitigation is deployment: state
directory owned by the service user, `0700`, on a host the attacker does not already
control. Under the organizer's sandbox the state directory is fresh per run.

### Out of scope by design

Root or code execution as the service user · a modified interpreter or injected package ·
sub-millisecond side channels across a process boundary (measured: a deny for an existing
asset is 1.2× an unknown one *in-process*, and ~75 ms of process startup dominates the real
request) · JSON nested past the interpreter's recursion limit, which the organizer's own
`json.loads` refuses before our code runs · DoS by message volume, which the sandbox
prohibits by policy and the wire format bounds at 67 107 840 bytes.

Full detail: `docs/SECURITY_NOTES.md` §P6-1…P6-9.

---

## Known limitations

1. **Identity is a string, not an authenticated session.** The contract passes `actor` as an
   opaque value; we authorize it but cannot prove the caller *is* that actor. A real
   deployment needs an authenticated channel in front.
2. **Keys live in the state directory.** The contract allows nothing else (read-only root,
   no KMS). File permissions protect against other users, not a process running as the same
   user.
3. **No forward secrecy for *stored* assets.** Each asset envelope uses a static recipient
   key, so compromising that key later decrypts stored assets. Messaging sessions **are**
   forward secret, because they derive keys from fresh ephemeral secrets that are erased —
   but a stored file has no "after the fact" to protect.
4. **No replay protection on `protected_read`.** The challenge is echoed into the HMAC but
   nothing tracks seen challenges. Messaging **does** track them, in a persisted 4096-entry
   set written before plaintext is returned. The weaker path is the adapter's own op.
5. **Nonce budget accounting resets every process.** Bounded by rotating keys on each setup,
   far below the 2^20 in-process limit. A long-running deployment needs a persisted counter.
6. **No constant-time guarantees on our own Python glue.** `hmac.compare_digest` is used for
   comparisons and primitives come from libraries, but Python cannot promise constant time.
7. **All "nodes" are processes on one machine.** No real network partition, no clock skew
   between hosts, no Byzantine publisher (one publisher key is the whole authority).
8. **Detection is blind to unusual *purpose*.** An attacker staying inside an identity's
   established edges is invisible to the lateral rules, and an approval record is a *claim*:
   compromise an approver and the privilege rules pass. Precision 1.000 is precision on our
   own synthetic corpus.

---

## Dependencies and why these

| Package | Version | Used for | Why this one |
| --- | --- | --- | --- |
| `pqcrypto` | `0.4.0` | ML-KEM-768, ML-DSA-65 | **The exact version the judging container ships.** pqclean C implementations of FIPS 203 / 204, prebuilt wheels, no compiler |
| `cryptography` | `46.0.4` | AES-256-GCM, HKDF-SHA256, X25519 | Widely deployed, audited, constant-time primitives; abi3 wheels for Python 3.9+ |
| `pycryptodome` | `3.23.0` (optional) | same surfaces as `cryptography` | Fallback only, used automatically if `cryptography` is absent |
| `pytest` | `9.0.1` | tests | dev only; in the image because the image is also where we run the suite |

Every pin has a prebuilt wheel for CPython 3.12 on linux/amd64, linux/arm64 and macOS
arm64 — including Apple Silicon, where `pqcrypto` publishes `cp312-macosx_11_0_arm64`, so
**no Rosetta and no Docker are needed on a Mac**. Full matrix and caveats:
`docs/PLATFORM_SUPPORT.md`. The build refuses source builds (`PIP_ONLY_BINARY=:all:`), so a
missing wheel fails loudly at install time instead of silently dragging in a compiler.

**Fallback crypto path (implemented, not theoretical):** `deps.py` detects at runtime what
is importable. `cryptography` present → use it. Absent → `pycryptodome`. Neither → HKDF
still works from the standard library pinned to RFC 5869 vectors, while AES-GCM and X25519
report `Unavailable` and the adapter refuses to claim an encrypted service
(`{"error": "crypto_backend_unavailable"}`) rather than inventing a cipher.

---

## Docker (Python 3.12, linux/amd64)

```sh
docker build --platform linux/amd64 -t pqc-kv:phase1 .
docker run --rm pqc-kv:phase1 python -m pytest tests -q

# the adapter exactly as the judge runs it: read-only root, temp-only state
printf '%s' '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo"}}' \
  | docker run --rm -i --read-only --tmpfs /tmp pqc-kv:phase1

# organizer validator against the image (toolkit mounted, never copied in)
docker run --rm -v /path/to/Track-4-Toolkit:/toolkit \
  -v "$PWD/track4_service.py:/toolkit/track4_service.py:ro" \
  -v "$PWD/team_app.py:/toolkit/team_app.py:ro" \
  -v "$PWD/src:/toolkit/src:ro" --tmpfs /tmp \
  pqc-kv:phase1 python /toolkit/validate.py --entry /toolkit/track4_service.py
```

The image installs only prebuilt wheels, bakes every dependency in for offline judging, runs
as UID 10001, and deliberately leaves `TRACK4_STATE_DIR` unset so the default path is the
OS-temp fallback the judge uses. The toolkit mount is **not** read-only: the validator
writes `__pycache__` beside it.

Without Docker, `./scripts/verify_container_contract.sh <toolkit>` reproduces the same
contract: read-only code directory, temp-only state, wheels-only install, full suite and the
validator. It needs `unshare` and therefore exits **77 (skip)** on macOS.

---

## Seeing it work, and the submission documents

```sh
python scripts/dashboard.py --open         # http://127.0.0.1:8000
python scripts/build_brief.py              # -> docs/yugaantar-astra-brief.pdf
```

`dashboard.py` serves six panels — access decisions including a revocation taking effect on
the next request, the ML-KEM protected read, messaging (deliver / re-address / replay),
detection, signed-log verification healthy and truncated, and the 38-attack gate. It is
stdlib-only, read-only, loads nothing from the network, and runs against throwaway state
directories. `tests/test_dashboard.py` holds it to the adapter's answers so the page cannot
drift into showing something the system would not do.

**No UI is required by the brief** — the submission is a two-page PDF plus a five-minute
video, and no interface is scored. The dashboard exists because a reviewer who clicks a
button and watches access flip to deny knows more than one who reads "revocation: verified".

The PDF is generated from `docs/BRIEF.md` (organizer's template: USP, architecture with a
diagram, demo entry point and video shot list on page 1; threat model on page 2). The script
**enforces** the two-page limit: it fails if the output is any number of pages other than
two. Two placeholders still need filling before submission — team member names and the video
URL. `docs/EVIDENCE.md` is the optional per-goal evidence sheet, which the template says is
**not** a third submission item.

---

## Scenario and threat model in one paragraph

Asset: synthetic file bodies stored on disk. Trust boundary: the state directory — inside it
everything is trusted and mutually consistent, outside it nothing is. Adversaries
considered: someone who can read the state directory as another user, someone who can modify
files on disk, an unauthorized actor asking for someone else's asset, a revoked actor
retrying, and a network attacker who drops, delays, reorders and re-addresses messages.
Defence: contents are useless without the ML-KEM secret key; every modification is caught by
the AES-GCM tag or the ML-DSA signature; authorization is enforced before any decryption and
every decision is logged with the rule that produced it. The largest remaining risk is that
possession of the state directory equals access to the keys — acceptable for a demo on a
trusted host, unacceptable for production without a KMS.

---

## Toolkit separation

The organizer toolkit is **not** in this repository and must not be added. Our adapter is the
unmodified starter file; our logic lives in `team_app.py` and `src/pqc_kv/`. Every script
that takes a corpus or toolkit path validates it up front and exits 2 with a message naming
the path, so a mistyped argument never looks like a security failure
(`tests/test_script_arguments.py`).
