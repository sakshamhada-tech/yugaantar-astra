# Trust, but verify

## Page 1: USP, architecture, and fallback video

**Project:** yugaantar-astra — post-quantum, zero-trust access control for protected files
**Team:** _[add member names]_
**Repository and commit:** https://github.com/sakshamhada-tech/yugaantar-astra · `4274c78`
**Demo entry point:** `python scripts/dashboard.py --open`

### Unique selling proposition (USP)

Enterprise files outlive the laptops holding their keys, so "who may read this, today" must
be answerable independently of the device asking — and still answerable once quantum
computers break today's primitives. This project seals every protected body under
ML-KEM-768, AES-256-GCM and ML-DSA-65, hash-chains every decision into an audit log, and
applies a revocation on the **next** request rather than the next day. What distinguishes it
is the proof rather than the feature list: 36 attacks against our own shipped adapter, 819
tests, and a demonstration that shows failures being refused instead of described as
refused.

### Architecture

Actors are **users** who own assets, a **service** running one adapter process per request,
and an **operator** who rotates keys, revokes identities and verifies logs. All state is on
disk, so a fresh process is indistinguishable from a restarted one.

A read crosses four checks. **Identity** is compared as exact bytes, so a Cyrillic look-alike
is a different, unauthorized principal. **Authorization** takes one lock, so the policy check
and its audit record commit together and a revocation landing mid-request cannot be missed.
**Decryption** opens an AEAD envelope whose associated data binds asset id and owner, so a
body sealed under one policy cannot be reopened under another. **Output** is silent on
failure: a deny carries no body, no reason, no hint the asset exists — the reason goes to the
audit log, which only an operator reads.

<!-- diagram: request path -->

Pinned to the judging runtime: `pqcrypto 0.4.0` (pqclean FIPS 203/204), `cryptography
46.0.4`, Python 3.12. **No primitive is implemented here.** Working: phases 1–6, all twelve
goals, including a messaging session layer over the same store — hybrid X25519 + ML-KEM
handshake, per-fragment keys erased after use, recipient and session bound into every
fragment. Not built: anything needing a second host.

### Accessible five-minute fallback video link

**Video link:** _[paste accessible URL before submission]_
**Duration:** five minutes
**Access checked:** _[date; confirm reviewers can open without requesting permission]_

Against commit `4274c78`: the dashboard shows maya reading her own asset (allow, body) and
ravi reading maya's (deny, no body); maya is revoked and refused on the very next request
with no restart; the ML-KEM panel shows ciphertext and proof and asserts the plaintext is
absent; a message is delivered, then re-addressed to carol (`wrong_recipient`), then
replayed (`duplicate_fragments=4`, 0 delivered); detection names one unapproved privilege
change and one lateral chain; the signed log verifies clean, loses its last record, and
fails with `head_mismatch`; the 36-attack gate runs. It closes on the rollback risk, stated
on camera rather than left to be found.

**Observed outcome:** every panel drives the real adapter in a fresh process, so the video
shows the shipped artifact. On the practice set the detector reports precision and recall
1.000 over 22 events and 5 incidents — a functional demonstration only. Revocation reaches
the last of three nodes in a median 324–360 ms; rotation re-wraps 20 assets in 67–97 ms.

<div style="page-break-before: always;"></div>

## Page 2: One-page threat model

### Assets

**Protected bodies** — confidentiality; sealed at rest, and the synthetic key material has
no read path. **Identity keys and the keyring** — integrity; compromise forges
authorization. **Policy state** — integrity, because it *is* the policy. **Logs** —
completeness, so a removal is as detectable as an edit. **Availability** — a system that
crashes instead of denying fails operationally.

### Adversaries

**(a)** An unauthorized caller with the public interface and arbitrary JSON, holding no key
material. **(b)** A revoked or compromised account that still has a session, cached
fragments, or an old key version. **(c)** A network attacker who drops, delays, reorders,
duplicates and re-addresses messages. **(d)** A caller who can write the state directory but
not execute as the service user — the strongest adversary modelled, and the one that defeats
us. Out of scope: root or code execution as the service user, a modified interpreter or
injected package, sub-millisecond side channels across a process boundary.

### Trust boundaries

The **state directory is the boundary**: inside it everything is trusted and mutually
consistent, outside it nothing is. Requests cross only through the adapter, which parses
untrusted JSON into a closed set of operations. Key material crosses only as KEM ciphertext
and MACs. The **operator** is a separate principal — only they rotate, revoke, or read
denial reasons.

### Assumptions

`rename` is atomic and `fsync` persists; every write is mkstemp → fsync → replace. Clocks are
trusted for log ordering but **never** for authorization — the post-rotation grace is a count
of requests, so a skewed clock cannot extend access. `pqcrypto` and `cryptography` are
trusted as shipped; wheel integrity is not verified at runtime. One publisher key is the
whole authority for cluster notices, with no quorum, so equivocation is undetected.
Administrators protect the directory (0700, service user) and hold the log anchor outside it.

### Defenses

| Threat | Defense | Evidence |
| --- | --- | --- |
| Unauthorized read | exact-byte identity, lock-scoped check-and-audit, silent deny | 12 concurrent reads sharing one `request_id` → exactly 1 allow |
| Forged or replayed asset | AEAD with AAD bound to asset id and owner | `tests/test_envelope.py` |
| Revoked user reads on | persistent revocation, effective next request | dashboard panel 2 |
| Crash mid-write | atomic replace, intent record | 40 `SIGKILL`s → 0 unusable states |
| Log edited | hash chain | reorder / edit / forge → `chain_broken` |
| **Log shortened** | anchor in `state.json`, same atomic write | truncate → `head_mismatch` (**fixed after this attack succeeded**) |
| Replay, re-addressing, loss | per-fragment freshness, recipient binding, at-most-once | `wrong_recipient`; replay → 0 delivered |
| Long-term key exposed later | per-session keys erased after use | `tests/test_phase5_*` |

### Exclusions and remaining risks

**Largest remaining risk: rollback of the state directory.** Restoring a snapshot taken before
a revocation brings the revocation off; one taken before a rotation reactivates the retired
key. No counter inside the directory can defeat this — the attacker is rewinding the directory
itself — so it needs a TPM counter, a remote witness, or an off-host ledger, none of which a
single-container submission has. It costs **policy, not confidentiality**: AAD binding means
an old directory cannot be replayed to read a body as someone else, and an operator anchored
outside the directory sees the shorter log.

Also stated, not hidden: rewriting `state.json` grants access, since policy lives beside the
keys enforcing it; 22 practice events cannot support an accuracy claim; timings are single-host
lower bounds; message volume is bounded by the wire format, not by policy.
