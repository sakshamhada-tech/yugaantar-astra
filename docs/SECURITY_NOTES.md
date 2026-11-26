# Security notes — per component

For each component: **what attack does this stop?** and **what are its limits?**
Status values are deliberately blunt. Anything marked *limit* is not a bug we
forgot; it is a boundary we are declaring.

---

## 1. `kem.py` — ML-KEM-768 (FIPS 203)

**Stops**

* Passive decryption of stored bodies. A reader without the decapsulation key
  cannot recover the shared secret from the KEM ciphertext, including a future
  attacker with a large quantum computer (that is the point of ML-KEM).
* Mismatched or truncated keys: explicit length checks before the library is
  called return `KemError` rather than a library traceback.

**Limits**

* ML-KEM is **implicitly rejecting**: a tampered ciphertext decapsulates to a
  different, unrelated secret instead of erroring. We deliberately document this
  and rely on the AES-GCM tag to turn it into a clean failure. Claiming
  "tampered KEM ciphertext is detected by decapsulation" would be false.
* The library returns bytes to Python `bytes` objects that cannot be reliably
  zeroised. Secret material can survive in the process heap until GC/exit.
  Mitigation: the process is short-lived (one request), and we never log it.
* ML-KEM-768 is NIST category 3. Not the highest level, chosen for size/speed.
* One-way only: KEM gives confidentiality, not sender authenticity. Signatures
  provide that separately.

---

## 2. `dsa.py` — ML-DSA-65 (FIPS 204)

**Stops**

* Substitution of a stored envelope: an attacker cannot forge an envelope or edit
  any signed byte without the signing key.
* Sender confusion: verification against the *expected* sender's public key
  (not "any key embedded in the message") means a valid signature by someone else
  is still rejected.
* Crash/DoS via hostile input: `verify()` returns `False` for every malformed
  input — wrong length, wrong types, `None`, truncated signature. It never raises.

**Limits**

* A signature proves origin relative to a public key we already trust. If the
  public key comes from the same tamperable directory, an attacker who can write
  both key and envelope wins. Storing the verifier's public key outside the
  writable state directory is future work.
* ML-DSA-65 is category 3. Signature size is 3309 bytes, which is visible in the
  envelope and dominated asset metadata; acceptable for this scenario.
* Hedged/randomised signing relies on the library's RNG. We do not control the
  RNG beyond trusting the OS CSPRNG.

---

## 3. `symmetric.py` — HKDF-SHA256 and AES-256-GCM

**Stops**

* Cross-context key reuse: HKDF with a distinct `info` label per purpose, so the
  asset-body key, the key-material key and the hybrid key are unrelated even if
  they share a root secret. Tested (`test_context_label_changes_output`).
* Undetected modification of a stored body: GCM's 128-bit tag. A single flipped
  bit in ciphertext, tag, nonce or AAD fails authentication (tested exhaustively).
* Nonce/nonce confusion attacks via field shifting: the AAD is canonical JSON with
  sorted keys, so `("ab","c")` and `("a","bc")` cannot collide.
* Predictable-key attacks on a weak input: HKDF is extract-then-expand, so even a
  low-entropy DH-style secret becomes a uniform key.

**Limits**

* GCM fails catastrophically on nonce reuse. Mitigated by fresh OS randomness plus
  a per-key budget (`aead.py`), but a duplicate nonce would be silent — there is no
  cross-process nonce ledger.
* No key commitment: GCM is not key-committing, so in principle one ciphertext can
  be made to decrypt under two keys. Not exploitable in our flow (the signature
  binds the envelope to one sender and AAD binds the recipient label), but worth
  stating rather than hiding.
* `AESGCM` decrypt raises `InvalidTag` and we map it to a uniform `TamperError`;
  the underlying library may spend measurably different time on malformed vs
  well-formed input. No timing claim is made.
* We do not zeroise key bytes (see §1 limits).

---

## 4. `aead.py` — nonce policy

**Stops**

* Birthday-bound nonce collisions: 96-bit random nonces stay safe to 2^32 messages;
  our per-key limit is 2^20 (`MAX_MESSAGES_PER_KEY`) and the store rotates at 4096.
* Silent over-use of one key: `NonceBudgetExhausted` makes it an explicit error and
  `seal()` turns it into a refusal, not a weaker encryption.

**Limits**

* The budget counter is in memory. Because the adapter is a new process per
  request, the count restarts each time. That is safe **only** because
  `StateStore.setup()` rotates keys per setup; a long-lived deployment must persist
  the counter (documented in `store.py`).
* Nonce freshness depends entirely on `os.urandom`. If the platform RNG is broken
  and duplicated nonces, nothing here would notice.

---

## 5. `hybrid.py` — X25519 + ML-KEM-768

**Stops**

* Single-algorithm failure: the final key is HKDF over both shared secrets, so an
  attacker must break X25519 **and** ML-KEM. Tested by mutating each component and
  asserting the key changes (`tests/test_hybrid.py`).
* Contribution-substitution / low-order points: an all-zero X25519 public key or an
  all-zero shared secret is refused (`HybridError`).
* Transcript confusion: both transmitted public values are bound in a fixed,
  length-delimited transcript before derivation.

**Limits**

* Not a full Noise/TLS-style handshake: no authentication of the ephemeral X25519
  key by itself. Authenticity comes from the envelope's ML-DSA signature.
* X25519 does not achieve forward secrecy *here* because the recipient's key is
  static; hybrid mode raises the bar for a quantum attacker, it does not provide
  FS (goal 10 is not claimed).
* Neither X25519 nor ML-KEM errors on most tampering, so tamper detection in hybrid
  mode comes from the AES-GCM tag and the signature — not from the agreement step.

---

## 6. `envelope.py` — `seal()` / `open()`

**Stops**

* Bit-flips anywhere (nonce, ciphertext, tag, KEM ciphertext/hybrid public key,
  signature, header identifiers): all rejected (parametrised tests).
* Envelope relocation: the AAD binds recipient label, envelope id, context and
  version, and `open()` rebuilds the AAD from those identifiers instead of trusting
  the wire, so a ciphertext copied from another asset or another recipient cannot
  be made to open. Verified at store level in
  `test_copied_envelope_cannot_be_moved_to_another_asset`.
* Wrong recipient key, wrong sender public key, truncated/garbage envelopes,
  malformed base64/JSON: one opaque `EnvelopeError`.
* Hostile `dict`s passed to `from_dict`: validated, never partially trusted.

**Limits**

* Error messages are uniform for *crypto* failures but structural failures (e.g.
  "unsupported envelope version", "malformed envelope") are distinguishable. They
  leak no secret, only that the input was structurally wrong.
* Verification happens before decryption; the extra decryption work for a valid
  signature but tampered ciphertext is a trivial cost, not a DoS vector at this
  size.
* A signature covers the envelope but not "when it was created". There is no
  freshness/expiry field yet.

---

## 7. `keystore.py` — key files

**Stops**

* Other local users reading keys: `0700` directory, `0600` files, permissions set
  at creation via `os.open`/`mkstemp`+`fchmod` (no world-readable window), and
  `read_key_file` **refuses to read** a key file whose mode is too open.
* Torn writes: temp file in the same directory, `fsync` on the file, `os.replace`,
  then `fsync` on the directory.
* Truncated / wrong-format keys being used: magic header, version, and base64
  validation; a corrupt key file raises `KeyStoreError` and the caller fails closed.
* Secret leakage in logs: no module in this package logs key bytes, and every key
  object's `__repr__`/`__str__` prints lengths only. Tested in
  `test_no_private_key_material_in_any_output` and `test_repr_of_key_objects_hides_secrets`.

**Limits**

* Same-user process compromise is out of scope: if the attacker runs as the same
  user, file permissions do not help.
* No at-rest wrapping of the private keys themselves (no KEK). The state directory
  *is* the trust boundary.
* `fcntl.flock` is advisory and POSIX-only. Fine for the Linux judging container;
  it would not coordinate across machines.

---

## 8. `store.py` — policy, revocation, audit

**Stops**

* Plaintext at rest: bodies only exist as envelopes; the demo and tests scan every
  file on disk for plaintext and key material, and find none.
* Wrong-owner access and post-revocation access: policy is evaluated before any
  decryption; denies carry no body and no hint about the asset's existence.
  Rule strings are kept for the audit log, not for the caller.
* Fail-open on corruption: a tampered asset envelope returns `deny` with rule
  `asset_integrity_failure`. It never returns a partial or alternate body.
* Non-durable acknowledgements: revocations are written atomically with `fsync`
  before the response is produced, so a crash after `{}` cannot un-revoke.
* Silent audit editing: each record hashes `prev || record`, so editing or deleting
  a line breaks verification from that point on (tested).
* Interleaved writers: `flock` around every read-modify-write.

**Limits**

* The audit chain is **unkeyed SHA-256 with no external anchor**. An attacker who
  can rewrite the entire file can recompute a valid chain. Log integrity (goal 5)
  is therefore *partial*: tamper-evident against casual edits, not against a
  determined attacker with write access. An HMAC keyed by a key stored elsewhere,
  or an append-only remote sink, would be needed.
* Auditing a read also writes state, so a full disk turns a read into an error.
  Deliberate: we prefer "cannot record ⇒ cannot serve".
* No clock trust: timestamps are the host's, unsynchronised.
* Policy is a single "owner == actor" rule. That is the contract's model; it is not
  a general RBAC/ABAC engine.
* `setup` resets policy and assets. That is the contract, but it means anyone who
  can issue `setup` can wipe state. In a real deployment `setup` would be a
  privileged, authenticated operation.

---

## 9. `team_app.py` — adapter surface

**Stops**

* Deny-with-disclosure: deny responses contain only `{"decision":"deny"}` plus a
  rule label that never reveals content or whether the asset exists.
* Leaking internals on failure: `StoreError`, `KeyError`, `TypeError`,
  `ValueError` all collapse into `{"error": ...}` with a fixed vocabulary; no
  paths, no exception text, no stack traces. The adapter's `except` also prints a
  fixed sentence to stderr.
* Malformed `protected_read` input (bad base64, wrong key length, non-string
  challenge): denied and recorded, with no traceback.

**Limits**

* `actor` is an unauthenticated string supplied by the caller. We enforce the
  policy *for* that identity but cannot prove the caller is that identity. This is
  the single biggest caveat of the whole submission and belongs in the brief.
* `protected_read` has no replay protection: the same `(challenge, public_key)`
  can be replayed for a fresh ciphertext. Recipient binding is inherent (only the
  holder of the private key can use the ciphertext), freshness is not.
* The `assert` used as an internal self-check is stripped under `python -O`. It is
  not a security control; it is a smoke test. Nothing depends on it for safety.

---

## 10. Cross-cutting: what we deliberately do *not* do

* No custom cryptographic primitives, no home-made padding, no "XOR with a hash".
* No AI/ML anywhere.
* No hard-coded keys, passwords or secrets; keys are generated at runtime and
  stored only under the gitignored state directory.
* We do not claim forward secrecy, multi-node revocation, log notarisation,
  detection accuracy, or production readiness. Those are Phase 2+ goals.

---
---

# Phase 2 — secure messaging

Scope: authenticated handshake with forward secrecy, an HKDF ratchet, fragmented
transport with loss/reorder tolerance, recipient binding, and a policy hook into
Phase 1 revocation. **Not** in scope: DH ratchet, group messaging, cover traffic,
a trusted clock, or a PKI for the directory.

Goals touched this phase: **9 (replay + recipient binding), 10 (forward secrecy),
11 (delivery under loss/reordering)**. Goal 12 (resumption) is assessed at the end
of this document.

---

## 1. `messaging/identity.py` — fingerprints

**Stops**

* Key confusion: the fingerprint is SHA-256 over a domain label plus *length-prefixed*
  both public keys, so `(aa, bbcc)` and `(aabb, cc)` cannot collide. Without the
  length prefix an attacker could craft a second key set sharing a trusted
  fingerprint -- a collision they control, which no hash function protects against.
* "Which key is this?" ambiguity: `PublicIdentity.from_dict` re-derives the
  fingerprint and refuses a record whose carried fingerprint disagrees with its keys.

**Limits**

* A fingerprint binds keys, not people. Mapping fingerprint -> human is entirely
  the directory's job (see §2). Comparing fingerprints out of band is the only
  defence against a swapped directory.

## 2. `messaging/directory.py` — the trust anchor

**Stops**

* Silently swapped keys: every `lookup` re-derives the fingerprint from the stored
  keys, so editing a public key without editing the fingerprint fails closed.
* Ambiguous matching: lookups are exact string equality. No case folding, no prefix
  matching, no "closest match" routing.
* Undetected whole-file changes *if the caller remembers a digest*:
  `Directory.fingerprint()` gives one stable digest over all entries.

**Limits (the most important ones in this document)**

* The directory is a local file in the same state directory as the private keys.
  **It is not authenticated against a remote party, and it is not protected by any
  key.** An attacker who can write the state directory can substitute their own
  keys *and* the matching fingerprints; every signature we verify afterwards will
  be valid for them.
* There is no PKI, no transparency log, no key pinning to an external root. The
  honest claim is: *the directory is the trust boundary, and the trust boundary is
  the state directory.* For a hackathon demo on a trusted host that is acceptable;
  for production it is the first thing to replace.
* `Directory.fingerprint()` only helps a caller that stores the digest somewhere
  the attacker cannot also rewrite. Nothing here does that for you.

## 3. `messaging/handshake.py` — 3-message signed handshake

**Message count, stated exactly** (this was a flaw in the first design sketch):
**three messages**, because both parties must sign the *same* transcript:

| # | direction | content | who is authenticated afterwards |
| --- | --- | --- | --- |
| 1 | A -> B | `hello`: A's ephemeral X25519 + ephemeral ML-KEM publics, A's identity, **intended recipient B (user id + fingerprint)**, signature | nobody yet |
| 2 | B -> A | `accept`: B's ephemeral X25519 pub + ML-KEM ciphertext, **transcript hash**, signature | **B to A** (B signs bytes A chose) |
| 3 | A -> B | `confirm`: the **same transcript hash**, signature | **A to B**, and B learns the keys agree |

Signing the same 32-byte transcript hash at steps 2 and 3 is what makes "both sign
the whole transcript" true rather than aspirational. A cannot sign at step 1
because B's ephemerals do not exist yet; B cannot prove A's key agreement until A
proves it at step 3. Attempting a 2-message version would mean asserting a
property the messages do not carry.

**Stops**

* Unknown-key-share / transcript splicing: B signs a hash that commits to A's
  hello, so a spliced conversation yields a different hash and A's reconstruction
  check fails (`TRANSCRIPT_MISMATCH`, tested).
* Re-addressing: the hello names the intended recipient by user id *and*
  fingerprint, both inside the signature, so C rejects a hello addressed to B
  (`WRONG_RECIPIENT`, tested).
* Impersonation: the peer's public key is taken from the **directory**, never from
  the message, so a self-signed hello from an unknown key is useless.
* Handshake replay: initiator ephemeral secrets are single-use, so a second
  `complete` for the same session raises `NO_PENDING` (tested). A replayed hello
  produces a different responder ephemeral and therefore a different transcript
  hash, which the original initiator will not have on disk.
* Downgrade: protocol version and suite are fixed constants; unknown values are
  rejected before any crypto runs.

**Limits**

* No rekey/DH ratchet inside the handshake, so no post-compromise security.
* Denial of service is not prevented: anyone can send us a hello and make us do a
  KEM encapsulation and two signature verifications.
* Timing is not constant. Verification time is dominated by the ML-DSA library.

## 4. `messaging/kdf.py` — the ratchet

Shape: `root -> ("i2r" | "r2i") chain -> (message key, next chain key)`, every step
one HKDF-SHA256 call with a distinct label. No XOR, no counter hashing, no
truncation of anything not derived.

**Stops**

* Message-key reuse: each chain step yields exactly one message key, and the
  receive ratchet refuses to return the same key twice (`ALREADY_USED`, tested).
* Cross-direction reuse: `i2r` and `r2i` are separate chains from separate labels
  (tested). *This was a real bug I hit:* labelling chains `send`/`recv` gives each
  side a different chain, so nothing ever decrypts. Caught by a smoke test.
* Unbounded memory from hostile sequence numbers: skipped keys are cached only up
  to `MAX_SKIP_AHEAD` (512) and `MAX_SKIPPED_KEYS` (512), oldest evicted first,
  and a jump beyond the limit is refused *before* deriving anything.
* Out-of-order delivery *within* a message sequence: intervening keys are derived
  and parked, so `[0,3,1,5,2,4]` all decrypt (tested).

**Limits**

* **No DH ratchet** -- if an attacker steals the current chain key, they read all
  future messages in that direction until a new handshake. Forward secrecy within a
  session: yes. Post-compromise security: **no**, and this document will not imply
  otherwise.
* Evicted skipped keys are gone. A message arriving after its key was evicted is
  undecryptable, not merely delayed. The bound is the price of bounded memory.
* Python cannot promise constant-time behaviour; we rely on the libraries.

## 5. `messaging/ephemeral.py` — handshake secret lifecycle (Option B)

Only the **initiator** persists ephemerals, plaintext, `0600`, in the private state
directory, because the adapter forces one process per request. The responder
completes inside a single request and never writes one.

**Stops**

* Long-lived ephemeral exposure: the record is single-use, and `complete()` erases
  it *before* returning the session key. A test asserts the file is gone after
  establishment (`test_ephemeral_file_is_gone_after_establishment`).
* Unbounded accumulation: at most 32 pending handshakes; prune keeps the newest,
  oldest-first, **without trusting the clock** (mtime only picks a victim among
  records already considered abandonable).
* Path traversal via handshake id: ids are sanitised, never trusted as paths (tested).

**Precise claim, and its limit (stated as required):**

> Ephemeral handshake secrets exist in the state directory only between the
> initiator's first and third handshake messages. They are overwritten with zeros,
> unlinked, and the directory is `fsync`ed as soon as the session key exists.
> **This deletes the reference, not the history.** On journalling filesystems
> (ext4 with `data=journal`, APFS) and on SSDs with wear levelling or
> copy-on-write, the previous blocks may persist and be recoverable with forensic
> tooling. `fsync` does not force a TRIM/discard, and we do not issue one because
> doing so on arbitrary filesystems is not portable and can be a no-op.
>
> We deliberately do **not** wrap these records under the long-term identity key:
> the only attacker who can read the state directory can also read that key, so
> wrapping would add no protection while implying it does, and it would tie
> ephemeral confidentiality to a static long-term key.

**Limits**

* In-flight handshakes lost to a crash are abandoned; the initiator must retry
  with a fresh handshake id.
* No expiry by wall clock (untrusted). Pending records are discarded at the next
  handshake once the cap is hit.

## 6. `messaging/wire.py` + `driver.py` — fragments and binding

Header and AAD both carry: protocol version, suite, session id, **sender
fingerprint + user id**, **recipient fingerprint + user id**, message id,
sequence, fragment index, fragment total. Each fragment is independently
AEAD-authenticated; the *set* is covered by one signature.

**Signature policy: once per message.** Measured on this implementation:

| body | fragment | per-fragment signatures | per-message signature |
| --- | --- | --- | --- |
| 1 KB | 1 KB | 5.96x wire, 3309 B sig | 5.96x (identical: one fragment) |
| 8 KB | 1 KB | 5.96x, 26 472 B sigs, 6.6 ms | **2.19x, 3309 B, 0.7 ms** |
| 64 KB | 1 KB | 5.96x, 211 776 B sigs, 59.9 ms | **1.72x, 3309 B, 3.6 ms** |

A 3309-byte ML-DSA signature per 1024-byte fragment is a 3.2x expansion *per
fragment*; signing once keeps overhead at ~1.7x and removes a 17x CPU cost.
**Decision: sign once per message, signature carried in fragment 0.**

What that costs, precisely: a fragment arriving out of order cannot be *attributed*
until fragment 0 arrives. Integrity and confidentiality do not depend on it --
every fragment is AEAD-authenticated under a key only the two parties hold -- and
reassembly refuses to deliver anything unless the manifest signature and every tag
verify. We give up cheap early attribution of an injected fragment, not secrecy,
integrity or binding.

**Stops**

* Re-addressing to another user, or to a different recipient fingerprint: rejected
  at the addressee check before any crypto (`WRONG_RECIPIENT`, tested both ways).
* Fragment substitution across messages or sessions: AAD includes session id,
  message id, sequence and both fragment fields.
* Truncation and corruption: indistinguishable at the transport layer, both become
  `invalid_format` or `decrypt_failed` (tested with a 100%-corrupt simulator).
* Injected fragments from a stranger: sender fingerprint is compared against the
  trusted peer (`WRONG_SENDER`, tested).

**Limits**

* A fragment of an *incomplete* message is buffered. The buffer is bounded (64
  partial messages per session, oldest evicted) so this cannot be used to wedge
  unbounded memory, but an attacker who can inject authenticated-looking traffic
  could still cost us that bounded amount.
* Failure reason codes are returned for the audit log. They distinguish *classes*
  of failure (`wrong_recipient` vs `signature_invalid`) to the application. They
  are never shown to a remote party by the adapter, and they never contain
  plaintext or key material.

## 7. Delivery semantics — **at-most-once**

The receive path advances the ratchet and persists `recv` state plus the replay
record (`seen_ids`) **before** the plaintext is returned
(`driver._receive_one` commits, then constructs the `Message`).

* **Crash before the commit** -> the message was never acknowledged, its key was
  never consumed, and a retransmit decrypts normally. At-least-once would be
  recoverable *if* the key survived, but we deliberately discard it.
* **Crash after the commit, before the response** -> the sender sees no
  acknowledgement, but the key is consumed and the message cannot be read again:
  **the message is lost.**

So the guarantee is **at-most-once**: never twice, possibly zero times. That
choice is deliberate -- delivering twice would mean reusing an AES-GCM message key,
and nonce/key reuse is the one failure mode that breaks confidentiality outright.
Losing a message is recoverable by retransmitting *new* content; replaying one is
not recoverable at all.

Tested: `test_ratchet_persists_before_plaintext_is_returned`,
`test_failed_decrypt_does_not_consume_the_ratchet` (a message that fails
authentication must not advance the chain -- otherwise one corrupt fragment would
permanently desynchronise the session).

**Bounded replay memory, and its limit:** `seen_ids` holds the last 4096 message
ids. An id evicted from that list is "novel" again to the duplicate check --
**but the ratchet still refuses its sequence**, because that key was consumed and
never stored. Tested explicitly by
`test_replay_of_evicted_message_id_is_still_refused`. The id list is a cheap fast
path; the ratchet is the actual replay defence.

## 8. Revocation wiring

`send_message` and `receive_fragments` accept a `policy(user_id, action)` callback
and refuse with `POLICY_DENIED` when it returns false. `team_app.py` wires this to
`StateStore`, so Phase 1 revocation applies to messaging: a revoked actor cannot
send, and a revoked local user cannot receive. Tested twice: with a plain lambda,
and against a real `StateStore` (`test_revocation_wired_from_statestore`).

**Limit:** `policy` is consulted *before* the ratchet advances, so a denied message
does not consume a key -- but that also means a revoked actor's messages are simply
dropped, and the sender keeps a chain state we never advance. On un-revocation the
session resumes from the old sequence; any messages sent while revoked will fail
authentication when they arrive later. This is correct for forward secrecy and
worth stating: **revocation is not retroactive and not queued.**

## 9. Pending-handshake flooding (the limit you asked for)

Anyone who can send a request can call `msg_handshake_init` and make us:

1. generate a fresh X25519 keypair and a fresh **ML-KEM-768 keypair** (~0.1 ms),
2. create one 0600 file in the state directory (~0.3 ms with `fsync`),
3. and later prune the oldest record once 32 are outstanding.

Concretely, **an unauthenticated attacker can create at most 32 pending handshake
records**, each under 4 KiB, and nothing is ever authenticated at that stage --
that is inherent to being the initiator. What bounds it:

* a hard cap of `MAX_PENDING_HANDSHAKES = 32` records on disk;
* oldest-first pruning at the *next* handshake, so the cap holds under sustained
  flooding (a flood evicts legitimate in-flight handshakes -- a denial of service
  on handshakes, not on established sessions);
* `flock` + atomic writes, so concurrent floods cannot corrupt state;
* no clock-based expiry, because the clock is untrusted (a wrong clock would either
  keep records forever or delete live ones).

**Not mitigated:** the CPU and disk cost of each attempt (~1 ms, 4 KiB). A real
deployment needs a rate limit or an authentication cost (proof of work, or
requiring a signed hello from a directory-known identity before persisting
anything). We do not claim DoS resistance. Note that the *responder* never writes a
file at all, so the flooding surface is the initiator side only.

## 10. What the long-term ML-KEM key is actually for

It is **not** used to encrypt messages and **not** used for session keys -- those
come from ephemeral ML-KEM, which is what gives forward secrecy against later
compromise of the long-term key.

Its roles:

1. **Stable addressable identity.** Along with the ML-DSA key it defines the
   fingerprint, so peers can pin and recognise each other across sessions.
2. **A post-quantum anchor for future channels.** Resumption tickets (§11) and any
   future out-of-band key delivery would use it; session key agreement does not.
3. **Reserved for goal 1 (key rotation)**, where rotating a long-term KEM key is
   meaningful precisely because sessions do not depend on it.

If a judge asks "why keep it if sessions don't use it?", the honest answer is: it
is part of the identity, it is what a future authenticated key exchange would use,
and **Phase 2 does not require it for confidentiality**. We did not remove it
because the fingerprint needs a stable, quantum-safe second key to be meaningful.

## 11. Goal 12 (session resumption) — **supported, with stated limits**

`messaging/resumption.py`. A ticket lets two peers skip the ephemeral exchange and
rebuild a session from long-term keys plus a stored secret. The four required
properties, and how each is met:

| Requirement | How | Test |
|---|---|---|
| Bound to the authenticated peer fingerprint | Ticket stores `peer_fp` **and** `peer_user`; both are compared against the directory entry at redeem time | `test_ticket_for_another_peer_is_refused` |
| Proof of possession | Redemption requires an ML-DSA-65 signature by the peer's long-term key over `proof_payload(ticket_id, challenge, peer_fp)` | `test_missing_proof_is_refused`, `test_proof_from_the_wrong_key_is_refused` |
| Fresh keys on resume | New root = HKDF(seed ‖ ticket secret ‖ challenge ‖ budget). The old chain keys are **discarded**, never continued; each redemption yields a different root | `test_resume_with_valid_proof_gives_fresh_root`, `test_each_resume_yields_a_different_root` |
| Single use | The ticket is decremented or deleted from disk **before** the caller receives the root, so a crash after that point cannot hand the same ticket out twice | `test_budget_exhaustion_expires_the_ticket` |
| Expiring | A **budget** (default 3 redemptions) rather than a timestamp | `test_budget_decrements_and_is_reported` |

### Expiry without a trusted clock

The container's clock is not something this code can trust, and a skewable clock is
a skewable expiry — an attacker who can move the clock forward or back can extend a
ticket's life. So a ticket carries a **budget**: an integer count of redemptions,
held in our own state file. It cannot be forged by changing the time, and it is
monotone under our control.

**The honest difference from a TTL design:** a ticket that is never redeemed is
still valid a year later, as long as its budget is untouched. This is not calendar
expiry and I am not going to describe it as such. What the budget actually bounds is
*reuse*, which is the property that matters for an attacker who has stolen a ticket
file — they still cannot use it without the long-term signing key, and the count of
attempts is capped.

### What resumption does *not* raise the bar against

The ticket secret lives in the same state directory as the session state. An attacker
who can read that directory already has the ratchet keys, so the ticket adds no
exposure **against that attacker**. What it buys over a full handshake is (a) no new
ephemeral exchange, and (b) the guarantee that *the ticket file alone* is useless
without the long-term signing key — stealing one file is not enough, you need the
key too.

### Why this counts as supported rather than skipped

A full handshake costs roughly 4 ms. Resumption therefore buys latency, not safety,
and it is only worth shipping if it is not *weaker* than the thing it replaces. Each
of the five properties above is tested to the same standard as goals 9–11, the
failure modes are single-reason codes with no key material, and the one real
divergence from a textbook design (budget instead of wall-clock expiry) is stated
above rather than hidden. Had any of the four required properties failed to test
cleanly, the answer would have been **"not supported"** — a defensible answer for a
4 ms saving.

## 12. Adapter operations added for Phase 2

`docs/adapter-v1.md` fixes the protected-resource interface (`setup`, `read`,
`revoke`, `audit`, `protected_read`) and states that the twelve goals include
capabilities outside it, while requiring that end-to-end messaging, replay protection
and forward secrecy each carry **separate evidence**. So Phase 2 is exposed as
thirteen additional `msg_*` operations through the *same* generic JSON shim.
`track4_service.py` is byte-identical to the toolkit starter; `setup` is unchanged.

| op | purpose |
|---|---|
| `msg_identity` | create/load a local identity, return fingerprint (and optionally the public record) |
| `msg_directory_add` / `msg_directory_show` | publish a peer's public record / list known peers + digest |
| `msg_handshake_init` | step 1: hello out, initiator ephemerals persisted |
| `msg_handshake_finish` | step 2: responder accepts, derives keys, persists **no** ephemerals |
| `msg_handshake_complete` | step 3: initiator finalises, erases ephemerals, emits confirm |
| `msg_handshake_confirm` | step 3 received: mutual key confirmation |
| `msg_send` / `msg_receive` | encrypt + fragment / reassemble + deliver |
| `msg_status` | counts and role — no keys |
| `msg_ticket_issue` / `msg_resume` | goal 12 |
| `msg_close` | delete session state |

**Every failure is `{"error": "request_failed"}`.** Returning `wrong_recipient`
versus `signature_invalid` versus `unknown_session` to the caller would turn the
adapter into an oracle that tells an attacker which of their guesses was closest.
The specific reason code exists inside the process (and in the audit log), never in
the response. This matches Phase 1's rule that a deny carries no hint.

The `msg_identity` op can return the public record on request (`export_public`).
That is safe by construction: it is the directory entry, i.e. exactly the material a
peer needs to pin us, and it reveals nothing that comparing fingerprints would not.
Secret keys are never serialised by any code path — the sweep in
`test_no_secrets_in_messaging_output` reads every state file, extracts any key
material it can find, and asserts none of it appears in any op response.

### End-to-end evidence

`tests/test_messaging_adapter.py` drives two separate **subprocesses** through the
real `track4_service.py`, one process per request, so nothing survives in memory
between steps. That suite covers the complete handshake, a multi-fragment message
round trip, replay rejection, re-addressing rejection, revocation taking effect, the
ephemeral file being gone after establishment, a third party refusing a hello
addressed elsewhere, opaque failures for malformed input, and the secret sweep. It
is the load-bearing evidence that the on-disk state design works under the
contract's one-process-per-request constraint, as opposed to only in-process tests.
