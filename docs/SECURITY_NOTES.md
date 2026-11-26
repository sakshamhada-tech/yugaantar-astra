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
