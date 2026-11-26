# Phase 1 review pack

## A. Security self-review (what I looked for, what I found, what I fixed)

Review lens: nonce handling, constant-time comparison, error-message leakage, key
handling, and anything a judge would file as an assessment finding.

| # | Check | Finding | Action |
| --- | --- | --- | --- |
| 1 | Nonce reuse | None possible in a single process: fresh `os.urandom(12)` per seal, plus a 2^20 per-key budget. **But** the adapter is a new process per request, so an in-memory counter cannot bound total messages per key. | **Fixed.** `setup()` now rotates the ML-KEM and ML-DSA keys and re-seals every asset, so a key only ever serves one setup. Rotation implemented in `store._rotate_keys()`; test `test_setup_rotates_keys_and_reseals`. |
| 2 | Nonce/IV derived from anything else | No counters, no timestamps, no keys-as-nonce. Only the CSPRNG. | Verified by inspection; `test_nonces_do_not_repeat_in_a_sample` over 2048 samples. |
| 3 | Constant-time comparison | The only MAC comparison (`protected_read` proof, verification results) uses `hmac.compare_digest`. Signature verification is inside the library. | Verified; no `==` on secret bytes anywhere. `hmac.compare_digest` is used via `symmetric.constant_time_equal`. |
| 4 | Error-message leakage | Crypto failures are uniform (`TamperError("authentication failed")`, `EnvelopeError`). Structural failures differ, but reveal only that the input was malformed. Adapter collapses all exceptions to a fixed vocabulary and never echoes request data. | Strengthened: decrypt-path length checks moved from `ValueError` to the same opaque `TamperError`, so a malformed tag is indistinguishable from a bad tag. Test `test_error_messages_do_not_leak_which_check_failed`. |
| 5 | Secret material in repr/logs | All key dataclasses override `__repr__`/`__str__` to print lengths. Adapter logs fixed sentences. | Verified by `test_no_private_key_material_in_any_output` (reads the real key files, then asserts those bytes appear nowhere in stdout/stderr/responses) and `test_repr_of_key_objects_hides_secrets`. |
| 6 | Key file permissions | `0700` dir, `0600` files, mode set at creation (no readable window), and readers **refuse** files with loose modes. | Verified; `test_key_file_with_open_permissions_is_refused`, `test_state_directory_permissions_are_private`. |
| 7 | AAD actually bound | Originally `from_dict` accepted `aad` from the wire and `open()` compared it against a rebuilt value — a tampered header would fail, but the design invited confusion. | **Fixed.** The AAD is never accepted from input: `Envelope.aad_bytes()` recomputes it from identifiers, and `from_dict` sets `aad=b""`. Test `test_flipped_aad_identifier_is_rejected`. |
| 8 | Wrong public key sent to an authorized reader | `protected_read` validates base64 and length; a bad key denies and is recorded, no traceback. | Verified; `test_protected_read_rejects_bad_public_key`. |
| 9 | Fail-open on corrupt ciphertext | A tampered asset envelope returns `deny` (rule `asset_integrity_failure`), never a fallback body. | Verified; `test_tampered_asset_envelope_fails_closed`, `test_copied_envelope_cannot_be_moved_to_another_asset`. |
| 10 | ML-KEM's implicit rejection misunderstood | First draft of `kem.public_key_from_secret` assumed the public key sat at offset 0 of the secret key. It **does not** — a test caught it. | **Fixed.** Offset is `2400 − 1184 − 64 = 1152` per FIPS 203 (`dk_PKE ‖ ek ‖ H(ek) ‖ z`), now a named constant pinned by a test. This was a real bug that a "looks fine" review would have missed. |
| 11 | Hybrid key really needs both parts | Confirmed by construction and test: changing either secret changes the derived key. | `test_changing_x25519_secret_changes_key`, `test_changing_mlkem_secret_changes_key`, `test_derive_key_depends_on_either_component`. |
| 12 | Length-extension / ambiguity in KDF input | Concatenating secrets without framing lets `("a","bc")` and `("ab","c")` collide. | Framed: `transcript ‖ x25519 ‖ "|mlkem(len=N):" ‖ mlkem`. Test `test_kem_component_is_length_prefixed`. |
| 13 | Low-order X25519 point | An all-zero peer key would contribute a known value. | Refused explicitly (`HybridError`). Test `test_low_order_x25519_point_refused`. |
| 14 | Denied response leaking content | Deny carries no body; the validator also checks the seeded marker does not appear. | Verified by validator ("fake key stays out of output", "denied response disclosed…") and `test_key_material_never_leaves_the_process`. |
| 15 | Honest claim about log integrity | The audit chain is unkeyed SHA-256 with no external anchor. | **Declared as a limit**, not fixed. Written in README §6 and SECURITY_NOTES §8. Do not claim goal 5 as "measured". |
| 16 | Read-only filesystem + no state variable | A naive implementation writes next to the code and dies in judging. | Verified by actually bind-mounting the code directory read-only and running with no `TRACK4_STATE_DIR`: setup/read/revoke/deny all worked. |

**Residual findings I am not fixing in Phase 1** (documented, would be Phase 2):

* `actor` is unauthenticated input — policy is enforced for the claimed identity, not proven.
* No replay window on `protected_read` (challenge is bound into the HMAC but not tracked).
* No at-rest wrapping (KEK) for the private keys; the state directory is the boundary.
* `assert` used once as an internal smoke check — stripped under `-O`, not a control.

---

## B. Desk review: 5 questions a judge may ask, with short answers

**1. "Where is the post-quantum part, and why does it matter here?"**
The asset bodies are sealed with ML-KEM-768 (FIPS 203) for confidentiality and
ML-DSA-65 (FIPS 204) for authenticity — both NIST post-quantum standards. It
matters because the realistic threat to *stored* data is "record now, decrypt
later": a classical-only envelope becomes readable the day a quantum machine
exists, and stored files are exactly the kind of thing an adversary keeps. Hybrid
mode goes further: X25519 **and** ML-KEM must both fall.

**2. "Anyone can write `if actor in disabled: deny`. What does crypto add?"**
It changes *what an attacker needs*. With plain policy, whoever can read the
state directory reads every file. Here, the directory contains only envelopes: an
attacker with the same read access gets ciphertext that is useless without the
ML-KEM secret key, cannot modify anything without breaking the GCM tag or the
ML-DSA signature, and cannot move a ciphertext onto another asset because the AAD
binds the asset id and recipient label. Policy decides *who may ask*; crypto
decides *what asking is worth*.

**3. "Show me tamper detection, not a description of it."**
`tests/test_envelope.py` flips one bit in each of nonce, ciphertext, tag, KEM
ciphertext, hybrid public key and signature, at two byte offsets, and asserts a
clean `EnvelopeError` every time. It also rewrites the header identifiers
(recipient, envelope id, context, version) and asserts rejection. At store level,
`test_copied_envelope_cannot_be_moved_to_another_asset` copies one asset's
ciphertext over another's and asserts the read becomes a deny rather than a wrong
body. Measured, not asserted by description.

**4. "What is your biggest security weakness?"**
The private keys sit in the same writable state directory as the ciphertext, so
"can write that directory" ≈ "is the service". That is forced by the adapter
contract (read-only root filesystem, no KMS, new process per request) and it is
written down in README §6 and SECURITY_NOTES §7–8. Second: `actor` is an
unauthenticated string, so we enforce policy *for* the claimed identity without
proving possession. Third: the audit chain is unkeyed, so it detects casual edits
but not a full rewrite — hence goal 5 is "partial", not "measured".

**5. "How do I reproduce this on a clean machine?"**
`./scripts/verify_install.sh /path/to/Track-4-Toolkit` — it builds a throwaway
venv from `requirements.lock`, prints the resolved versions and detected backend,
runs the 140-test suite, then runs the organizer's validator against
`track4_service.py`. It is the same script I ran, including a run in a
pycryptodome-only environment (`140 passed`, backend `pycryptodome`) to prove the
fallback path. The toolkit is never copied into this repo.

---

## C. Coverage of the 12 checklist goals after Phase 1

| Goal | Touched in Phase 1? | Status | Note |
| --- | --- | --- | --- |
| 1. Key rotation | **Yes, partially** | partial | `setup()` rotates ML-KEM/ML-DSA keys and re-seals all assets. No versioned rotation interface, no overlap window. |
| 2. Revocation across nodes | **Yes, single node** | partial | Revocation persists atomically and is enforced before decryption; only one node exists. |
| 3. Crash recovery | **Yes, implicitly** | partial | Atomic state writes + `fsync`; revocation survives process death. No restart-timing measurement yet. |
| 4. Backup integrity | No | not tested | Assets are self-verifying (GCM tag), but no backup/restore operations exist. |
| 5. Log integrity | **Yes, partially** | partial | Hash-chained audit log detects edits/deletions; unkeyed with no external anchor. |
| 6. Routine and suspicious activity | No | not tested | The practice `events.csv` is a separate exercise; not parsed. |
| 7. Lateral movement | No | not tested | Out of scope for the adapter. |
| 8. Clock differences | **Minimal** | not tested | Audit records carry UTC timestamps only; no offset handling. |
| 9. Replay and recipient binding | **Yes, half** | partial | Recipient binding is inherent (KEM ciphertext only opens for the private-key holder). No freshness/replay tracking. |
| 10. Forward secrecy | No (claimed nowhere) | not supported | Static recipient key; README and SECURITY_NOTES say so explicitly. |
| 11. Delivery under loss or reordering | No | not tested | No messaging layer in Phase 1. |
| 12. Session resumption | No | not supported | No sessions; one process per request, policy re-checked every call. |

> **This table is the Phase 1 state and is deliberately not updated.** It is a
> snapshot of what existed before the messaging layer, kept so the Phase 1 claim is
> auditable in its original form. For the current status of goals 9–12 see
> `docs/SECURITY_NOTES.md` sections 3–11, which describe what Phase 2 actually
> implements and tests: 9 (replay + recipient binding), 10 (forward secrecy via the
> hybrid handshake), 11 (fragmentation under loss/reordering) and 12 (resumption,
> with its budget-expiry limit stated).

**Touched: 1, 2, 3, 5, 9 (all partial). Not covered: 4, 6, 7, 8, 10, 11, 12.**
Nothing above is marked "measured" — a design description is not a measurement,
and the evidence sheet's own rule says so.

---

## D. Phase 1 commands and observed results

```
$ PYTHONPATH=src:. python -m pytest tests -q
139 passed, 1 skipped in 3.49s
  # cryptography backend; 1 skip = pycryptodome-only test

$ PYTHONPATH=src:. /tmp/fbc/bin/python -m pytest tests -q   # pycryptodome-only venv
140 passed in 4.57s

$ ./scripts/verify_container_contract.sh /path/to/Track-4-Toolkit
  code dir is read-only: ok
  {"ready": true} / {"decision":"allow",...} / {} / {"decision":"deny",...}
  139 passed, 1 skipped
  PASS: 22   FAIL: 0
  == all container-contract checks passed ==

$ ./scripts/verify_install.sh
  detected backend: {'symmetric': 'cryptography', 'aead': True, 'x25519': True, 'pqcrypto': '0.4.0'}
  139 passed, 1 skipped
  == all checks passed ==

$ cd /path/to/Track-4-Toolkit && python validate.py --entry ../yugaantar-astra/track4_service.py
  22 PASS / 0 FAIL, "Local scenario passed.", exit 0

$ python scripts/demo_lost_device.py
  plaintext files found: none
  maya reads brief  -> allow
  maya reads brief  -> deny (identity_revoked), audit r03 explains it
  ravi reads notes  -> allow
  chain verifies: True (5 records)
  keys dir 0o700, key files 0o600
```

**Phase 1 stops here.** Phase 2 (rotation interface, multi-node revocation,
messaging, detection, backup) is not started.
