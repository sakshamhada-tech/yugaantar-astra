# Break it on purpose — Phase 3 mutation log

Every row is a mutation I applied to the source, ran the suite against, and reverted.
The "caught by" column lists tests that **actually failed**, copied from the pytest
output of a re-run done after this document existed — not from memory.

Reproduce any row: apply the one-line change, run the module, restore the file.
The script used is reproduced at the bottom. `git status` was clean afterwards.

| # | Mutation | File | Caught by | Verdict |
|---|---|---|---|---|
| 1 | Notice signature verification replaced with `pass` | `cluster.py` | `test_a_notice_signed_by_another_key_is_refused`, `test_a_tampered_payload_fails_verification`, `test_the_sequence_number_cannot_be_lowered`, `test_a_forged_notice_in_the_outbox_is_ignored`, `test_stranger_signed_notice_is_refused_when_pinned_to_another_key` (5) | caught |
| 2 | Identifier validation becomes `return value` | `logsign.py` | `test_every_hostile_identifier_is_refused`, `test_a_forged_json_value_cannot_create_a_second_record`, `test_a_newline_in_an_identifier_cannot_split_a_record`, `test_detail_text_is_validated_too`, `test_a_revoked_actor_with_a_hostile_name_cannot_inject_a_log_event` (5) | caught |
| 3 | Per-record signature check in `verify()` replaced with `pass` | `logsign.py` | `test_a_forged_record_signed_with_another_key_is_detected` | caught |
| 4 | `write_commit()` returns without writing the marker | `intent.py` | `test_a_crash_after_commit_does_not_re_wrap_anything` | **caught only after a gap was fixed** |
| 5 | Backup rollback (high-water) check replaced with `pass` | `backup.py` | `test_restoring_an_older_backup_cannot_resurrect_a_revoked_key`, `test_restoring_an_older_key_version_is_refused` | caught |

Earlier in the phase, two further mutations were run against the recovery logic, before
the intent log was finished. They are kept for the record:

| # | Mutation | File | Result |
|---|---|---|---|
| 6 | `recover()` becomes a no-op (clears intent, returns) | `store.py` | 3 tests failed, incl. `test_assets_are_consistent_after_a_mid_rewrap_crash` |
| 7 | `rotate()` never writes the intent record | `store.py` | 5 tests failed, incl. `test_recovery_preserves_the_audit_chain` |

## The gap, and what it taught me

Mutation 4 is the useful one. Deleting `write_commit()` *should* be serious: without a
commit marker a finished rotation looks unfinished. But all 20 recovery tests passed.

The reason is uncomfortable: recovery's "finish forward" path is **idempotent**, so
re-doing a completed rotation produced a correct end state. The tests were checking the
result, and the result was right — the work was simply done twice, re-sealing every
asset and burning fresh nonces on data that was already correct.

The test added in response asserts the *behaviour distinction* instead of the end state:
after a crash past the commit point, recovery must report `action == "cleared"` and must
not report `resealed`. That fails under the mutation and passes normally.

Lesson: when an operation is idempotent, "the answer is still right" is a weak
assertion. Check that the cheap path was taken, not just that the outcome is correct.

## Mutation 1 deserves a note too

Skipping the notice signature still leaves sequence-number checks in place, so replay
protection survives and five tests fail for the *forgery* reasons specifically. That is
the split I wanted: the signature stops forgery, the sequence number stops replay, and
each has tests that fail independently of the other.

## What I did not mutate, and why

* **The GCM tag check.** Removing it means patching a vetted library call. The bit-flip
  tests already fail without it by construction.
* **`os._exit` in the fault hook.** Changing it to `sys.exit` would let interpreter
  cleanup run, so it would stop simulating a crash. Existing tests assert exit code 97.
* **`flock` in `_locked`.** A concurrency mutation whose failure is timing-dependent: a
  green suite would be no evidence either way. Listed as untested rather than claimed.

## The script

```python
import pathlib, shutil, subprocess

ROOT = pathlib.Path(".")          # repo root
PY = str(ROOT / ".venv/bin/python")
mutations = [
    # (label, file, exact source text to replace, replacement, test module)
    ("notice-signature-skipped", "src/pqc_kv/cluster.py",
     "    if not dsa.verify(signer_public, expected, signature):\n"
     "        raise NoticeError(Reason.BAD_SIGNATURE)",
     "    pass  # MUTATION", "tests/test_phase3_cluster.py"),
]

for name, rel, old, new, module in mutations:
    path = ROOT / rel
    backup = pathlib.Path("/tmp") / (path.name + ".mutbak")
    shutil.copy(path, backup)
    text = path.read_text()
    assert old in text, f"{name}: pattern not found"
    path.write_text(text.replace(old, new, 1))
    try:
        out = subprocess.run([PY, "-m", "pytest", module, "-q"],
                             capture_output=True, text=True, timeout=600)
        failed = sorted({line.split("::")[1].split(" ")[0]
                         for line in out.stdout.splitlines()
                         if line.startswith("FAILED")})
        print(name, "->", failed or "SURVIVED (gap!)")
    finally:
        shutil.copy(backup, path)
```

A mutation that survives prints `SURVIVED (gap!)` rather than being silently ignored,
which is how mutation 4 was found.
