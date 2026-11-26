# Evidence sheet — goals 1–5 (Phase 3)

The rule this sheet follows: **"measured" means a script produced the number, in this
repository, and the command is printed next to it.** A design description is not a
measurement. Anything I could not demonstrate is marked `limit` or `not tested`
instead of being talked up.

Machine: Linux container, Python 3.11.2, `pqcrypto 0.4.0`, `cryptography 46.0.4`.
Note the interpreter: the project targets 3.12 and CI runs 3.12, but the sandbox here
could not install it (see `docs/PLATFORM_SUPPORT.md`). Nothing was run on macOS.

Reproduce everything:

```sh
python -m pytest tests -q                  # 467 passed, 1 skipped
python scripts/phase3_acceptance.py        # 26 passed, 0 failed
python /path/to/toolkit/validate.py --entry ./track4_service.py   # 22 PASS, 0 FAIL
```

---

## Goal 1 — Key rotation

| Claim | Status | Evidence |
| --- | --- | --- |
| Keys are versioned with integer versions and explicit states (active/retiring/retired/revoked) | measured | `test_initial_ring_has_one_active_version`, `test_rotate_creates_n_plus_1_and_retires_n` |
| Rotation makes version N+1 and re-protects existing data so reads continue | measured | `test_rotation_keeps_data_readable_under_the_new_version`; acceptance `goal1/readable-after` |
| A documented cutoff exists after which the old version is rejected | measured | `test_old_version_rejected_exactly_at_the_boundary`; acceptance `goal1/grace-at-cutoff` |
| The cutoff is a bounded count, not wall time | measured | `test_old_version_accepted_inside_the_grace_budget`; the grace is `epoch < grace`, an integer in state |
| Both sides of the boundary tested | measured | grace 2 → allow, allow, deny (3 assertions in one test) |
| In-flight requests complete | measured | the two grants inside the budget in `test_old_version_request_accepted_then_rejected_through_the_store` |
| Rotation does not run the destructive `setup()` path | measured | `test_rotation_does_not_run_the_destructive_setup_path` (monkeypatched hooks never entered) |
| Old-version requests are rejected *identically* to other denials | measured | `test_rotation_does_not_break_the_deny_oracle_fix` |
| Re-wrap cost | **measured: 67–97 ms for 20 assets** | `test_rotation_cost_is_measured` prints it; six runs |
| Re-wrap cost at realistic scale (thousands of assets) | **not tested** | — |
| Rotation propagates across nodes | measured | `test_a_rotation_notice_reaches_nodes_that_have_not_applied_it` |

## Goal 2 — Revocation across nodes

| Claim | Status | Evidence |
| --- | --- | --- |
| N nodes (default 3), each its own state dir and adapter process | measured | `tests/test_phase3_cluster.py` — every node is a subprocess call |
| Notices are signed and sequence-numbered | measured | `test_a_notice_round_trips_and_verifies`, `test_the_sequence_number_cannot_be_lowered` |
| Signature is verified before the notice is applied | measured | `test_a_notice_signed_by_another_key_is_refused`, `test_stranger_signed_notice_is_refused_when_pinned_to_another_key` |
| Apply is idempotent | measured | `test_applying_the_same_notice_twice_is_idempotent` |
| Apply is order-independent | measured | `test_rotation_notices_are_order_independent` (v2 then v3, and the max wins) |
| Revoked key rejected on every node | measured | `test_a_revoked_actor_is_rejected_on_every_node`; acceptance `goal2/all-nodes-enforce` |
| A node that was offline catches up and then rejects | measured | `test_a_node_that_was_offline_catches_up_then_rejects` |
| Forged or replayed notice refused | measured | `test_a_forged_notice_in_the_outbox_is_ignored`, `test_replaying_a_notice_is_refused_and_changes_nothing`, `test_an_out_of_order_older_notice_is_refused` |
| Re-enrolment works and the old device key stays rejected | measured | `test_re_enrolment_after_a_device_is_revoked` |
| Peers unaffected | measured | `test_peers_are_unaffected_on_every_node` |
| Propagation time to the LAST node | **measured: median 324–360 ms, worst 390 ms** | `test_propagation_time_is_measured`, 5 runs per invocation, 4 invocations |
| Propagation over a real network | **not tested** — lower bound only | all nodes are local dirs; no network, no partition, no clock skew |
| Byzantine/equivocating publisher | **limit** | one publisher key is the whole authority; no quorum |

## Goal 3 — Crash recovery

| Claim | Status | Evidence |
| --- | --- | --- |
| Write-ahead intent record, commit marker, atomic writes | measured | `pqc_kv/intent.py`; `test_a_crash_after_commit_does_not_re_wrap_anything` asserts the marker is what distinguishes done from half-done |
| Recovery lands on ONE consistent authorized version | measured | `test_recovery_lands_on_one_consistent_version`, parametrised over all 5 points |
| Tested by killing a REAL subprocess at each point | measured | 5/5 exit code 97; `test_the_hook_kills_a_real_process_at_the_named_point` |
| Revoked keys stay revoked after recovery | measured | `test_revocation_survives_a_crash_at_every_point`, 5 points |
| Committed keys and data remain readable | measured | the read assertions in the same parametrised test |
| Mid-re-wrap crash leaves no mixed versions | measured | `test_assets_are_consistent_after_a_mid_rewrap_crash`, `test_double_crash_then_recover` |
| Fault hook is off by default and unreachable from adapter input | measured | `test_the_hook_is_not_reachable_from_adapter_input` (sends it as request fields, exit 0) |
| Recovery time | **measured: 92.9 ms worst** (acceptance), 89.9 ms on a re-run | acceptance `goal3/recovery-time` |
| Crash during a *backup* or *restore* | **not tested** | only rotation and recovery are crash-tested |
| Power-loss rather than process kill | **limit** | `os._exit` skips cleanup; a real torn page is not simulated |

## Goal 4 — Backup integrity

| Claim | Status | Evidence |
| --- | --- | --- |
| Single authenticated blob: encrypted + signed + manifest | measured | `pqc_kv/backup.py`; `test_a_good_backup_restores_exactly` |
| Restore verifies BEFORE using anything | measured | `test_restore_does_not_use_any_material_before_verification` (key files byte-identical after refusal) |
| Bit flip in every region detected | measured | 10 regions × 3 offsets; `test_a_single_bit_flip_is_detected`, `test_a_flip_anywhere_in_a_region_is_detected` |
| Truncated backup refused | measured | `test_a_truncated_backup_is_refused`, acceptance `goal4/truncation` |
| Swapped manifest refused | measured | `test_a_swapped_manifest_is_refused` |
| Stale backup replay refused (rollback) | measured | `test_restoring_an_older_backup_cannot_resurrect_a_revoked_key` |
| A good backup restores exactly | measured | `test_a_good_backup_restores_exactly`, acceptance `goal4/restore` |
| Backup key supplied by the operator, not stored | measured | `test_the_backup_key_is_required_and_never_stored` (scans the whole state dir) |
| Rollback marks cannot be forged | **limit** | they live in the state directory; whoever writes it can lower them |
| Restore into a fresh directory detects rollback | **not possible without an external anchor** — documented | `backup.py` docstring, §P3-4 |
| Backup size/time for a realistic key set | **not measured** | — |

## Goal 5 — Log integrity

| Claim | Status | Evidence |
| --- | --- | --- |
| Every rotation/revocation/enrolment/backup/restore/recovery is logged | measured | `test_every_lifecycle_action_lands_in_the_signed_log` (revoke, rotate, restore); `recover` asserted in `test_recovery_preserves_the_audit_chain` |
| Hostile text cannot create a second event | measured | **fuzz: 406 strings, 405 refused, 1 accepted, 0 forged** — `test_fuzz_hostile_strings_never_produce_a_second_event` |
| Hostile text cannot alter the recorded actor | measured | `test_fuzz_a_hostile_actor_cannot_change_the_recorded_actor`, `test_a_revoked_actor_with_a_hostile_name_cannot_inject_a_log_event` |
| Records keep their original boundary | measured | `test_every_emitted_line_is_a_single_json_object`, `test_a_newline_in_an_identifier_cannot_split_a_record` |
| Chain PLUS signature | measured | every record individually signed; `test_every_record_carries_a_valid_signature` |
| Verify op reports ok/broken and the first bad record | measured | `verify()` returns `first_bad`; acceptance `goal5/edit-detected` |
| Head digest exportable for an external anchor | measured | `log_head` / `log_events_head`; `test_the_head_is_exportable_for_external_anchoring` |
| Edit / delete / reorder / insert / truncate each detected | measured | 5 separate tests in `tests/test_phase3_log.py` |
| Truncation without an anchor | **limit** — invisible; a shorter valid chain is still valid | `test_a_truncated_log_still_verifies_without_an_anchor` asserts the limit explicitly |
| Full rewrite by someone holding the signing key | **limit** — undetectable | `test_a_whole_file_rewrite_with_the_real_key_is_not_detectable` asserts the limit explicitly |
| External anchor shipped off-box automatically | **not built** | the operator must store the head themselves |

---

## Checklist coverage after Phase 3

| # | Goal | Status |
| --- | --- | --- |
| 1 | Key rotation | **covered** — versioned ring, counted cutoff, non-destructive rotate |
| 2 | Revocation across nodes | **covered** — signed notices, 3 nodes, offline catch-up, re-enrolment; single-publisher limit |
| 3 | Crash recovery | **covered** — intent log, 5 real kill points, revocation preserved |
| 4 | Backup integrity | **covered** — damage/tamper/rollback all refused; state-dir limit stated |
| 5 | Log integrity | **covered with a stated limit** — signed chain + anchor; no default external sink |
| 6 | Routine and suspicious activity | untouched (Phase 4) |
| 7 | Lateral movement | untouched (Phase 4) |
| 8 | Clock differences | untouched, but Phase 3 adds no clock dependence: rotation grace, revocation ordering and rollback checks are all integer counters |
| 9 | Replay and recipient binding | covered in Phase 2 |
| 10 | Forward secrecy | covered in Phase 2 |
| 11 | Delivery under loss/reordering | covered in Phase 2 |
| 12 | Session resumption | covered in Phase 2, with a budgets-not-clocks limit |
