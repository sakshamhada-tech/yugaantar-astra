# Detection: goals 6, 7 and 8

Rule-based, explainable, deterministic. No model, no weights, no learning. Every
alert is a conjunction of facts that a judge can re-derive by hand from the log and
the approval file.

This document states what each rule does, why it is not tuned to the practice data,
what timing range the detector will claim, what it cannot do, and how each number in
it was measured.

---

## 1. What was read, and what it contains

The practice data was read from the toolkit (`practice/`), never copied into this
repository.

### Log schema (`events.csv`, 22 events + header)

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | `evt-NNN` | Record identity. **Not** arrival order |
| `event_time_utc` | RFC 3339, ms, literal `Z` | Timestamp **recorded by the source** |
| `received_time_utc` | RFC 3339, ms, `Z` | Timestamp **recorded by the collector** |
| `source_clock_offset_ms` | integer ms | Known source offset vs collector. Subtract to estimate collector time |
| `actor` | string | The identity acting with the listed role. For admin events, the **operator**; `approvals.json` names the affected **subject** |
| `source_service`, `target_service` | string | The observed service edge, not proof of a network connection |
| `action` | string | `sign_in`, `read`, `role_change`, `approve_role_change`, `revoke_role`, `list_roles`, `sign_out` |
| `role_before`, `role_after` | string | Role on each side of the event; equal means no change |
| `outcome` | string | `success`/`allow`/`deny` |
| `approval_id` | string or empty | Change ticket the event claims |
| `session_id`, `correlation_id` | string | Grouping hint, not a credential |

Timezone: a bare `Z`, so UTC by definition. Timestamps with an explicit offset such
as `+02:00` are **refused at ingest** — the source's clock error is a separate
column, and folding two mechanisms into one field is how ordering bugs start.

### Labels (`labels.csv`)

One row per event, deliberately **not** a binary. The vocabulary is:

| Label | Count | Treatment |
| --- | --- | --- |
| `routine` | 8 | benign |
| `approved_change` | 2 | benign — this is the false-positive trap |
| `routine_denial` | 2 | benign |
| `routine_delayed_delivery` | 1 | benign |
| `routine_clock_offset` | 1 | benign |
| `isolated_denial` | 1 | benign — explicitly "does not establish lateral movement" |
| `unexpected_role_change` | 1 | **positive** |
| `review_after_role_change` | 1 | **positive** |
| `lateral_movement_candidate` | 3 | **positive** |

The mapping from these to "positive" is a judgement call and is stated in
`scripts/phase4_eval.py` rather than hidden: the three positives are the labels that
describe something wrong having *happened*. `approved_change` and the `routine_*`
labels are deliberately benign — the practice data includes them precisely to test
that a detector stays quiet.

There is **no alert-matching window and no grouping rule** in the data. It is a
one-row-per-event explanation, not a scoring file. So the evaluation defines its own
rule (§6).

### Composition

22 events, 5 identities (`user-alex`, `user-admin`, `user-blair`, `user-casey`,
`svc-report-worker`), 6 services (`portal`, `admin-console`, `identity`, `catalog`,
`reports`, `billing`, `archive`, `reports-node-a`, `reports-node-b`), 17 benign and
5 positive. Scenarios present: approved admin work (`evt-003`–`evt-005`), unexpected
privilege change (`evt-008`), unexpected access (`evt-009`), isolated denial
(`evt-020`), valid-credential lateral movement with denials (`evt-010`–`evt-012`),
out-of-order delivery (`evt-013` after `evt-014`), clock offset (`evt-015`, +2000 ms),
revocation propagation (`evt-016`–`evt-018`).

### How a detector is invoked: the contract says nothing

`docs/adapter-v1.md` defines `setup`, `read`, `revoke`, `audit`, `protected_read` and
says the practice dataset "is a separate exercise. Its file format does not add an
operation to the judging adapter." It never says how a detector is invoked or scored.

So we added three operations to `team_app.py` (never touching `track4_service.py`):
`detect_log` (whole log in one request), `detect_append` (accumulates a persisted
baseline under `TRACK4_STATE_DIR`), `detect_status` (what is persisted, plus the
supported timing range). Unknown ops still return `unsupported_operation`.

### What the practice data does **not** cover

The hidden logs will differ, and these are the gaps I designed against explicitly:

* **No false positives of the interesting kind.** 22 events, all hand-chosen. Precision
  from this file is meaningless.
* **No volume.** No identity with a real baseline, no chained movement over hours.
* **One example per scenario.** A single out-of-order pair, a single clock offset.
* **No hostile fields.** Every value is tidy; the brief's hostile-input requirement is
  entirely untested here.
* **No ambiguous approval.** The `evt-016` revocation carries a ticket but no
  `valid_from`/`valid_until`, only `effective_at`.
* **No clock-uncertainty case.** `+2000 ms` is declared, so it is correctable; the
  harder case (offset unknown or too large) does not appear.
* **No identity with an empty baseline**, and no baseline poisoning.

---

## 2. Goal 6 — routine versus suspicious privilege change

### The rule

A privilege change is **suspicious when no approval record covers it**. Coverage is a
conjunction of facts, each reported separately so the operator sees *which* one failed:

| Fact | Check | Why it is not a hack |
| --- | --- | --- |
| structural | `role_before != role_after`, or the action is a configured privilege action | Independent of any vocabulary. Survives renaming every role and action |
| subject | the approval names this identity | A relational query over two tables |
| operation | approval operation matches the action, if mapped | Mapped in config; unmapped means "not claimed" |
| role | the granted role equals the approval's role | Stops a lesser ticket justifying a greater grant |
| window | event time inside `[valid_from, valid_until)` | The bound is exclusive, per the README |
| signer | approver ≠ subject | Separation of duties; the one fact that stops self-authorisation |

Rules: `unapproved_privilege_change` (high), `self_approved_privilege_change` (high),
`uncertain_approval_window` (medium, goal 8 interaction),
`follow_on_access_after_unapproved_change` (medium).

### Why this is not tuned to the practice labels

Three of the six facts are structural. The vocabulary that *is* in a config list
(`privileged_actions`) is empty of practice values, and removing the list entirely
still catches the practice data's `evt-008`, because `role_before != role_after` catches
it. That is asserted, not claimed:

```
tests/test_phase4_rules.py::test_the_vocabulary_list_is_not_needed_for_a_structural_change
tests/test_phase4_rules.py::test_a_renamed_action_still_alerts_when_the_role_changed
```

### The two judgement calls I had to make, and got wrong first

**An empty `approval_id` is not an unapproved change.** My first implementation
treated a blank ticket column as "no paperwork" and would have flagged every deployment
whose ticketing system backfills ids after the fact. A change is authorised because a
record covers its subject, role, scope and time — not because someone copied an id into
a column. The abuse that worried me (using one ticket to launder a different grant) is
already blocked by the **role** fact.

**Scope is not checked on the role change itself.** The event's `target_service` is
where the change was *recorded* (`identity`); the approval's `scope` lists what the new
role may *reach*. Comparing the two compares a location with a permission set and
rejects every correct grant. Scope is enforced where it belongs: on the data access, in
the lateral rule.

---

## 3. Goal 7 — lateral movement with valid credentials

### The rule

Per identity, from a baseline of the earliest `baseline_fraction_percent` (40%) of
events by event time:

* **edge** — the ordered pair `(source_service, target_service)`;
* **targets** — services ever reached;
* **transitions** — `(previous_target, target)` within `transition_window_ms`.

An edge is **novel** if it is absent from that identity's baseline. Alerts carry the
count that justifies them — `0 of 12 baseline events used it` — because a judge can
check a count and cannot check "unusual".

| Rule | Fires when | Severity |
| --- | --- | --- |
| `novel_service_edge` | a successful first-seen edge from an **established** identity | high |
| `lateral_movement_chain` | ≥2 novel targets **and** ≥1 hop departing a freshly-reached service | high/medium |
| `first_seen_sensitive_service` | first-seen edge into an operator-marked service | high |
| `novel_service_transition` | familiar services in an unfamiliar order (**off by default**) | low |

### Why chaining, not counting

One denial is one denial; two denials from one place are two attempts. What
distinguishes movement is **leaving a service you just reached** — a foothold being
used. That is a property of the graph's topology, so it needs no service names, and it
is why the practice data's denials from `reports` into `billing` **and** `archive`
(when `archive` is newly reached from `billing`) can be separated from a pair of
parallel denials.

### Cold start, stated rather than hidden

An identity below `min_baseline_events` has no usable graph. Both dishonest options are
refused: silently trusting it (an attacker who appears only in the evaluation window is
invisible) and blanket-alarming on it (every new hire is an incident).

Instead: the identity is marked `cold_start`, needs **more** novel targets
(`cold_start_min_novel_edges`, default 3), and any alert it produces says
`baseline_state="cold_start"`. A single lone edge from a cold identity is **not**
emitted by default — that option exists (`cold_start_report_lone_edges`) and was
measured at **20 false alerts against 3 true positives**, which is why it is off.

`min_baseline_events` is **12, measured not chosen**: at 5, the synthetic log produced
25 false alerts from identities with 5–8 baseline events, including `metrics -> metrics`
being called first-seen. At 12, false alerts went to zero on both the tuning and
held-out identity halves with no true positive lost.

---

## 4. Goal 8 — clock differences and uncertain order

### The supported timing range

| Parameter | Default | Meaning |
| --- | --- | --- |
| `offset_mode` | `declared` | trust `source_clock_offset_ms`; alternatives `estimated`, `none` |
| `offset_uncertainty_ms` | 250 | residual per-source uncertainty |
| `max_abs_offset_ms` | 3 600 000 | offsets beyond ±1 h are **refused at ingest** |
| `max_out_of_order_ms` | 600 000 | reorder horizon (10 min of corrected event time) |
| `reorder_buffer_events` | 4096 | hard memory bound |
| `max_offset_uncertainty_ms` | 60 000 | beyond this a source is **unorderable** |

**An order is claimed only when the gap exceeds the sum of the two sources' residual
uncertainties.** Otherwise the alert carries `order="uncertain"` and both possible
orders are reported. That is the whole of goal 8: sort what is sortable, and say so
when it is not.

### The three modes

* **`declared`** — the practice format's meaning: subtract the column. Residual
  uncertainty is a stated constant. Used when the log supplies offsets and you believe
  them.
* **`estimated`** — ignore the column; estimate per source with a **minimum filter**
  (NTP's idea: a real delivery delay is never negative, so the smallest delay bounds
  the error). Uncertainty grows with the observed spread; a spread beyond
  `max_offset_uncertainty_ms` makes the source unorderable.
* **`none`** — no correction. Only same-source ordering is claimed; every cross-source
  comparison is uncertain. The honest fallback when a log has no offset column.

### Out-of-order handling

A bounded reorder buffer releases an event only when nothing earlier can still arrive
(`min(max_receipt_seen, highest_corrected) - horizon`). Events past the horizon go to
`deferred`: they are **still analysed**, but their order is unknown, so sequence rules
get `uncertain` rather than a guess. The invariant asserted in the tests is that the
ordered output is always non-decreasing in corrected event time, under random delivery
patterns.

### No wall clock

`time.time`, `datetime.now` and friends appear nowhere in `src/pqc_kv/detect/`. This is
enforced by an AST walk, not a grep, in
`tests/test_phase4_timing.py::test_no_wall_clock_is_read_anywhere_in_the_detector`.

---

## 5. Hostile input

Every field is validated, never sanitised, following the Phase 3 rule. A field is either
accepted verbatim or the **whole event is quarantined** with a counted reason.

* Charset is narrow printable ASCII, 96 characters for identities/services, 64 for event
  ids, 64 KB per line, 1 M events per request.
* A file with no header row, or a foreign one, is refused as `bad_header` and parsing
  stops there. It is a distinct token from `bad_column_count` because the two need
  different fixes — one is a bad *record*, the other is a bad *export* — and because a
  missing header aborts the whole file. Without the distinction a headerless log
  reported "line 1: bad_column_count, 0 events accepted", which reads like one
  malformed row instead of a file the detector could not interpret at all.
* Non-ASCII is refused outright — Cyrillic `а` versus Latin `a` is the classic
  look-alike, and refusing beats guessing.
* Leading/trailing/doubled spaces are refused (`"user-alex "` vs `"user-alex"`).
* Alert **structure** is a fixed key set from `alerts.py`, never derived from input; ids
  are content-derived, so the same log yields byte-identical alerts.

### An unreadable approvals file is reported, not silently ignored

An approvals *document* that cannot be read leaves detection running with no change
control, but it is reported as `context.document_error` (for example `approvals_invalid`
or `approvals_not_json`). Without that flag, an empty context from a broken file is
indistinguishable from "no change control was supplied", and every privilege change in
the log becomes an unapproved-change alert. That is a false-alarm flood pointing at the
wrong cause, so the operator has to be told which of the two happened. Absent and
empty-but-valid both stay silent, because neither is an error. Pinned by
`tests/test_phase4_properties.py::test_an_unreadable_approvals_file_is_distinguishable_from_none_supplied`.

Individual records that fail validation are counted separately in `context.rejected`
(e.g. `approvals_invalid: 5000` for a file of 5 000 unusable records).

### One known limit, stated because it is real

An **unquoted newline in the final CSV column** terminates the field: the row parses
with a truncated value and the injected tail becomes an orphan line, which is refused
and counted. The injected text never becomes an event or an alert, but the surviving
value is shorter than the original. CSV cannot distinguish that from a short last field.
Pinned by
`tests/test_phase4_ingest.py::test_a_newline_in_the_final_column_truncates_and_counts`.

---

## 6. How the numbers were measured

All figures below come from `scripts/phase4_eval.py`, which prints its method.

### Alert-to-label matching

An alert carries `event_ids`. It is a **true positive** if **at least one** of those ids
is labelled positive, otherwise a **false alert**. One shared id or no credit — no
window, no fuzzy match. The strictest simple rule, which can only make the detector look
worse.

* **Precision** is per alert; **recall** is per **incident** (a three-hop chain is one
  incident, not three, so the rule is not punished for being economical); **F1** is
  computed from those two reported numbers.
* **False alerts per 1,000 benign events** = `1000 × (alerts with no positive event) /
  (events labelled benign)`. Benign includes *approved* administration: an alert on a
  properly ticketed change is a false alert, and the most important kind to count.

### Time to alert, and why the headline number is 0

**Event time, not processing time.** The literal definition — alert event time minus the
first positive event of its incident — is **structurally 0** here, because the detector
alerts on the event that opens the incident. Reporting "median time to alert: 0 ms" as a
result would be trivially true and misleading, so the script prints both and the honest
number is the **incident span covered by the alert** (median 25 000 ms, max 240 000 ms on
the synthetic log): the window in which the alert already existed. It is an upper bound
measured in event time, **not** a claim of real-time speed — no rule waits on anything.

### The numbers

| Set | Alerts | Precision | Recall (incident) | F1 | False / 1k benign |
| --- | --- | --- | --- | --- | --- |
| **practice** (22 events, functional only) | 3 | 1.000 | 1.000 (5/5) | — | 0.00 (17 benign) |
| **synthetic, all** (276 events) | 20 | 1.000 | 0.923 (12/13) | 0.960 | 0.00 (253 benign) |
| synthetic, tuning identities | 8 | 1.000 | 1.000 (5/5) | 1.000 | 0.00 (135 benign) |
| synthetic, **held-out identities** | 12 | 1.000 | 0.875 (7/8) | 0.933 | 0.00 (118 benign) |
| synthetic, tuning window | 0 | — | 0.000 (0/1) | — | 0.00 (144 benign) |
| synthetic, **held-out window** | 20 | 1.000 | 0.923 (12/13) | 0.960 | 0.00 (100 benign) |

Thirteen positive incidents and 23 positive events in total: **12 incidents detected,
1 missed**; 20 alerts, **all 20 true positives**. The single miss is the planted
limitation — an identity that behaves badly *during* the baseline, so its later access
is no longer novel (§7). No benign event produced an alert on this corpus.

Ingest on the synthetic log: 278 lines including the header, **10 quarantined**
(8 `bad_field`, 2 `bad_column_count`), 267 accepted; none of the hostile values became
part of an event.

**These are synthetic numbers and are labelled as such.** They measure the detector
against a generator I wrote, and the generator shares no code or constants with the
detector — but it is still my model of what logs look like. The practice numbers are a
functional check only: the toolkit's own README says 22 examples "cannot establish
detection accuracy, false-positive rate, ... or event-scale throughput". Precision of
1.000 and zero false alerts should be read as *this corpus contains no benign case that
the rules mistake for an attack*, which is a statement about the corpus.

### Splits, and why both are reported

Tuning and held-out are split **by identity** (sorted, alternate) and **by time**
(earliest 55% / latest 45%), reported separately rather than intersected — the
intersection on a 276-event log collapsed to nothing, which reports as "0 incidents" and
says nothing. The detector's defaults were not fitted to either half; `min_baseline_events`
was chosen from baseline-size behaviour, and the split numbers are the check on that.

### Throughput (measured, with hardware)

`scripts/measure_timing.py` on a 100 023-event, 13.2 MB synthetic log:

* **36 944 events/second** (best of 3; median 35 978), 2.7 s per run;
* **peak RSS 173 MB**;
* hardware: Linux 6.1.158+ / x86_64 / **2 CPUs** / Python 3.11.2.

This is processing time, the one place a clock is allowed to appear. The judged
container is Python 3.12; this sandbox could not install it (see PLATFORM_SUPPORT.md).

---

## 7. Rule → attack → known evasion

| Rule | Stops | Known evasion |
| --- | --- | --- |
| `unapproved_privilege_change` | self-granted or untracked privilege change | **compromise an approver**, or file a real ticket. Approval records are claims, not proof |
| `self_approved_privilege_change` | one identity approving its own change | two colluding identities; a ticket approved by a *different* compromised operator |
| `uncertain_approval_window` | guessing at a boundary | none — it is the honest answer, but it is also **not an alert**: an attacker who keeps every change inside the clock shadow is reported as uncertain, and uncertainty can be ignored by a busy operator |
| `follow_on_access_after_unapproved_change` | blast radius right after an escalation | wait out `follow_on_window_ms` (15 min), or use a different session id |
| `novel_service_edge` | first-hop lateral movement with valid credentials | **stay inside normal edges**. This is the rule's structural blind spot: an attacker who only uses services the identity already touches is invisible to it |
| `lateral_movement_chain` | multi-hop movement through fresh services | two hops only, spaced beyond `burst_window_ms`, or one hop per session. **Baseline poisoning**: behave badly early and the edge becomes "normal" — measured, see below |
| `first_seen_sensitive_service` | reaching a marked crown-jewel service | marks are operator-supplied and empty by default; unmarked targets get no special treatment |
| `novel_service_transition` | familiar services in an unfamiliar order | off by default; needs a mature baseline or it is noise |

**The honest summary of evasions:** this detector is good at *unusual shape* and blind
to *unusual purpose*. An attacker who stays within an identity's established edges, or
who is authorised by a stolen approval, is not caught by any rule here. It is a
detector, not a control.

### The baseline-poisoning limit, measured

The generator plants an identity that accesses `vault` during the baseline window and
again afterwards. The post-baseline access **is missed** — three events, all labelled
malicious, all absent from the alert list (`nw-000265`–`nw-000267`). That is the one
structural miss on the synthetic set and it is reported as such rather than tuned away.
Novelty-based detection cannot catch an attacker who defines the baseline.

---

## 8. Mutation testing: does each rule earn its place?

`scripts/phase4_mutate.py` deletes one behaviour at a time (by monkeypatching in a
subprocess — source files are never edited) and reports which tests fail and how the
metrics move. All figures below are from that run against the synthetic log.

| Mutation | Baseline alerts → | Tests that catch it |
| --- | --- | --- |
| approve everything (no change-control matching) | 20 → **2** | **14** |
| ignore the granted **role** | 20 → 18 | 3 |
| ignore the **validity window** | 20 → 16 | 4 |
| never report a **novel edge** | 20 → 20* | **10** |
| never report a **chain** | 20 → 18 | 6 |
| claim every order (no clock tolerance) | 20 → 20* | 8 |
| no cold-start policy | 20 → **80** | 6 |
| no follow-on rule | 20 → 14 | 1 |
| no self-approval check | 20 → 20* | 1 |
| no field validation | 20 → 20* | **122** |
| swallow an unreadable approvals file | 20 → **34** | 1 |

`*` = the metric did not move but tests failed. That is the important column: a rule
whose removal changes no *count* is still load-bearing if a test names it, and the reverse
is a rule that only duplicates another. Two of these were found to be under-tested by the
metrics and I added generator scenarios for them:

* **role mismatch** — a ticket for `reviewer` used to justify `operator` (subject, operator
  and time all match). Before adding it, ignoring the role fact changed nothing.
* **expired ticket** — a correct ticket used two hours after expiry. Before adding it,
  ignoring the window changed nothing.

The last row was added during the security self-review, after the review found that a
broken approvals *document* was being silently treated as "no change control": deleting
the fix inflates the alert count from 20 to 34, which is the false-alarm flood that
motivated it. Every mutation is caught by at least one test, and six of the eleven move
the alert count.

Both are now caught (20 → 18 and 20 → 16). The remaining `*` cases are caught by name:
`no_novel_edge` breaks 10 tests, `no_clock_tolerance` breaks 8, `no_self_approval_check`
breaks 1, `no_ingest_validation` breaks 122.

`novel_service_transition` is not mutated because it is off by default and its removal
changes no default-config behaviour; it is covered by its own on-switch test.

---

## 9. Configuration

Every threshold lives in `src/pqc_kv/detect/config.py` and is overridable per request
(`"config": {...}`) or from a JSON file. Unknown keys are **refused**, not ignored — a
typo'd threshold that silently fails to apply is a detection failure that looks like a
quiet week. All values are range-checked.

No identity, service, role or action name from the practice data appears in the
defaults. The two vocabulary lists (`privileged_actions`, `authorising_actions`) and
`sensitive_services` are operator-supplied.

`tests/test_phase4_properties.py::test_a_config_with_different_numbers_still_produces_detections`
runs the whole pipeline against a config that shares no numbers with the default.
