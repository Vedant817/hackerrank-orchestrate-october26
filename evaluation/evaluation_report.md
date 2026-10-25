# Evaluation report - Ghost Data Still Exists

This report is **generated from the harness**, not transcribed: every number below comes
from `code/evaluation/main.py` run against the **public** sample answers
(`dataset/sample_output.csv`, 32 requests) and the authored fixtures. The sample labels
are read only inside the harness, after the predictions exist; they never enter the
prediction path or the audit core. The model pipeline is **deterministic**: it makes zero
runtime model calls (see `usage_report.md`). AI assistance was used during development,
not at runtime.

Reproduce (from the repository root):

```bash
python code/evaluation/main.py                       # full metrics (Markdown)
python code/evaluation/main.py --json                 # machine-readable metrics
python code/evaluation/custom_cases.py                # the authored cases (self-contained; no flags)
python code/evaluation/usage.py --dataset dataset      # measured runtime usage
python -m pytest code/tests -q                        # all tests
python -m ruff check code                             # lint
```

From `code/` (`cd code` first) the same runs work without the `code/` prefix:

```bash
python -m evaluation.main --dataset ../dataset
python -m evaluation.custom_cases
python -m evaluation.report_gen      # regenerate both report mirrors from live metrics
python -m pytest tests -q
```

A dataset supplied **outside** the repository is supported explicitly by the runner and
the metrics harness; the authored-case runner is self-contained and takes no dataset:

```bash
python code/evaluation/main.py --dataset /path/to/supplied/dataset
python code/main.py --dataset /path/to/supplied/dataset
# or set GHOSTWATCH_DATASET once and omit --dataset (runner and evaluator both honour it)
```

## 1. Scope and method

- **Prediction path.** `python code/main.py` loads the participant dataset, runs the
  accepted audit core (`code/ghostwatch`) over every request, validates each row against
  the §6.3/§6.4 contract, and writes the root `output.csv` atomically. The release gate is
  **split** (T04 parent decision): a **contract** problem (schema, citations, ordering,
  status vocabulary, empty future `evidence_id`) always refuses the write, while a
  contract-clean run whose only remaining limitation is a genuine **evidence** gap writes
  the answer and discloses the affected cases. `--require-certifiable` restores the strict
  fail-closed gate for internal verification.
- **Labels.** `dataset/sample_output.csv` is opened only by `evaluation.main.load_labels`,
  which is called after `run_sample_evaluation` has computed every prediction.
  `test_sample_labels_never_enter_predictions` asserts this ordering.
- **Two separate step metrics.** The evaluation reports two metric families that are
  defined on *different* alignments, and it never mixes them:

  | Family | Alignment | Scored fields |
  | --- | --- | --- |
  | *Exact-step* precision / recall / F1 and whole-array exact-sequence | six-field identity (`phase`, `operation`, `system_id`, `resource_id`, `state`, `evidence_id`) | all six, as an exact multiset identity |
  | *Field* accuracy and evidence agreement | `(phase, operation)` groups, positional one-to-one | `system_id`, `resource_id`, `state`, `evidence_id` |

  The alignment key for the field metric (`phase`, `operation`) is **disjoint** from the
  fields it scores, so no scored value can influence whether a pair exists. This is the
  non-circularity property the harness asserts directly in
  `test_alignment_key_is_disjoint_from_scored_fields`.

## 2. Public sample metrics (32 requests, disclosed denominators)

| Metric | Count | Rate |
| --- | --- | --- |
| Case-status accuracy | 27/32 | 84.4% |
| Exact-step precision (micro) | 137/144 | 95.1% |
| Exact-step recall (micro) | 137/193 | 71.0% |
| Exact-step F1 (micro) | — | 81.3% |
| Exact-sequence match (whole array) | 2/32 | 6.2% |
| Field accuracy (independent alignment) | 523/792 | 66.0% |
| Evidence agreement (independent alignment) | 54/75 | 72.0% |

**Denominators (why they are what they are).**

- Field denominator: `field_total = ALIGNED_PAIRS × 4 + UNMATCHED_EXPECTED × 4 +
  UNMATCHED_PREDICTED × 4` = 139 × 4 + 54 × 4 +
  5 × 4 = 792. Missing, extra, duplicate and
  permuted steps therefore *increase* the denominator and the error count; a mismatch can
  never shrink them (the defect the reviewers found in the previous revision, where a
  wrong field silently removed the pair and left the rate at 100%).
- Field errors: 269 of 792 scored fields disagree.
- Evidence denominator: 75 label steps carry a non-empty `evidence_id`;
  55 of them sit in aligned pairs (and can match), while
  20 belong to unmatched label steps that are counted in the
  denominator but can never match. The structural ceiling is therefore
  55/75
  (73.3%),
  not 100%; the missing entries are counted as errors, exactly like every other scored
  field. A missing or different id counts as an error rather than dropping the row.

**Reading these numbers honestly.**

- *Exact-step precision* is over the strict six-field identity: a step that is right in
  every way but its `evidence_id` counts as both a false positive and a false negative.
  This is deliberately strict, and it is a *separate* metric from field accuracy.
- *Case-status accuracy* is 27/32. The five wrong cases are `case_01` (label COMPLETE, predicted INCOMPLETE), `case_02` (label COMPLETE, predicted INCOMPLETE), `case_04` (label COMPLETE, predicted INCOMPLETE), `case_10` (label INCOMPLETE, predicted COMPLETE), `case_12` (label INCOMPLETE, predicted COMPLETE).
- *Field accuracy and evidence agreement* are now genuinely informative: a single wrong
  scored field in a three-step plan raises `field_errors` by 1 while keeping
  `field_total` fixed. See `test_field_metric_is_not_circular`.

## 3. Exact-step difference census (derived, not transcribed)

Both counts use **one declared definition**: a false negative is a label step with no
identical predicted step and a false positive is a predicted step with no identical label
step, compared as **multisets** over the six serialized fields. Verified with
`test_public_sample_census_matches_the_reported_numbers`.

- Matched steps (TP, prediction ∩ label): **137**
- Label steps with no identical prediction (FN): **56**
- Predicted steps with no identical label (FP): **7**
- **Net difference** (predicted − label): **-49** = FP − FN = 7 − 56

The net difference is deliberately *not* the same as the false-negative count: 56 steps
are missing and 7 are extra, so the prediction is 49 steps shorter, not 56. Reporting the
FN count as the net difference (or vice versa) would overstate the shortfall by the seven
extra steps.

| Operation | Missing (FN) | Extra (FP) |
| --- | --- | --- |
| `DELETE_RECORD` | 3 | 0 |
| `DISABLE_DATA_FLOW` | 0 | 1 |
| `REDACT_RECORD` | 1 | 0 |
| `REPORT_ACTIVE_DATA_FLOW` | 0 | 1 |
| `REPORT_EXPOSED_PII` | 1 | 0 |
| `REPORT_REMAINING_RECORD` | 3 | 0 |
| `VERIFY_DATA_FLOW_DISABLED` | 0 | 1 |
| `VERIFY_RECORD_ABSENT` | 31 | 2 |
| `VERIFY_RECORD_ANONYMIZED` | 7 | 0 |
| `VERIFY_RECORD_PRESENT` | 9 | 0 |
| `VERIFY_RECORD_REDACTED` | 1 | 2 |
| **Total** | **56** | **7** |

| System | Operation | Missing (FN) | Extra (FP) |
| --- | --- | --- | --- |
| `account_service` | `VERIFY_RECORD_ABSENT` | 28 | 1 |
| `analytics_platform` | `DELETE_RECORD` | 1 | 0 |
| `analytics_platform` | `REPORT_REMAINING_RECORD` | 1 | 0 |
| `analytics_platform` | `VERIFY_RECORD_ABSENT` | 1 | 0 |
| `analytics_platform` | `VERIFY_RECORD_ANONYMIZED` | 7 | 0 |
| `security_service` | `VERIFY_RECORD_PRESENT` | 9 | 0 |
| `support_platform` | `DELETE_RECORD` | 2 | 0 |
| `support_platform` | `REDACT_RECORD` | 1 | 0 |
| `support_platform` | `REPORT_EXPOSED_PII` | 1 | 0 |
| `support_platform` | `REPORT_REMAINING_RECORD` | 2 | 0 |
| `support_platform` | `VERIFY_RECORD_ABSENT` | 2 | 1 |
| `support_platform` | `VERIFY_RECORD_REDACTED` | 1 | 1 |
| `identity_service` | `VERIFY_RECORD_REDACTED` | 0 | 1 |
| `integration_service` | `DISABLE_DATA_FLOW` | 0 | 1 |
| `integration_service` | `REPORT_ACTIVE_DATA_FLOW` | 0 | 1 |
| `integration_service` | `VERIFY_DATA_FLOW_DISABLED` | 0 | 1 |

| Case | System | Operation | Extra (FP) |
| --- | --- | --- | --- |
| `case_07` | `support_platform` | `VERIFY_RECORD_ABSENT` | 1 |
| `case_10` | `support_platform` | `VERIFY_RECORD_REDACTED` | 1 |
| `case_12` | `account_service` | `VERIFY_RECORD_ABSENT` | 1 |
| `case_15` | `integration_service` | `DISABLE_DATA_FLOW` | 1 |
| `case_15` | `integration_service` | `REPORT_ACTIVE_DATA_FLOW` | 1 |
| `case_15` | `integration_service` | `VERIFY_DATA_FLOW_DISABLED` | 1 |
| `case_17` | `identity_service` | `VERIFY_RECORD_REDACTED` | 1 |

`case_15` accounts for 3 of the 7 extra steps (an `integration_service` data-flow trio:
`REPORT_ACTIVE_DATA_FLOW` / `DISABLE_DATA_FLOW` / `VERIFY_DATA_FLOW_DISABLED` on
`data_flow_1121`); the remaining four belong singly to `case_07`, `case_10`, `case_12` and
`case_17`.

## 4. Full-dataset run that produced the submitted `output.csv`

The normal run audits all 518 requests, validates the contract, and writes the
repository-root `output.csv` atomically:

| Check | Result |
| --- | --- |
| Rows produced | 518 (one per request id, sorted by `case_id`) |
| Contract problems (schema / order / citations / empty plans) | 0 |
| Status split | COMPLETE 156 · INCOMPLETE 352 · NOT_APPLICABLE 10 |
| Run digest (sha256 over `case_id\tdeletion_status\tsteps_json\n`) | `1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899` |
| Evidence-limited cases (written `INCOMPLETE`, disclosed) | 4 — `case_46`, `case_55`, `case_61`, `case_63` |
| Certifiable (no evidence-limited case) | No — 4 remain |
| Final `output.csv` written | **Yes** — the root answer was written by this run |

The digest is identical to the accepted T02 core digest, proving the runner adds no
non-determinism and does not alter the core's decisions. The T04 split gate changed only
*whether* the run may write, never *what* it decides: the four evidence-limited rows stay
honestly `INCOMPLETE` with their reviewed plans and are named in the run output, here, and
in `usage_report.md`. They are **not** certified complete deletion (see §7).

## 5. Failures found and improvements made

### 5.1 Failure — the audit under-emits verification steps (measured)

Across the 32 samples the audit emits **56 fewer** steps than the labels matched by identity (137 matched of 193 label steps), with 7 extra steps, for a net difference of **-49**.

The missing steps are dominated by `account_service` absence checks; the per-operation and
per-system tables are in §3 and are computed by the harness, so they cannot drift.

**Diagnosis.** The audit's scoped-relevance rule emits a duty check only when the evidence
grounds that duty for the specific resource. For roughly one step per case the label
expects an `account_service` absence check that the current evidence-grounded relevance
does not raise, and for a handful of cases an `analytics_platform` anonymize or
`security_service` presence check. Three of the 32 samples (`case_01`, `case_02`,
`case_04`) have **no** grounded evidence at all, so the audit correctly returns
`INCOMPLETE` with an empty plan (fail-closed) while the label expects `COMPLETE` — an
honest "cannot certify" result rather than a bug.

**Improvement made (within T03 scope).** The runner validates every emitted row against
the contract and *reports* the shortfall instead of hiding it. The fix for the
under-emission itself belongs to the audit core (T02 scope) and is **not** applied here:
T03 may not edit the reviewed core. It remains the primary accuracy limitation (§8).

### 5.2 Failure — rule-condition divergence on two samples (`case_10`, `case_12`)

For `case_10` and `case_12` the audit returns `COMPLETE` where the label expects
`INCOMPLETE`.

- `case_10`: the audit reads the support record `support_002` as the policy-described
  shared-context REDACT state and certifies the case; the label expects the support record
  to still be present and require deletion.
- `case_12`: the audit misses an `analytics_9914` copy and a retained `audit_record_2945`,
  so it certifies on the single account absence it did find.

**Diagnosis.** These turn on the `rule_05`/`rule_06` condition predicates
("conversation contains shared context" / "attachment belongs only to the subject"). Where
the evidence does not ground sole ownership, the policy layer defers to the safer
shared-context REDACT treatment (a deliberate, documented choice); the labels show the
stricter treatment for these two rows. This is the residual, non-blocking
condition-mapping limitation disclosed in the T02 reviews.

**Improvement made.** None in T03 (core scope). Recorded here so the limitation is
explicit and the case ids are reproducible.

### 5.3 Failure — three empty sample plans (`case_01`, `case_02`, `case_04`)

These three sample subjects resolve in the identity index but have **zero** grounding
activity rows and **zero** evidence records in the participant data. The audit cannot
evidence a completeness claim, so it returns `INCOMPLETE` with `[]` rather than a
fabricated `COMPLETE`. The label expects `COMPLETE`. This is the fail-closed behaviour
working as designed; the accuracy cost is the consequence of genuinely absent evidence.

### 5.4 Improvement — non-circular field and evidence metrics

The previous revision aligned steps on the six serialized fields and then re-scored a
subset of them, so `field_accuracy` was definitionally 100% and could never detect a
wrong field. Both independent reviewers reproduced this (a three-step fixture with one
wrong `system_id` scored 10/10 = 100.0%, with the denominator collapsing from 15 to 10).
The metric is now computed over an independent alignment whose grouping key is disjoint
from the scored fields, with unmatched steps contributing their fields as errors. The
measured public-sample field accuracy moved from the tautological **685/685 (100.0%)** to
a genuine **523/792 (66.0%)**, and evidence agreement from the
tautological **55/55 (100.0%)** to **54/75 (72.0%)**.
Regressions: `test_field_metric_is_not_circular`,
`test_alignment_key_is_disjoint_from_scored_fields`,
`test_missing_and_extra_steps_increase_denominators`,
`test_field_alignment_matches_across_duplicated_operations`.

### 5.5 Improvement — the runner writes a contract-valid answer and refuses only bad ones

Before T03 there was no CLI. The runner now:

1. audits every request and validates the full contract surface (status vocabulary, JSON
   array, exact seven fields, consecutive numbering, phase grouping, canonical order, empty
   `evidence_id` on proposed remediation/future verification, real citations on findings and
   COMPLETE verification, citation existence against the manifest/activity/audit ids);
2. **fails closed on any contract problem** — the problems are printed and the run exits
   non-zero **without touching** the previous `output.csv` (atomic temp-file +
   `os.replace`);
3. **writes the final answer when the run is contract-clean**, even if genuine evidence
   limits remain, naming the limited cases and keeping them `INCOMPLETE` (T04 decision);
4. cannot be bypassed for the real root path: `--allow-partial` refuses the root `output.csv`
   location; the only draft path is `--diagnostic`, which writes to `code/evaluation/`.

`test_invalid_run_does_not_replace_output` and
`test_contract_problem_still_refuses_and_preserves_output` prove (2) with a sentinel file
and a genuine injected contract problem;
`test_normal_run_writes_final_output_when_only_evidence_limits_remain` proves (3), and
`test_require_certifiable_refuses_on_evidence_limits` proves the strict mode still refuses.

## 6. The seven extra steps and the ordering contract

The audit emits 144 steps where the labels have 193 across the samples, so 7 predicted steps have no identical label counterpart (the per-case breakdown is in §3). None is fabricated: every
extra step names a real resource and, where it is a finding, cites a real in-window
evidence id. The runner's validator confirms **zero** canonical-order violations across
all 518 rows, so array ordering is correct even where the step set differs.

## 7. The four evidence-limited cases (disclosed, written `INCOMPLETE`)

The audit core fails closed while four genuine evidence gaps remain unresolved. Their
rows are still written to the submitted `output.csv` — the competition requires one row
per case — and each is honestly `INCOMPLETE` with the reviewed plan and verification
checks that must pass once the gap is closed with real evidence:

| Case | Gap | What the audit cannot certify |
| --- | --- | --- |
| `case_46` | ACCOUNT_TOMBSTONE coverage | The catalogue links `tombstone_17`, but the only in-window artifact names the stable `user_17`, not the tombstone row. |
| `case_55` | BACKUP_ARCHIVE evidence | `backup_9287`'s only direct state evidence is captured after `audit_at`; correctly excluded. |
| `case_61` | SUPPORT_ATTACHMENT coverage | `object_19` is grounded by a catalogue statement but appears in no evidence file. |
| `case_63` | MARKETING_PROFILE coverage + contradiction | The catalogue links `marketing_001`, but the reachable artifact exposes a different, unregistered person. |

These are genuine "cannot certify" limits, not
defects to be papered over: resolving them requires evidence the dataset does not contain,
and fabricating a `COMPLETE` would be the exact failure the challenge warns against. They
are therefore **not certified complete deletion** — the limitation is disclosed here, in
the run summary and in `usage_report.md`, and the strict gate
(`python code/main.py --require-certifiable`) still refuses to release while any of them
stands (`test_require_certifiable_refuses_on_evidence_limits`). The T04 release decision is
that withholding the mandatory 518-row `output.csv` would not improve honesty: the four
rows already say `INCOMPLETE` with the plan needed to finish the audit.

## 8. Authored evaluation cases

Four cases were authored (the contract requires at least three). Each builds a
self-contained fixture, runs the real core, and asserts the expected behaviour.

| Case | Focus | Expected status | Predicted status | Result |
| --- | --- | --- | --- | --- |
| `historical_identifier` | historical identifier resolution | COMPLETE | COMPLETE | PASS |
| `temporal_recreation` | temporal recreation by an active flow | INCOMPLETE | INCOMPLETE | PASS |
| `tombstone_retention` | tombstone redaction and retention | COMPLETE | COMPLETE | PASS |
| `late_evidence_ignored` | audit_at cutoff | COMPLETE | COMPLETE | PASS |

4/4 authored cases pass.

- **`historical_identifier`** — the request arrives under the subject's *historical* email
  (changed per `user_audit_log.csv`). The audit resolves the same subject, proves the account
  record absent from the declared-complete snapshot (`VERIFY_RECORD_ABSENT account_service
  customer_profiles`), and proves the retained security record present
  (`VERIFY_RECORD_PRESENT security_service audit_record_hist`).
- **`temporal_recreation`** — a `SYNC_RECORD` job recreates the profile in the search store
  after the "successful" deletion. The audit returns `INCOMPLETE` with a cited
  `REPORT_REMAINING_RECORD`, a `REPORT_ACTIVE_DATA_FLOW`, and the ordered remediation
  `DISABLE_DATA_FLOW` → `DELETE_RECORD` → the post-remediation checks. It never trusts the
  workflow's `COMPLETE` claim.
- **`tombstone_retention`** — the account tombstone keeps the stable `user_id` while the
  direct identifiers are nulled. The audit emits `VERIFY_RECORD_REDACTED identity_service
  tombstone_tomb` (never a delete/absence against the tombstone) and `VERIFY_RECORD_PRESENT
  security_service audit_record_tomb` for the retained record.
- **`late_evidence_ignored`** — a file captured after `audit_at` shows the record
  reappearing. The audit answers from the in-window snapshot and never cites `evidence_late`.

## 9. What "complete" means in this submission (relevance-limited certification)

156 of the 518 predictions are `COMPLETE`. Of those:

- **80 carry no delete-duty verification** because no delete duty is *grounded* for the
  subject by any participant evidence under the scoped relevance rule;
- **84 have an empty relevant-duty set** (72 have a non-empty set, so the machinery is
  non-vacuous).

This is a **relevance-limited** certification, not proof that an identified copy of the
subject was deleted. The output vocabulary cannot encode a qualifier, so the caveat lives
here and in `plan_complete.diagnostics`. No narrative in this submission may be read as
proving deletion of an identified copy where none was grounded.

## 10. Unavailable metrics (not estimated)

- **Hidden-set accuracy is unknown.** Only 32 public samples exist; the evaluation set's 518
  labels are not available. No accuracy claim is made about the hidden canonical answers.
- **Step-level exactness on the hidden set** is likewise unknown; the public metrics above are
  the only measured basis.
- **Runtime token/cost** is not estimated: the deterministic pipeline makes zero model calls
  (see `usage_report.md`), and no rate is configured.

## 11. Summary of limitations

1. The audit under-emits verification steps (a core-scope coverage limit, out of T03 bounds).
2. Two samples show a rule-condition divergence (`case_10`, `case_12`) inherited from the
   policy layer's scoped condition mapping.
3. Three samples (`case_01`, `case_02`, `case_04`) have no grounded evidence and return an
   honest empty `INCOMPLETE`.
4. Four genuine evidence limits (`case_46`, `case_55`, `case_61`, `case_63`) keep those
   rows honestly `INCOMPLETE`; they **are** written to the submitted `output.csv` and are
   disclosed in the run summary, §4 and §7. They are not certified complete deletion, and
   the strict gate (`--require-certifiable`) still refuses the release while they stand.
5. The field/evidence metrics align steps positionally within a `(phase, operation)` group.
   A group whose members are permuted *and* differ in a scored field is therefore scored
   positionally; whole-array order is measured separately by the exact-sequence metric.
6. OCR/PDF extraction depends on `pypdf`/`Pillow` and, for screenshots, a system OCR backend
   (Windows built-in, or `pytesseract`); missing backends fail loudly rather than skipping.
