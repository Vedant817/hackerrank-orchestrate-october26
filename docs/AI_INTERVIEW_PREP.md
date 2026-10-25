# AI Judge Interview Prep — Ghost Data Still Exists

A preparation pack for the 30-minute voice interview, tailored to this repository's submission.
Every answer below is grounded in the actual code, reports, and measured numbers. Speak from these;
do not memorize word-for-word.

Sources for the format/rubric are listed at the end. The domain-specific anchor is this repo's own
contract: the interview covers **architecture, investigation approach, remediation planning, and
evaluation** (`AGENTS.md` §6.9).

---

## 1. How the interview actually works

| Fact | Detail |
| --- | --- |
| Format | 30-minute voice interview with an AI judge, after submission; camera on is mandatory |
| Judge sees | Your `code.zip`/repo, your `output.csv`, and your AI chat transcript (`log.txt`) |
| Flow | Opening pitch → problem framing & failure modes → technical deep-dive into code and testing → production viability & monitoring → how you worked with AI tools (directed / accepted / pushed back on) |
| Overall weights | AI Judge interview 30% · output CSV 30% · code ZIP 30% · chat transcript 10% |

### Interview scoring rubric (official)

| Dimension | Weight | What it measures |
| --- | --- | --- |
| Technical depth & ownership | **40%** | Can you explain architecture, retrieval/classification logic, schemas, guardrails, and code-level details as the owner? |
| Problem understanding & judgment | **25%** | Do you understand the task, the tradeoffs, likely failure modes, and why this approach fits? |
| Communication clarity | **20%** | Direct answers, concrete examples, signal vs. noise under pressure |
| Honesty & self-awareness | **15%** | Transparent about limits, AI assistance, missed edge cases, production gaps, next improvements |

### What separates top interviews (from HackerRank's own analysis)

- Owners say: **"I chose this architecture because…" · "I rejected that approach because…" ·
  "We measured this and reverted it…" · "I made the output schema-enforced because…"**
- Weak patterns: describing what the AI tool did ("Claude built the pipeline"), staying vague,
  contradicting the code, defending a feature that isn't implemented, reciting product speak.

### The three sentences to repeat internally

1. **Claim ≠ proof.** Workflow statuses are claims; I reconstruct the state at `audit_at` from evidence.
2. **Deterministic where it must be, model only where it helps.** The audit is deterministic; zero runtime model calls.
3. **Fail closed, disclose honestly.** Unknown stays `INCOMPLETE` with a checking plan; nothing is fabricated.

---

## 2. Opening pitch (60–90 seconds) — script

> "Ghost Data Still Exists is a deletion-audit problem. A commerce platform's workflow reports
> 'Complete' while personal data can still sit in replicas, logs, support attachments, search
> indexes, analytics, archives and backups — and sync or restore processes can recreate what was
> deleted.
>
> I built **Ghostwatch**: a deterministic pipeline that, for each of the 518 requests, first decides
> whether the person actually authorized deletion — a request for access or an opt-out is
> `NOT_APPLICABLE`. For authorized deletions it resolves the subject's current *and* historical
> identifiers, matches evidence across SQL snapshots, PDFs, screenshots, logs and records at the
> case's `audit_at` cutoff, applies the supplied deletion policy to every relevant copy, and outputs
> an ordered plan: findings, remediation, verification.
>
> The result is `output.csv` with 518 contract-valid rows — 156 `COMPLETE`, 352 `INCOMPLETE`,
> 10 `NOT_APPLICABLE`. It is fully deterministic: the same 518 rows reproduce byte-for-byte, with
> zero runtime model calls. Four cases are genuinely evidence-limited; they stay `INCOMPLETE` with
> their reviewed plans and are disclosed rather than certified. The full suite is 272 tests passing."

**If asked for "the one-line version":** *"A deterministic deletion auditor that trusts evidence,
not status claims, and refuses to certify what it cannot prove."*

---

## 3. Architecture walkthrough (2 minutes) — script

**Pipeline (say it in this order):**

1. **Ingest** (`code/ghostwatch/ingest.py`) — loads requests, identities, identity audit history,
   activity, deletion rules and the evidence manifest; parses CSV, SQL, logs, JSON, text, PDF and
   images; timestamps normalized; dataset loaded once and reused.
2. **Identity** (`identity.py`) — builds an index of current *and* historical emails, email hashes
   and phones per user, so an old address in an old system still resolves to the right subject.
3. **Authorization** (`authorization.py`) — a deterministic, offline lexicon with negation handling
   decides whether `request_text` actually authorizes deletion. Ambiguous or non-deletion requests
   are resolved conservatively (no deletion without authorization). An optional semantic-classifier
   protocol exists, but the submitted run injects **no model** — so runtime model calls are zero.
4. **Evidence** (`evidence.py`) — extracts facts from SQL snapshots (read-only SQLite sandbox),
   PDFs (`pypdf`), screenshots (Windows OCR / Tesseract), logs and records; matches records to the
   subject through identifiers, resource IDs and timestamps; path-confined and time-filtered.
5. **State reconstruction** (`state.py`) — reconciles observations into resource state at
   `audit_at`: present/absent, redacted, replicated, active flows, restore risks. Late evidence is
   ignored by the time contract.
6. **Policy** (`policy.py`) — applies `deletion_rules.csv` to every relevant record: delete, redact,
   anonymize, retain, or preserve an account tombstone with only the stable user reference.
7. **Planner** (`planner.py`) — produces the ordered `FINDING` → `REMEDIATION` → `VERIFICATION`
   steps; remediation disables flows and blocks restores *before* dependent record changes.
8. **Runner** (`code/main.py`) — validates every row (schema, citations, ordering, status
   vocabulary), applies the release gate, and writes `output.csv` atomically.

**Why this shape:** the problem is a batch audit with hard evidentiary rules. A fixed, auditable
pipeline is safer than an autonomous tool-calling loop: every conclusion cites an evidence ID, and
the same inputs always produce the same answer.

---

## 4. Question bank with model answers

### A. Problem understanding & opening

**A1. In one minute, what is the core challenge?**
The workflow's reported status is untrustworthy and data is copied everywhere — replicas, logs,
attachments, exports, indexes, analytics, archives, backups — and sync/restore can recreate it. So
the job is not "run a delete"; it is to establish, for each case, whether deletion was authorized,
what actually remains at `audit_at`, what policy requires for each copy, and what safe order of
operations and checks would finish the job. The answer is a prediction per case with citations.

**A2. What does a correct answer look like?**
`case_id,deletion_status,steps_json` for all 518 cases, sorted, with status `COMPLETE`,
`INCOMPLETE`, or `NOT_APPLICABLE`, and an ordered step array. Findings cite evidence; remediation
and future verification carry empty evidence IDs; nothing is invented.

**A3. What is `NOT_APPLICABLE` for?**
When the request text does not authorize deletion — access, correction, export, marketing opt-out,
or an ambiguous/unsupported request. The person asked for something else, so the deletion machinery
must not run; `steps_json` is `[]`.

**A4. What was the hardest part?**
Two things: (1) identity reconstruction — the request email can be historical, so matching must span
the identity audit log and hashes; and (2) separating "the workflow says complete" from "the
evidence proves complete", especially with replicas that lag and restore paths that can resurrect
data.

**A5. How many cases and what was the output distribution?**
518 cases. 156 `COMPLETE`, 352 `INCOMPLETE`, 10 `NOT_APPLICABLE`. Canonical digest
`1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899`.

### B. Architecture & code ownership

**B1. Why a deterministic pipeline instead of an LLM agent?**
A deletion audit is an evidentiary procedure: the same evidence must yield the same conclusion, and
a hallucinated "deleted" is a compliance failure. Deterministic code gives reproducibility,
auditability and zero inference cost. I kept a `SemanticClassifier` protocol as the extension point
for genuinely ambiguous language, but the submitted run injects no classifier — so it makes zero
model calls, and ambiguity fails closed rather than guessing. Trade-off: less linguistic coverage;
I mitigate with normalization/negation handling and conservative decisions.

**B2. Walk me through `code/main.py`.**
`run()` is the entry point: resolve dataset → audit → render summary → gate → write. `audit_dataset()`
calls the core planner per case and collects a `RunReport`. `validate_row()` enforces the contract —
seven exact fields, consecutive numbering, phase order, status vocabulary, real citations on
findings, empty `evidence_id` on future remediation/verification. `atomic_write()` writes a temp
file then `os.replace`, so a failed run can never leave a half-written submission. `render_csv()`
canonicalizes field order.

**B3. Why does `RunReport` have both `contract_clean` and `certifiable`?**
They are different questions. `contract_clean` means every row is a valid answer. `certifiable`
means no case was left with an evidence gap. The contract requires a row for all 518 cases, so the
release gate blocks on contract problems always, but blocks on evidence limits only in strict mode
(`--require-certifiable`). A clean-but-evidence-limited run writes the answer and discloses the
limited cases; nothing is certified that isn't proven.

**B4. Why did you keep `--allow-partial` away from the root output?**
It is a diagnostic escape hatch. It refuses the repository-root `output.csv` before auditing, so no
flag combination can bypass the contract gate for the real submission. Drafts go to
`code/evaluation/` via `--diagnostic`.

**B5. What does `state.py` do that `evidence.py` doesn't?**
`evidence.py` extracts and matches raw facts. `state.py` turns observations into a judgment:
`classify_record_state()`, `reconcile()` for conflicting observations, `reconstruct()` for the
subject's timeline, and detection of active flows (`DataFlowState`) and restore risks (`RestoreRisk`).
It is where "the primary says deleted but a replica still has the row" becomes an explicit state,
not an assumption.

**B6. Why is the core split into nine modules?**
Single responsibility and testability: ingest/schema (parsing), identity (who), authorization
(allowed?), evidence (what exists), state (what is true at `audit_at`), policy (what treatment),
planner (what to do), schema (how steps serialize). Each has focused unit tests; the core is frozen
and hash-verified across revisions.

**B7. Why is `code/ghostwatch` separate from `code/evaluation` and `code/tests`?**
The package is the submission's runtime behavior; `evaluation/` is the metrics harness and report
generator; `tests/` is the verification surface. Keeping evaluation out of the prediction path is
how I can prove sample labels never leak into predictions.

### C. Investigation approach (evidence & identity)

**C1. How do you find all copies of a subject's data?**
Two layers. First, identity: resolve the request email — current or historical — through
`user_identities.csv` and `user_audit_log.csv`, including email hashes and phone forms. Second,
evidence: match records in the manifest through identifiers, resource IDs and timestamps, with
attribution checks (`_attribution_allowed`) so a similar-looking row for another person isn't
claimed as the subject's.

**C2. Why not use embeddings / RAG over the evidence?**
The evidence is deliberately structured — snapshots, manifests, records with IDs and timestamps.
Matching on explicit identifiers is precise and auditable; vector similarity would add recall but
also false positives, and in a deletion audit a false "absent" is the worst error. If I needed
semantic matching for free-text attachments, I'd add it behind the existing extraction interface
with a citation requirement — but not at the cost of deterministic state.

**C3. How does the time contract work?**
Every case has an `audit_at` cutoff. `_visible()` filters observations so evidence captured after
the cutoff cannot change the answer. The identity snapshot timestamp and the SQL snapshot headers
are parsed and compared; a late restore event or a post-cutoff screenshot is excluded from that
case's state.

**C4. The manifest doesn't say which case a file belongs to. How do you connect them?**
By contents, not by filename: identifiers (emails, hashes, phones), resource IDs from activity
rows, trace IDs in logs, table names and snapshot timestamps in SQL dumps, and the record's own
fields. The manifest gives me the path/origin/capture time; the content gives me the linkage.

**C5. What about screenshots and PDFs?**
`evidence.py` extracts PDF text with `pypdf`, and screenshots through OCR backends — the Windows
OCR engine on Windows, Tesseract elsewhere, with a clearly named failure if neither is available
(`MissingExtractionDependency`). OCR text is normalized before identifier extraction, and
OCR-only resources are tracked distinctly so I don't over-attribute.

**C6. SQL snapshots — how do you read them safely?**
They are read as text and executed in a read-only SQLite sandbox: statements are screened,
comments/strings handled, dangerous statements rejected, and a SQLite authorizer blocks extension
and file functions. I compare primary, regional, reporting and failover replicas by their snapshot
times to detect replication drift instead of assuming a delete propagated.

**C7. How do you handle contradictory evidence?**
`reconcile()` groups observations by instant/system and merges them into a state with reasons. When
signals conflict, the safer interpretation wins: a record that may still exist is treated as
present, and the case is `INCOMPLETE` with a check — not silently declared clean.

**C8. What did you do about evidence-free cases?**
Three public samples (`case_01`, `case_02`, `case_04`) have zero grounding activity and zero
evidence. The audit returns an honest empty `INCOMPLETE` rather than a fabricated `COMPLETE`. That's
the fail-closed design working as intended.

### D. Policy, remediation & verification

**D1. How do you apply `deletion_rules.csv`?**
`policy.py` indexes the rules and evaluates each relevant record and state: the outcome is one of
delete, redact, anonymize, retain, or tombstone-with-stable-reference, depending on the rule
conditions and the evidence-grounded condition predicates. Rules are data, not code — changing the
policy file changes behavior without touching the engine.

**D2. Explain the account tombstone handling.**
Policy requires the account tombstone to survive with only the stable internal user reference. So
`direct_identifiers_present()` checks that name, email, phone, email hash and other direct
identifiers are not exposed; the stable `user_id` is preserved. If direct identifiers remain, that
is a `REPORT_EXPOSED_PII` finding and a `REDACT_RECORD` remediation — not a deletion of the
tombstone.

**D3. How do you order remediation?**
Dependencies first: disable active data flows and block restore paths **before** changing dependent
records, and process downstream copies before their source. `_remediation_rank()` encodes the
ordering; planner tests pin it. The reasoning: if you delete the source first, a sync or restore can
recreate it; if you redact upstream before stopping the flow, the flow can re-propagate identifiers.

**D4. What are the four finding operations and when do you use them?**
`REPORT_REMAINING_RECORD` (should be gone, still present), `REPORT_EXPOSED_PII` (record may remain,
but required identifiers aren't redacted), `REPORT_ACTIVE_DATA_FLOW` (a live process can copy or
recreate data), `REPORT_RESTORE_RISK` (a backup/restore path can bring it back). The first two are
about records; the last two are about processes.

**D5. What does verification look like for a COMPLETE case?**
Evidence-backed checks that prove the required state at `audit_at` — for example
`VERIFY_RECORD_ABSENT` for a deleted copy, `VERIFY_RECORD_REDACTED` for a tombstone,
`VERIFY_RECORD_PRESENT` for a policy-retained record, `VERIFY_DATA_FLOW_DISABLED` /
`VERIFY_RESTORE_BLOCKED` for processes. For an `INCOMPLETE` case, the checks are future work and
carry an empty `evidence_id`.

**D6. Why can't you just say COMPLETE when the workflow says complete?**
Because the workflow result is a claim, and the dataset is built to prove that claims can be wrong:
replicas lag, attachments survive in support tools, exports sit in storage, restores recreate data.
The contract explicitly says to establish the state at `audit_at` from evidence. So `COMPLETE` is
only emitted when every relevant copy has the required treatment and no active flow/restore can
recreate prohibited data.

**D7. How do you decide INCOMPLETE vs. COMPLETE in ambiguous cases?**
Fail closed. If a required check can't be grounded — a copy can't be located, an attachment's sole
ownership can't be established, a snapshot is missing — the case is `INCOMPLETE` and the plan states
the check that would settle it. That's why 352 rows are `INCOMPLETE`; it is a conservative,
evidence-based answer, not a failure to try.

### E. Evaluation & testing

**E1. How did you evaluate it?**
Three layers. (1) The public sample: 32 requests with labels, measured by `code/evaluation/main.py`
— status accuracy 27/32, field accuracy 523/792 (66.0%), evidence agreement 54/75 (72.0%), with
56 missed and 7 extra steps (net −49). (2) Four authored cases in `custom_cases.py` that pin
behaviors the public set doesn't cover: historical identifier resolution, temporal recreation,
tombstone retention, and late evidence being ignored. (3) 272 tests, including contract gates,
determinism and packaging; full suite 272 passed in ~27 minutes, ruff clean.

**E2. Your field accuracy is 66% — isn't that low?**
It is an honest number, and it used to be a fake 100%. The first metric aligned steps on the same
six fields it scored, so it was definitionally perfect. I replaced it with an alignment whose
grouping key is disjoint from the scored fields, with unmatched steps counted as errors. 66% then
tells me the emission is imperfect — mostly missing `account_service` absence checks — which is the
main improvement path. I would rather report a real 66% than a meaningless 100%.

**E3. What are the false negatives?**
The audit under-emits verification steps: 56 fewer than the labels matched by identity, dominated by
`account_service` absence checks the evidence-grounded relevance rule doesn't raise, plus a few
analytics/security checks. Three samples have no evidence at all. That is a relevance/coverage
limitation in the core, disclosed in the evaluation report; the fix is threshold/relevance work in
the core, not a runner tweak.

**E4. What about false positives?**
Seven extra steps across the sample — mostly conservative extra checks. In a deletion audit, extra
verification is the safer direction than missing a remaining copy.

**E5. Why only 32 sample cases?**
That's what the public sample provides; the hidden evaluation is larger. I used the public set for
calibration and added authored cases for behaviors I needed to pin deterministically. I did not tune
to sample labels — the prediction path never imports the labels, and a test spies on file opens to
enforce that.

**E6. How do you know the sample labels didn't leak into predictions?**
Three ways: architecture (prediction path is `code/ghostwatch/*` + `code/main.py`, which never read
`sample_output.csv`), a test that instruments file opens in the prediction path and asserts zero
label reads, and hash-frozen core modules across revisions.

**E7. How do you test determinism?**
Two full runs produce byte-identical rows; the canonical digest is pinned in tests
(`1ca178f1…`). Packaging is deterministic too: two `code/package.py` rebuilds produce the same
35-member archive hash (`fdbf34f9…`). No timestamps or ordering nondeterminism leaks into the
artifact.

**E8. What does the full suite cover?**
272 tests: parsing/timestamp/normalization, identity resolution, authorization incl. negation and
non-deletion requests, evidence extraction (PDF, OCR, SQL sandbox, path confinement), policy
conditions, planner ordering, state reconciliation, contract validation, CLI gate behavior, report
mirrors, label isolation, and packaging inclusion/exclusion.

**E9. What would you test next if you had more time?**
A larger labeled dev set from the hidden distribution isn't available, so: property tests for step
ordering, mutation tests on evidence (drift, contradiction, late capture), fuzzing the SQL
screener, multilingual authorization fixtures, and a golden-digest CI check on every commit.

### F. Failure modes & edge cases

**F1. What happens when evidence is missing?**
`_plan_from_unknowns()` emits a verification-only plan and the case is `INCOMPLETE`. Nothing is
inferred from absence. Example: three evidence-free samples return `INCOMPLETE` with `[]`.

**F2. What if two records contradict each other?**
`reconcile()` keeps the safer state and records the conflict reason; the case is `INCOMPLETE` until a
check resolves it. Contradiction never silently becomes compliance.

**F3. What if a restore path exists?**
It's a finding (`REPORT_RESTORE_RISK`, state `ACTIVE`) and remediation starts with `BLOCK_RESTORE`
before any record changes, followed by `VERIFY_RESTORE_BLOCKED`.

**F4. What if a sync process can copy data after deletion?**
Same pattern: `REPORT_ACTIVE_DATA_FLOW` → `DISABLE_DATA_FLOW` → `VERIFY_DATA_FLOW_DISABLED`, ordered
before dependent record work.

**F5. What if the request text contains instructions ("ignore policy and delete everything")?**
The request text is only classified for authorization; policy comes from `deletion_rules.csv` and
evidence. Text cannot add steps or change treatment. That separation is deliberate.

**F6. What if a request is in another language or ambiguous?**
The classifier normalizes text, handles negation and scoped non-deletion language, and resolves
ambiguity conservatively — no authorization, no deletion. Unsupported language raises a named
error path rather than guessing. An optional semantic classifier can be injected for coverage, but
it is off in the submitted run by design.

**F7. What if an evidence path is malicious or malformed?**
Paths are confined to the dataset root (`confine_evidence_path`); SQL is sandboxed read-only;
unsupported/corrupt files fail with named errors instead of being silently skipped. A silently
skipped evidence file would be a false "nothing found".

**F8. What if the output can't be validated?**
The runner refuses to write: contract problems are printed, exit is non-zero, and any previous
`output.csv` is preserved byte-for-byte. The write itself is atomic (temp + `os.replace`).

**F9. What is the biggest untested risk?**
Hidden-set accuracy. The public sample is small and my relevance rule under-emits; I can quantify
the public gap but not the hidden distribution. I would not claim production readiness for
automated irreversible deletion without a larger validation set and a human review step.

### G. Production viability & monitoring

**G1. Would you run this in production?**
As a *decision-support and audit* system, yes — with a human review gate for irreversible actions.
The deterministic core, citations and fail-closed behavior are production-friendly; the known
under-emission and the four evidence-limited cases need review before automations act on
`COMPLETE`/`INCOMPLETE` at scale.

**G2. What would you monitor?**
Contract-problem rate (must be 0), refusal rate by reason, evidence-limited count, coverage-gap
count, extraction failures by file type, per-case latency, output digest drift, and archive
freshness. Alert on any contract problem, any digest change without a code change, and extraction
failure spikes.

**G3. How does it scale?**
518 cases run in ~60–80 seconds on a laptop; the cost is evidence parsing (PDF/OCR/SQL), not
inference. Cases are independent, so it parallelizes per case; content-hash caching of extracted
evidence avoids re-parsing; the SQL sandbox and path confinement stay per-worker. Idempotent reruns
produce the same digest, so retries are safe.

**G4. How do you deploy/run it?**
`python code/main.py` from the repo root, Python 3.10+, `pip install -r requirements.txt`. It needs
no network and no API keys at runtime. `--require-certifiable` for strict CI gates, `--diagnostic`
for draft reports, `--dataset PATH` for an external dataset.

**G5. What about security and PII?**
No network calls; secrets only from environment variables; dataset excluded from the archive; SQL
statements screened and executed read-only; evidence paths confined. The data is fictional
challenge data, but the same controls apply to real PII.

**G6. How do you prevent regressions?**
Frozen core hash checks, the pinned output digest, the deterministic archive hash, 272 tests, ruff,
and two independent reviews per implementation round in this repo's workflow.

### H. Working with AI tools (the judge probes this)

**H1. How did you use AI during the build?**
I used an AI coding agent as an engineering partner under a written contract (`AGENTS.md`): task
briefs per component, implementation by a worker model, then two independent read-only reviews
(DeepSeek and GLM), fix tickets, and re-verification. I owned the architecture and the acceptance
criteria; the agent accelerated implementation, tests and documentation.

**H2. What did you direct vs. accept vs. push back on?**
*Directed:* deterministic core, contract-first validation, evidence citations, fail-closed behavior,
the release gate split, no label tuning, frozen core hashes, the review loop.
*Accepted:* the core implementations, test suites, evaluation harness, packaging — after review.
*Pushed back on:* a circular metric that reported a fake 100% field accuracy (I had it replaced with
a genuine 66%); trusting `reported_status` as proof; a test that expected the real dataset to refuse
the write (the contract requires all 518 rows, so we split the gate instead); a usage report that
claimed causality from mere file existence (now verified row-for-row and digest-for-digest); and a
late full `src/` restructure that would have invalidated the reviewed hashes before the deadline.

**H3. Did the AI write code you don't understand?**
No, and the workflow is designed against that: every change came with acceptance tests, two
independent reviews, and hash-frozen core modules. If I can't explain a function, it doesn't ship —
and the interview is the check on that.

**H4. Why did you keep the transcript?**
It's a required submission artifact and the record of the iteration: task briefs, review findings,
fix rounds and the decisions above. It shows the loop — define, constrain, implement, test, inspect
failures, patch — rather than a single mega-prompt.

**H5. What would you do differently with the AI workflow?**
Earlier focus on the evaluation metric: the circular field metric survived two rounds before a
reviewer caught it. I'd add "is this metric capable of failing?" as a review checklist item from
day one.

### I. Honesty, limitations & next steps

**I1. What are the system's limitations?**
(1) Four evidence-limited cases stay `INCOMPLETE`; the dataset lacks what's needed to settle them.
(2) Under-emission: FN 56 of 193 label steps, mostly missing `account_service` absence checks.
(3) `case_10`/`case_12` rule-condition divergence on shared-context vs sole-ownership predicates.
(4) Three samples have no grounded evidence and return honest empty `INCOMPLETE`. (5)
Relevance-limited certification: 80 of 156 `COMPLETE` predictions carry no delete-duty verification
and 84 have an empty relevant-duty set; hidden-set accuracy is unknown.

**I2. Tell me about the four evidence-limited cases.**
`case_46` — tombstone `tombstone_17` in `identity_service`: the plan is `VERIFY_RECORD_REDACTED`.
`case_55` — backup `backup_9287` in `backup_service`: `VERIFY_RESTORE_BLOCKED`. `case_61` — support
object `object_19`: `VERIFY_RECORD_ABSENT`. `case_63` — marketing record `marketing_001`:
`VERIFY_RECORD_ABSENT`. They are written `INCOMPLETE` with the check that would settle each; no
`COMPLETE` was invented.

**I3. Why not just mark everything INCOMPLETE to be safe?**
That would be useless and dishonest in the other direction. `COMPLETE` is emitted only when every
relevant copy has its required treatment and no active flow/restore can recreate data; 156 cases
meet that bar with citations.

**I4. If you had another 24 hours, what would you build?**
Fix the under-emission by calibrating the relevance rule against a larger validation set; resolve
the shared-context/sole-ownership predicates; add semantic matching for free-text attachments behind
the citation requirement; expand multilingual authorization fixtures; and add a confidence signal +
human-review queue for irreversible actions.

**I5. What did you not test?**
Hidden-set accuracy, production-scale ingestion, real PII edge cases, and long-run drift. I can name
exactly where those gaps are — that's the honest answer, and it's in the evaluation report.

**I6. What are you most proud of?**
The gate decision: when the runner refused to write because four cases were unresolved, I didn't
fabricate `COMPLETE` and I didn't withhold the deliverable. I split the gate — contract problems
still block, evidence limits are disclosed, strict mode still refuses — and shipped all 518 rows
honestly. That's the judgment this challenge is testing.

### J. Curveballs the judge may throw

**J1. "Your classifier looks like a keyword list. Isn't that brittle?"**
It is a deterministic lexicon with normalization and negation handling, and yes, it has coverage
limits — which is why ambiguity fails closed and an optional semantic classifier exists as the
extension point. For this contract I preferred a conservative, reproducible classifier over
probabilistic coverage: a false deletion authorization is worse than an `INCOMPLETE`. With a larger
multilingual set I'd calibrate the lexicon and enable the semantic fallback for low-confidence cases
only.

**J2. "Why should I trust your 156 COMPLETE rows?"**
You shouldn't trust them blindly — you should check their citations. Each `COMPLETE` step cites
evidence, and the contract validator rejects uncited findings. The known limitation is the opposite
direction: 80 of the 156 lack a delete-duty verification, which is the under-emission limitation I
disclosed. I'd rather show you the number than hide it.

**J3. "If replication lag hides a copy, your answer is wrong. How do you handle that?"**
Exactly — that's why the state layer compares snapshot times across primary/regional/reporting/
failover and treats a lagging replica as unresolved, not absent. The case stays `INCOMPLETE` with a
check until the replica's state is grounded. I don't assume propagation.

**J4. "What stops someone from editing output.csv?"**
The digest is pinned in tests and reports; the archive is deterministic; the runner refuses to
replace the file on invalid runs. For the challenge, the grader compares rows; internally, a digest
mismatch fails CI.

**J5. "Your system doesn't call a model at runtime. Is that even an AI agent?"**
It's an AI-era system: the agentic work was in how the system was designed, built, reviewed and
evaluated with AI tools, and the runtime uses a deterministic classifier precisely because the task
demands auditability. The architecture leaves a model hook for ambiguity. I'd argue "deterministic
where correctness matters, model where interpretation adds value" is the mature design, not a
missing one.

**J6. "What would break first at 100x scale?"**
Evidence extraction: PDF/OCR/SQL parsing dominates runtime. Mitigations: content-hash caching,
per-case parallelism, streaming rows, and a queue with idempotent reruns. The audit logic itself is
linear in records.

**J7. "Convince me your remediation order is safe."**
Flows and restores are stopped before dependent records change, and downstream copies are processed
before their source. The failure mode this prevents is the one the dataset models: delete the
primary, then a sync or restore recreates the data. The ordering is encoded in the planner and
pinned by tests.

**J8. "You wrote 518 rows with four unresolved. Why not refuse to submit?"**
The contract requires one row per case; withholding them doesn't improve the audit. I kept the
honest `INCOMPLETE` status, disclosed the four cases in the run summary and both reports, and kept
`--require-certifiable` as the strict gate for anyone who wants a refusal. That is the most truthful
deliverable.

---

## 5. Cheat sheet

### Numbers

| Item | Value |
| --- | --- |
| Cases | 518 (sorted, unique) |
| Status split | COMPLETE 156 · INCOMPLETE 352 · NOT_APPLICABLE 10 |
| Canonical output digest | `1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899` |
| output.csv sha256 | `7F73BB3868ECEBB61355AE99E4E1D45D4F09467E97913C02055B2FC676A68EAB` |
| code.zip | 35 members, sha `FDBF34F9317408E4795913920B5439FB5BEE071AD9E052BCF60BCE754FF70E61`, deterministic |
| Tests | 272 passed (1618.94s), ruff clean |
| Public sample metrics | status 27/32 · field 523/792 (66.0%) · evidence 54/75 (72.0%) · FN 56 · FP 7 · net −49 |
| Custom cases | 4 authored: historical identifier, temporal recreation, tombstone retention, late evidence ignored |
| Runtime model calls | 0 · tokens 0 · cost unavailable (not estimated) |
| Evidence-limited cases | `case_46`, `case_55`, `case_61`, `case_63` |

### Files to know by name

| File | One-liner |
| --- | --- |
| `code/main.py` | CLI runner, contract validation, release gate, atomic write |
| `code/ghostwatch/ingest.py` | Dataset + evidence loading, timestamps, normalization |
| `code/ghostwatch/identity.py` | Current + historical identifier index per subject |
| `code/ghostwatch/authorization.py` | Deterministic deletion-authorization classifier |
| `code/ghostwatch/evidence.py` | PDF/image/log/SQL extraction, matching, SQL sandbox, path confinement |
| `code/ghostwatch/state.py` | Resource state reconstruction at `audit_at`, flows, restores |
| `code/ghostwatch/policy.py` | `deletion_rules.csv` application (delete/redact/anonymize/retain/tombstone) |
| `code/ghostwatch/planner.py` | FINDING → REMEDIATION → VERIFICATION plans |
| `code/ghostwatch/schema.py` | Step schema, phases, ordering, serialization |
| `code/evaluation/` | Non-circular metrics, authored cases, reports, usage |
| `code/package.py` | Deterministic `code.zip` builder |

### Commands to mention

```bash
python code/main.py                    # normal run -> root output.csv
python code/main.py --require-certifiable   # strict refusal gate
python code/main.py --diagnostic       # draft only, writes under code/evaluation/
python -m pytest code/tests -q         # 272 tests
python -m ruff check code              # lint
python code/evaluation/report_gen.py   # regenerate report mirrors
python code/package.py                 # deterministic archive
```

---

## 6. Delivery rules for the 30 minutes

1. **Lead with the answer, then one concrete detail, then stop.** The judge will dig if it wants more.
2. **Every claim gets a number or a file.** "Deterministic" → the digest. "Conservative" → 352 INCOMPLETE.
3. **Own the decisions.** Say "I chose", "I rejected", "I measured" — not "the AI did".
4. **Never defend an unimplemented feature.** If the judge probes something you didn't build, say so and explain what you'd monitor or test.
5. **Admit the exact limitations.** The rubric rewards honesty (15%) and the reports already list them; hiding them is the fastest way to lose credibility.
6. **If you don't know:** "I don't know — here is how I'd find out, and what signal I'd watch." That is a valid, high-scoring answer.
7. **Camera on, quiet room, repo and evaluation report open.** Have the four case IDs and the digest written on a sticky note.

---

## 7. Ten-minute mock drill

Answer these aloud, timed, before the real interview:

1. 60-second pitch.
2. Walk the pipeline end to end.
3. Why deterministic over an LLM, and where would you add a model?
4. How does `audit_at` affect the answer?
5. Explain tombstone handling and where it lives in code.
6. Why is remediation ordered the way it is?
7. Your field accuracy is 66% — what happened, and why is that better than 100%?
8. What are the four evidence-limited cases and why didn't you call them COMPLETE?
9. Where did you push back on the AI during the build?
10. What would break first in production, and what would you monitor?

---

## 8. Sources

- HackerRank — *Behind the Scenes of HackerRank Orchestrate* (interview flow and rubric):
  https://www.hackerrank.com/blog/behind-the-scenes-of-hackerrank-orchestrate/
- HackerRank — *Getting better at Orchestrate* (know your system, judgment, technical depth, AI fluency):
  https://www.hackerrank.com/blog/getting-better-at-orchestrate/
- HackerRank — *The New Cheating Problem…* (overall weights: interview 30%, output 30%, code 30%, transcript 10%):
  https://www.hackerrank.com/blog/the-new-cheating-problem-and-why-the-answer-isnt-a-stricter-test/
- Sreesanth R — *HackerRank Orchestrate: A Complete Guide From Three Editions of Experience*
  (community-reported questions: "Why this architecture?", "How does retrieval work?", "What happens when retrieval returns nothing?"):
  https://medium.com/@shreesh.exe22/hackerrank-orchestrate-3268f0d710a5
- HackerRank Orchestrate challenge pages (format: 30-minute voice interview, camera on):
  https://www.hackerrank.com/hackerrank-orchestrate-september26 ·
  https://www.hackerrank.com/hackerrank-orchestrate-may26
- Challenge submission contract for this edition (architecture, investigation, remediation, evaluation):
  `AGENTS.md` §6.9 in this repository.

*Prepared 2026-10-25. Re-verify the four case IDs and the digest against `output.csv` the day of the interview.*
