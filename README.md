# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Solution overview

The solution is a terminal-run deletion-audit agent. It reads the participant inputs from
`dataset/`, reconstructs the evidence-backed state of every relevant record at `audit_at`,
applies `deletion_rules.csv`, and serializes the contracted `steps_json`. The code is split
into reviewable layers:

| Module | Responsibility |
| --- | --- |
| `code/ghostwatch/ingest.py` | Load and validate the participant CSVs. |
| `code/ghostwatch/identity.py` | Resolve a request (current or historical email) to one subject and reconstruct the identifiers in force at an instant. |
| `code/ghostwatch/evidence.py` | Read the evidence files (SQL snapshots, JSON, logs, text, PDF, screenshots) with provenance; retrieve only the subject's grounded records. |
| `code/ghostwatch/state.py` | Reconstruct each resource state at `audit_at`, newest-wins, from grounded evidence. |
| `code/ghostwatch/policy.py` | Apply `deletion_rules.csv` to every record, flow and restore path. |
| `code/ghostwatch/planner.py` | Decide `COMPLETE`/`INCOMPLETE`/`NOT_APPLICABLE` and build the ordered plan. |
| `code/ghostwatch/schema.py` | The single source of the allowed phases, operations and states; validates and serializes a plan. |
| `code/main.py` | The terminal runner: audit all requests, validate the contract, write the output. |
| `code/evaluation/` | The metrics harness, authored cases, usage reporter and the two Markdown reports. |
| `code/package.py` | Build the deterministic `code.zip`. |

**Runtime is deterministic; AI assistance was development-time.** The delivered pipeline is a
rule-and-evidence engine: it makes **zero** model calls at runtime (measured, not assumed — see
`code/evaluation/usage_report.md`). An AI coding agent was used to *write* the code and is
reported separately from runtime inference; the "AI-powered agent" framing in the challenge
brief describes the intended capability, not a runtime model dependency of this implementation.

### Setup

```bash
python -m pip install -r requirements.txt
```

Requires Python 3.10+. `pypdf` and `Pillow` are needed to read the PDF and screenshot
evidence; screenshots use the built-in Windows OCR engine on Windows 10/11, or `pytesseract`
with a `tesseract` binary elsewhere (`TESSERACT_CMD` points at it). If a dependency is
missing, the evidence layer fails with a named install hint rather than silently skipping a
file.

### Run

```bash
python code/main.py                    # normal run -> repository-root output.csv
python code/main.py --require-certifiable  # strict: refuse while any evidence limit remains
python code/main.py --diagnostic       # draft predictions + gap report under code/evaluation/
python code/main.py --output PATH      # explicit output path (tests / dry runs)
python code/main.py --dataset PATH     # dataset supplied outside the repository
```

If `code.zip` is extracted somewhere on its own, place the supplied participant `dataset/`
directory **next to** `code/` (the archive deliberately does not include it), or point at it
explicitly with `--dataset PATH` (or the `GHOSTWATCH_DATASET` environment variable).

The normal run audits all 518 requests, validates the exact schema, citations and canonical
ordering, and writes `output.csv` **atomically**. The release gate is **split** (T04 parent
decision):

* a **contract** problem (bad status, malformed JSON, missing/illegal citation, wrong order,
  empty plan) always refuses the write — the problems are printed, the run exits non-zero, and
  any previous `output.csv` is left byte-for-byte intact;
* a contract-clean run whose only remaining limitation is a genuine **evidence** gap writes the
  answer, names the affected cases, and keeps them honestly `INCOMPLETE`.

`--require-certifiable` restores the strict fail-closed gate: the write is refused while any
evidence-limited case remains. `--allow-partial` refuses the root `output.csv` location, and
`--diagnostic` writes only to `code/evaluation/`, so no flag can silently turn an unresolved run
into a final one.

> **Current readiness — disclosed evidence limits.** The normal run is contract-clean and writes
> the submitted root `output.csv` (518 rows). Four cases (`case_46`, `case_55`, `case_61`,
> `case_63`) are **evidence-limited**: the supplied dataset does not contain the evidence needed
> to settle every copy/retention duty, so those rows stay honestly `INCOMPLETE` with their
> reviewed remediation and verification plans. They are **not** certified complete deletion and
> are disclosed in the run summary, `code/evaluation/evaluation_report.md` §7 and
> `code/evaluation/usage_report.md` §5. Closing them needs evidence the dataset does not contain,
> not code. The strict gate still refuses the release while they stand:
>
> ```bash
> python code/main.py --require-certifiable   # exit 1, names the four cases, writes nothing
> ```

### Tests and lint

```bash
python -m pytest code/tests -q          # unit + acceptance + smoke + T03 tests
python -m ruff check code               # lint
```

(or `cd code && python -m pytest tests -q` and, from `code/`, `python -m ruff check .`)

### Evaluation

```bash
python code/evaluation/main.py                     # public-sample + authored-case metrics
python code/evaluation/main.py --json              # machine-readable metrics
python code/evaluation/custom_cases.py             # the four authored cases (self-contained)
python code/evaluation/usage.py --dataset dataset  # measured runtime usage
```

Run from `code/` instead with `python -m evaluation.main --dataset ../dataset`,
`python -m evaluation.custom_cases` and `python -m evaluation.usage --dataset ../dataset`.
The metrics harness and the usage reporter accept `--dataset PATH` and also honour
`GHOSTWATCH_DATASET`, so a dataset supplied outside the repository is fully supported (the
evaluator reads the supplied dataset and uses `sample_output.csv` from it **only** as
reference labels, after predictions exist). The authored-case runner is deliberately
**self-contained** — it builds its own fixtures and takes no dataset argument, so passing one
is rejected rather than silently ignored.

Reports are regenerated from live metrics with `cd code && python -m evaluation.report_gen`
(equivalently `python code/evaluation/report_gen.py`); it takes no `--dataset` flag and
resolves the dataset from `GHOSTWATCH_DATASET` or the sibling `dataset/`.

The evaluation harness reads `dataset/sample_output.csv` **only** as reference labels, after
predictions are produced; the prediction path never imports a label. Metrics cover case-status,
step precision/recall/F1, field accuracy, evidence agreement and sequence accuracy, with
explicit denominators. Two metric families are kept strictly separate: *exact-step*
precision/recall/F1 and whole-array exact-sequence match use the six-field step identity, while
*field* accuracy and evidence agreement use an independent positional one-to-one alignment
keyed on `(phase, operation)` — a key disjoint from the fields it scores, so the field metric
cannot be circular. The per-operation / per-system / per-case difference census, the
false-negative vs net-difference distinction, and the measured failures are generated by the
harness into `evaluation_report.md`.

### Packaging

```bash
python code/package.py          # writes repository-root code.zip
python code/package.py --list   # print the included files
```

The builder is deterministic (fixed metadata and ordering) and excludes the dataset, the
git-ignored orchestration tree, the transcript, caches, virtual environments, secrets, raw
data and nested archives. A denied path aborts the build rather than being dropped silently.

The archive carries the two Markdown reports at **both** contract locations — the
`code/evaluation/` primary and the archive-root `evaluation/` mirror (`AGENTS.md` §6.8). The
root mirrors are declared individually in the allowlist (`TREE_SPEC`), and the build asserts
all four report members are present, so a missing report aborts the build with a named error
instead of producing an incomplete archive.

### Reports and dataset resolution

The two report files are generated from live metrics; regenerate them after any source change
so the archive ships current bytes:

```bash
cd code && python -m evaluation.report_gen     # or: python code/evaluation/report_gen.py
```

`report_gen` takes no `--dataset` flag: it resolves the dataset through the same resolver as
the runner and the metrics harness — `GHOSTWATCH_DATASET` when set, otherwise the sibling
`<repo>/dataset` — and exits 2 with a clear diagnostic if neither exists. The usage reporter
(`python code/evaluation/usage.py`) uses the same precedence and the same exit-2 failure mode.
Rebuild `code.zip` **after** the reports settle so the archived bytes match the live files.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
