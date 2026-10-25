# Token usage and cost analysis

Reproduce this report with:

```bash
python code/evaluation/usage.py --dataset dataset
# from code/ :  python -m evaluation.usage --dataset ../dataset
```

## 1. The measured run

- Run: deterministic audit of all 518 requests (reproduces the submitted output.csv)
- Dataset: `C:\Users\vedan\Documents\Resources\Code\hackerrank-orchestrate-october26\dataset`
- Requests audited: 518
- Run digest (sha256 over `case_id\tdeletion_status\tsteps_json\n`, rows sorted by
  `case_id`, UTF-8): `1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899`
- Status split: COMPLETE 156, INCOMPLETE 352, NOT_APPLICABLE 10
- Cases with an unresolved gap: 4 (case_46, case_55, case_61, case_63) — these are evidence-limited
  and are written `INCOMPLETE` in the submitted `output.csv`, never as certified complete
  deletion (see §5)
- Contract problems: 0
- Submitted `output.csv`: `C:\Users\vedan\Documents\Resources\Code\hackerrank-orchestrate-october26\output.csv` **matches this run exactly** — 518 rows and digest `1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899` are identical
- Release command: `python code/main.py` — this measured audit reproduces the submitted `output.csv` exactly (see the `Submitted output.csv` line above)
- Elapsed: 78.1s (run-specific wall-clock; excluded from the byte-reproducibility claim — see the note below)

Every value above is measured for this captured run; the `Elapsed:` line is the
run wall-clock and the `Dataset:` line records the resolved path, so both vary
between runs/layouts. They are carried as run evidence and are **excluded** from
the byte-reproducibility claim for this report, so archive freshness checks
compare the deterministic content (counts, digest, status split).

## 2. Model calls and tokens

| Metric | Value |
| --- | --- |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0.0000 |

### Per-model totals

There is exactly one writer in this run — the deterministic classifier — and it is not a
model, so the per-model table has no model rows. The overall totals are therefore the
complete accounting of the run:

| Model provider | Model name | Calls | Input tokens | Output tokens | Total tokens |
| --- | --- | --- | --- | --- | --- |
| _(none — deterministic lexicon)_ | _(none)_ | 0 | 0 | 0 | 0 |
| **Overall** | — | **0** | **0** | **0** | **0** |

**Providers and model names:** none at runtime. The shipped authorization classifier is a
deterministic, offline lexicon with a negation scan (`ghostwatch.authorization`). It
never contacts a network service, so the measured run makes **zero** model calls and
consumes **zero** runtime tokens.

**Diagnostic semantics of the zero.** A zero here means *no calls were made*, not *calls
went unrecorded*:

- `ModelUsage` objects are produced only by a classifier that is explicitly handed to
  `audit()`; with no classifier configured, `AuditResult.model_usage` is `None` for every
  case, and the runner's counters (which sum `model_usage.calls`, `.input_tokens`,
  `.output_tokens`) remain at zero.
- The authorization layer runs the deterministic classifier first and only consults an
  injected semantic classifier when the deterministic result is ambiguous — and no
  classifier is injected by `code/main.py`.
- `test_usage_is_actual_not_estimated_tokens` pins the zero counts and the
  "unavailable cost" behaviour.

This report is explicitly **not** claiming "no inference usage because calls were
unrecorded"; it is claiming a measured zero through a code path that would have counted
the calls had any occurred.

## 3. Estimated cost

**Unavailable.** No model is invoked by the shipped deterministic pipeline, and no
per-token price is configured for this run, so a cost is **not** estimated. The report
states *unavailable* rather than inventing a rate. (A rate can be supplied via the
optional environment variables `GHOSTWATCH_MODEL_INPUT_USD_PER_MTOK` /
`GHOSTWATCH_MODEL_OUTPUT_USD_PER_MTOK`; when both are set the report computes a figure
from them, and when they are absent it says unavailable.)

## 4. Development-agent usage (separate from runtime inference)

The code in this repository was written with AI assistance: an AI coding agent (OpenCode
running a DeepSeek-hosted coding model) under the repository's `AGENTS.md`, orchestrated
through the repository's task/review workflow. That development usage is **not** part of
the submission's runtime cost and is reported separately:

- the runtime pipeline (the artifact being scored) is **deterministic** and makes **0**
  model calls;
- the development agent's own token usage is bounded by the chat transcript (`log.txt`),
  which is uploaded as the `chat_transcript` artifact and is deliberately **not** counted
  as runtime inference for the run that produces `output.csv`.

Conflating the two would overstate the submission's runtime cost; keeping them separate is
the honest presentation. No API key, credential or provider token is recorded in this
report.

## 5. The run behind the submitted `output.csv`

The release command (`python code/main.py`, contract-clean under the split T04 gate)
wrote the repository-root `output.csv` **atomically**. This usage report is measured by
`measure_deterministic_run`, which re-runs the same deterministic audit over all 518
requests and then **verifies the shipped file against it**: the submitted `output.csv`
matches this run row-for-row and digest-for-digest (see the `Submitted output.csv` line
in §1). The claim is the equality, not merely that a file exists — a differing or absent
file is reported as a mismatch instead.

The release gate is **split** (T04 parent decision): the write is refused whenever a
**contract** problem exists (schema, citations, ordering, status vocabulary), while a
contract-clean run whose only remaining limitation is a genuine **evidence** gap writes
the answer and discloses the affected cases. Four cases (`case_46`, `case_55`,
`case_61`, `case_63`) are evidence-limited: they are written honestly as `INCOMPLETE`
with their reviewed plans and are **not** certified as complete deletion. Their
limitation is disclosed in the run summary and in `evaluation_report.md` §7. The strict
gate (`python code/main.py --require-certifiable`) still refuses to release while any
such case stands; `python code/main.py --diagnostic` produces a draft-only gap report
under `code/evaluation/`.

The measured runtime totals are unaffected by the release decision: the shipped pipeline
is deterministic and makes zero model calls either way.

## 6. Environment and orchestration (for reproducibility)

- Python 3.10+ (validated on 3.14.0); dependencies in `requirements.txt` (`pypdf`, `Pillow`,
  `pytest`, `ruff`); screenshots use the built-in Windows OCR engine, or `pytesseract` +
  `TESSERACT_CMD` elsewhere.
- The deterministic run needs no network access, no API keys, and no credentials.
- The development workflow (task dispatch, model routing, review rounds) is the
  repository's orchestration layer and is **git-ignored**; it is not part of `code.zip`
  and not required to run the solution. The submitted runner imports nothing from it.
