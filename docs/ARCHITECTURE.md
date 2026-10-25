# Architecture

`ghostwatch` audits whether a deletion request's data is actually gone. For every case it
determines whether deletion was authorized, reconstructs the subject's current and historical
identifiers, searches activity and evidence, applies the deletion policy, and answers with a
contract-valid status plus an ordered plan.

## Pipeline

```text
dataset/ ──► ingest ──► identity ──► authorization ──► evidence ──► policy ──► planner ──► runner
             (CSV,        (current +      (request_text       (PDF,        (deletion   (findings,     (validate,
              SQL,        historical       authorizes          images,      rules →     remediation,   write
              logs)       emails/ids)      deletion?)          logs, SQL)   treatment)  verification)  output.csv)
```

| Stage | Module | Responsibility |
| --- | --- | --- |
| Ingest | `code/ghostwatch/ingest.py` | Parse requests, identities, activity, rules and the evidence manifest; extract PDF/image/log/SQL evidence. |
| Identity | `code/ghostwatch/identity.py` | Recover current and historical identifiers (email, hash, phone) for the subject. |
| Authorization | `code/ghostwatch/authorization.py` | Deterministic, offline request classifier with a negation scan; non-deletion requests become `NOT_APPLICABLE`. |
| Evidence | `code/ghostwatch/evidence.py` | Match evidence to a case through grounded identifiers, resources and timestamps. |
| Policy | `code/ghostwatch/policy.py` | Apply `deletion_rules.csv` to each relevant record (delete / redact / anonymize / retain / tombstone). |
| Planner | `code/ghostwatch/planner.py` | Emit ordered `FINDING` → `REMEDIATION` → `VERIFICATION` steps. |
| Runner | `code/main.py` | Validate the contract, enforce the release gate, write `output.csv` atomically. |
| Evaluation | `code/evaluation/` | Public-sample metrics, authored cases, report generation and token/cost accounting. |
| Packaging | `code/package.py` | Build the deterministic `code.zip` submission archive. |

## Repository layout

```text
code/
  main.py                 terminal entry point
  package.py              deterministic archive builder
  ghostwatch/             audit core package
  evaluation/             metrics harness and generated reports
  tests/                  unit, acceptance and packaging tests
evaluation/               report mirrors required by the submission contract
dataset/                  participant-facing inputs and evidence
output.csv                final 518-row answer (repository root, per the contract)
code.zip                  deterministic submission archive (kept out of git)
docs/                     architecture notes
```

## Running

```bash
python code/main.py                    # normal run -> root output.csv
python code/main.py --require-certifiable   # strict: refuse while any evidence limit remains
python code/main.py --diagnostic       # draft predictions + gap report under code/evaluation/
python -m pytest code/tests -q         # full test suite
python -m ruff check code              # lint
python code/package.py                 # rebuild code.zip
```

## Release gate

The write is **split**: a contract problem (schema, citations, ordering, status vocabulary)
always refuses and preserves any previous `output.csv`; a contract-clean run whose only
remaining limitation is a genuine evidence gap writes the answer and discloses the affected
cases. Evidence-limited cases stay `INCOMPLETE` with their reviewed plans and are never
certified as complete deletion. `--require-certifiable` restores the strict refusal, and
`--allow-partial` can never touch the repository-root output.

## Determinism and limits

The audit is deterministic and makes zero model calls at runtime: the classifier is an offline
lexicon, so the usage report measures 0 calls and 0 tokens with cost reported as unavailable
rather than estimated. Known limits (under-emission, rule-condition divergence, evidence-free
samples and relevance-limited certification) are disclosed in `code/evaluation/evaluation_report.md`.
