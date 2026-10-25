"""Ghost Data Still Exists - terminal runner.

Reads the participant dataset from ``dataset/``, audits every request in
``dataset/deletion_requests.csv`` with the accepted audit core, validates the result
against the submission contract, and writes the completed ``output.csv`` at the
repository root.

Two modes:

``normal`` (default)
    Audit all requests, validate the exact schema, citations and canonical ordering, and
    write the root ``output.csv`` **atomically**. The release gate is split into two
    independent conditions (T04 parent decision):

    * **contract-clean** — schema, citations, canonical ordering, status vocabulary, empty
      future ``evidence_id``, and the row set itself. A run that violates the contract
      never writes a final file: the problems are printed and any previous ``output.csv``
      is left byte-for-byte intact (exit 1).
    * **certifiable** — no case is left with an evidence/coverage/contradiction limit. This
      is no longer the default release gate: a contract-clean run whose only remaining
      limitation is a genuine evidence gap writes the root ``output.csv`` and **names the
      affected cases** in the run output and in both reports, keeping them honestly
      ``INCOMPLETE``. Pass ``--require-certifiable`` to restore the strict fail-closed
      behaviour, which refuses the write whenever any such limit remains.

``--diagnostic``
    Audit all requests and write clearly named *draft* predictions plus a Markdown gap
    report under ``code/evaluation/`` (never the root ``output.csv``). This exists so the
    remaining evidence limits stay measurable without ever masquerading as a final answer.

Usage::

    python code/main.py                     # normal run -> root output.csv (contract-gated)
    python code/main.py --require-certifiable  # strict: refuse while any evidence limit remains
    python code/main.py --diagnostic        # draft predictions + gap report under code/evaluation/
    python code/main.py --output PATH       # normal run to an explicit path (tests / dry runs)

The dataset directory is resolved with the documented precedence ``--dataset`` (explicit)
> ``GHOSTWATCH_DATASET`` (environment) > ``<repo>/dataset`` (default). An invalid supplied
path fails with a clear message and exit code 2 rather than silently falling back to the
repository dataset.

The runner never reads ``dataset/sample_output.csv``; the sample labels are evaluation
data (see ``code/evaluation``), not prediction input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

# The package lives next to this file; make the import work whether the runner is invoked
# as `python code/main.py` from the repo root or as a module.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ghostwatch.ingest import (  # noqa: E402  (import after sys.path fix)
    Dataset,
    DatasetNotFoundError,
    load_dataset,
    parse_timestamp,
)
from ghostwatch.planner import (  # noqa: E402
    AuditError,
    AuditResult,
    ParticipantContext,
    audit,
    build_context,
)
from ghostwatch.schema import (  # noqa: E402
    OPERATIONS,
    PHASE_RANK,
    validate_steps_payload,
)

REPO_ROOT = _HERE.parent
DEFAULT_DATASET = REPO_ROOT / "dataset"
#: Documented environment fallback for the runner. Used only when ``--dataset`` is omitted,
#: so the explicit CLI argument always wins. An invalid value fails loudly (see
#: :func:`resolve_dataset_dir`) instead of silently reverting to the repository dataset.
DATASET_ENV_VAR = "GHOSTWATCH_DATASET"
DEFAULT_OUTPUT = REPO_ROOT / "output.csv"
DIAGNOSTIC_DIR = _HERE / "evaluation"
DIAGNOSTIC_PREDICTIONS = DIAGNOSTIC_DIR / "diagnostic_predictions.csv"
DIAGNOSTIC_GAPS = DIAGNOSTIC_DIR / "diagnostic_gaps.md"

OUTPUT_HEADER = ("case_id", "deletion_status", "steps_json")
ALLOWED_STATUSES = frozenset({"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})


# --------------------------------------------------------------------------------------
# Contract validation
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Problem:
    """One contract violation found while validating a run."""

    case_id: str
    kind: str
    detail: str

    def as_line(self) -> str:
        return f"{self.case_id}\t{self.kind}\t{self.detail}"


@dataclass(slots=True)
class RunReport:
    """The measured result of auditing a whole dataset."""

    mode: str
    rows: list[tuple[str, str, str]]
    status_counts: Counter
    step_counts: Counter
    gaps: list[tuple[str, str, str, bool]]  # case_id, kind, detail, blocking
    diagnostics: int
    problems: list[Problem] = field(default_factory=list)
    unresolved_cases: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    case_digest: str = ""
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def blocking_gaps(self) -> list[tuple[str, str, str, bool]]:
        return [gap for gap in self.gaps if gap[3]]

    @property
    def contract_clean(self) -> bool:
        """True when every row satisfies the §6.3/§6.4 contract.

        This is the *release* condition: only a contract-valid run may ever replace the
        final ``output.csv``. It is deliberately independent of whether the supplied
        evidence was sufficient to decide every case (see :attr:`certifiable`).
        """

        return not self.problems

    @property
    def certifiable(self) -> bool:
        """True when no case is left with an unresolved evidence/coverage/contradiction limit.

        ``False`` means at least one case is honestly ``INCOMPLETE`` because the dataset does
        not contain the evidence needed to prove the required state. Those cases are named in
        :attr:`evidence_limited_cases` and disclosed in the reports; they are not defects and
        no ``COMPLETE`` is invented for them.
        """

        return not self.evidence_limited_cases

    @property
    def evidence_limited_cases(self) -> list[str]:
        """Case ids whose answer is limited by the available evidence, not by the contract."""

        return list(self.unresolved_cases)

    @property
    def ok(self) -> bool:
        """True only for a clean, fully certifiable, contract-valid answer (strict mode)."""

        return self.contract_clean and self.certifiable

    def digest(self) -> str:
        """SHA-256 over the canonical row serialization (documented in the reports)."""

        body = "".join(
            f"{case_id}\t{status}\t{steps}\n" for case_id, status, steps in self.rows
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _canonical_order_ok(payload: Sequence[dict]) -> bool:
    keys = [
        (PHASE_RANK[step["phase"]], OPERATIONS[step["operation"]][2], step["system_id"], step["resource_id"])
        for step in payload
    ]
    return keys == sorted(keys)


def validate_row(
    case_id: str,
    status: str,
    steps_json: str,
    *,
    manifest_ids: frozenset[str],
    activity_ids: frozenset[str],
    audit_ids: frozenset[str],
) -> list[Problem]:
    """Validate one output row against the §6.3/§6.4 contract.

    Checks the status vocabulary, JSON array shape, the exact seven step fields,
    consecutive ``step_no`` from ``1``, legal phase/operation/state triples, phase
    grouping, canonical order, empty ``evidence_id`` for proposed future work, non-empty
    citations on findings and COMPLETE verification, and that every cited id exists in
    the participant data. It never mutates the row.
    """

    problems: list[Problem] = []
    if status not in ALLOWED_STATUSES:
        problems.append(Problem(case_id, "status", f"unknown deletion_status {status!r}"))
        return problems
    try:
        payload = json.loads(steps_json)
    except json.JSONDecodeError as exc:
        problems.append(Problem(case_id, "json", f"steps_json is not valid JSON: {exc}"))
        return problems

    for violation in validate_steps_payload(payload):
        problems.append(Problem(case_id, "schema", violation))
    if problems:
        return problems

    if status == "NOT_APPLICABLE" and payload:
        problems.append(Problem(case_id, "na_not_empty", "NOT_APPLICABLE must serialize []"))
    if status in {"COMPLETE", "INCOMPLETE"} and not payload:
        problems.append(Problem(case_id, "empty_plan", f"{status} must carry at least one step"))

    known = manifest_ids | activity_ids | audit_ids
    for offset, step in enumerate(payload, start=1):
        evidence_id = step["evidence_id"]
        phase = step["phase"]
        if phase == "FINDING" and status == "INCOMPLETE" and not evidence_id:
            problems.append(Problem(case_id, "uncited_finding", f"step {offset} cites no evidence"))
        if phase == "REMEDIATION" and evidence_id:
            problems.append(
                Problem(case_id, "remediation_cited", f"step {offset} must use an empty evidence_id")
            )
        if status == "INCOMPLETE" and phase == "VERIFICATION" and evidence_id:
            problems.append(
                Problem(case_id, "future_verification_cited", f"step {offset} must use an empty evidence_id")
            )
        if status == "COMPLETE" and phase == "VERIFICATION" and not evidence_id:
            problems.append(
                Problem(case_id, "uncited_verification", f"step {offset} cites no evidence")
            )
        if evidence_id and evidence_id not in known:
            problems.append(
                Problem(case_id, "unknown_citation", f"step {offset} cites unknown id {evidence_id!r}")
            )
    if payload and not _canonical_order_ok(payload):
        problems.append(Problem(case_id, "order", "steps are not in canonical order"))
    return problems


# --------------------------------------------------------------------------------------
# Whole-dataset audit
# --------------------------------------------------------------------------------------


def _timestamp_or_none(value: str):
    try:
        return parse_timestamp(value)
    except Exception:  # pragma: no cover - defensive; ingest already validated
        return None


def audit_dataset(
    dataset: Dataset,
    *,
    context: ParticipantContext | None = None,
    mode: str = "normal",
    progress: bool = False,
) -> RunReport:
    """Audit every request and validate the contract for the whole run.

    The function is deterministic and side-effect free: it never writes a file. Callers
    decide whether the report is a final answer (normal) or a diagnostic draft.
    """

    started = time.perf_counter()
    context = context or build_context(dataset)

    manifest_ids = frozenset(entry.file_id for entry in dataset.evidence_manifest)
    activity_ids = frozenset(event.activity_id for event in dataset.activity)
    audit_ids = frozenset(entry.audit_id for entry in dataset.audit_log)

    rows: list[tuple[str, str, str]] = []
    status_counts: Counter = Counter()
    step_counts: Counter = Counter()
    gaps: list[tuple[str, str, str, bool]] = []
    problems: list[Problem] = []
    unresolved: list[str] = []
    diagnostics = 0
    model_calls = 0
    input_tokens = 0
    output_tokens = 0

    requests = sorted(dataset.requests, key=lambda item: item.case_id)
    for index, request in enumerate(requests, start=1):
        if progress and index % 50 == 0:
            print(f"  audited {index}/{len(requests)} cases", file=sys.stderr)
        try:
            result: AuditResult = audit(request, context)
        except AuditError as exc:
            # The core refuses to fabricate a plan. Record it as a blocking problem; the
            # case still gets exactly one row so the run stays well-formed, but the run
            # cannot be written as final.
            problems.append(Problem(request.case_id, "audit_error", str(exc)))
            unresolved.append(request.case_id)
            rows.append((request.case_id, "INCOMPLETE", "[]"))
            status_counts["INCOMPLETE"] += 1
            continue

        status_counts[result.deletion_status] += 1
        for gap in result.gaps:
            gaps.append((request.case_id, gap.kind, gap.detail, gap.blocking))
            if gap.blocking:
                unresolved.append(request.case_id)
            if gap.kind == "contradiction" and not gap.blocking:
                # The runner must not silently trust the blocking flag alone: an
                # unresolved contradiction also refuses the final write (build-notes).
                unresolved.append(request.case_id)
        diagnostics += len(result.diagnostics)
        if result.model_usage is not None:
            model_calls += result.model_usage.calls
            input_tokens += result.model_usage.input_tokens
            output_tokens += result.model_usage.output_tokens

        payload = json.loads(result.steps_json)
        for step in payload:
            step_counts[step["operation"]] += 1

        problems.extend(
            validate_row(
                request.case_id,
                result.deletion_status,
                result.steps_json,
                manifest_ids=manifest_ids,
                activity_ids=activity_ids,
                audit_ids=audit_ids,
            )
        )
        rows.append((request.case_id, result.deletion_status, result.steps_json))

    rows.sort(key=lambda item: item[0])
    report = RunReport(
        mode=mode,
        rows=rows,
        status_counts=status_counts,
        step_counts=step_counts,
        gaps=gaps,
        diagnostics=diagnostics,
        problems=problems,
        unresolved_cases=sorted(set(unresolved)),
        elapsed_seconds=time.perf_counter() - started,
        model_calls=model_calls,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    report.case_digest = report.digest()
    return report


# --------------------------------------------------------------------------------------
# Output writing
# --------------------------------------------------------------------------------------


def render_csv(rows: Iterable[tuple[str, str, str]]) -> str:
    """Render rows as the submission CSV body (header + one line per case).

    Field quoting follows ``csv`` semantics: a value containing a comma or quote is
    wrapped in double quotes with internal quotes doubled. ``steps_json`` uses ``:``/``,``
    separators and sorted keys, so it never contains a bare newline.
    """

    lines = [",".join(OUTPUT_HEADER)]
    for case_id, status, steps in rows:
        lines.append(",".join(_csv_field(value) for value in (case_id, status, steps)))
    return "\n".join(lines) + "\n"


def _csv_field(value: str) -> str:
    if any(ch in value for ch in (",", '"', "\n", "\r")):
        return '"' + value.replace('"', '""') + '"'
    return value


def atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (temp file + ``os.replace``).

    A crash mid-write can never leave a half-written answer in place; the destination is
    either the old bytes or the complete new bytes.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".csv")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():  # pragma: no cover - only on failure
            tmp_path.unlink(missing_ok=True)


# --------------------------------------------------------------------------------------
# Diagnostic mode
# --------------------------------------------------------------------------------------


def render_gap_report(report: RunReport, dataset: Dataset) -> str:
    """Render the Markdown gap summary for a diagnostic run."""

    blocker_lines = []
    seen: set[str] = set()
    for case_id, kind, detail, blocking in report.gaps:
        if case_id in seen:
            continue
        seen.add(case_id)
    for case_id in report.unresolved_cases:
        reasons = sorted({f"{kind}: {detail}" for cid, kind, detail, _ in report.gaps if cid == case_id})
        if not reasons:
            reasons = ["audit error (see run output)"]
        for reason in reasons:
            blocker_lines.append(f"- `{case_id}` - {reason}")
    if not blocker_lines:
        blocker_lines.append("- none: the run is contract-clean and would be written as final")

    status_line = ", ".join(f"{name} {count}" for name, count in sorted(report.status_counts.items()))
    problem_lines = [f"- `{p.as_line()}`" for p in report.problems[:40]]
    if len(report.problems) > 40:
        problem_lines.append(f"- ... {len(report.problems) - 40} more")

    return "\n".join(
        [
            "# Diagnostic run gap report (NOT a submission answer)",
            "",
            "This file is produced by `python code/main.py --diagnostic`. It describes a",
            "**draft** run: the draft predictions live in `diagnostic_predictions.csv` and",
            "the root `output.csv` is deliberately left untouched because the run is not",
            "contract-clean. It must never be presented as the final submission.",
            "",
            f"- Requests audited: {len(report.rows)}",
            f"- Status split: {status_line or 'n/a'}",
            f"- Cases with an unresolved (blocking or contradiction) gap: {len(report.unresolved_cases)}",
            f"- Recorded diagnostics: {report.diagnostics}",
            f"- Elapsed: {report.elapsed_seconds:.1f}s",
            f"- Run digest (sha256 over `case_id\\tdeletion_status\\tsteps_json\\n`): `{report.case_digest}`",
            "",
            "## Unresolved cases (block the final write)",
            "",
            *(blocker_lines if blocker_lines else ["- none"]),
            "",
            "## Contract problems",
            "",
            *(problem_lines if problem_lines else ["- none"]),
            "",
            "## Interpretation",
            "",
            "The audit core fails closed by design: when the supplied evidence cannot decide",
            "every copy duty, it names a real grounded verification check and leaves the case",
            "`INCOMPLETE` rather than inventing a `COMPLETE`. Those cases are genuine evidence",
            "limits, so this diagnostic draft is useful for measuring the pipeline but is not",
            "a certifiable final answer.",
            "",
        ]
    )


def write_diagnostic(report: RunReport, dataset: Dataset) -> tuple[Path, Path]:
    DIAGNOSTIC_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(DIAGNOSTIC_PREDICTIONS, render_csv(report.rows))
    atomic_write(DIAGNOSTIC_GAPS, render_gap_report(report, dataset))
    return DIAGNOSTIC_PREDICTIONS, DIAGNOSTIC_GAPS


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def resolve_dataset_dir(dataset: str | Path | None = None) -> Path:
    """Resolve the runner's dataset directory with documented precedence.

    Precedence: an explicit ``--dataset`` value, then ``GHOSTWATCH_DATASET``, then the
    repository default ``<repo>/dataset``. A supplied (non-default) path that does not
    exist fails with a clear message; it is never silently replaced by the repository
    dataset, so a grader who sets the environment variable cannot accidentally audit the
    wrong data. Mirrors ``evaluation.main.resolve_dataset_dir`` so both entry points behave
    identically.
    """

    if dataset is not None:
        candidate: str | Path = dataset
    else:
        candidate = os.environ.get(DATASET_ENV_VAR) or DEFAULT_DATASET
    path = Path(candidate).expanduser()
    if not path.is_dir():
        raise DatasetNotFoundError(
            f"dataset directory not found: {path} "
            "(pass --dataset PATH or set GHOSTWATCH_DATASET)"
        )
    return path


def render_run_summary(report: RunReport, *, output: Path | None = None) -> str:
    """Render the human-readable run summary printed to stdout.

    The disclosure of any evidence-limited case is part of the summary itself (not only of
    the diagnostic gap report), so every run that writes a final ``output.csv`` states which
    cases are honestly ``INCOMPLETE`` and why. T04 requires this limitation to be visible in
    the run output and in both reports.
    """

    lines = [
        f"cases audited: {len(report.rows)}",
        "status: " + ", ".join(f"{name}={count}" for name, count in sorted(report.status_counts.items())),
        f"run digest: {report.case_digest}",
        f"elapsed: {report.elapsed_seconds:.1f}s",
        f"model calls: {report.model_calls}  input tokens: {report.input_tokens}  output tokens: {report.output_tokens}",
    ]

    if report.problems:
        lines.append(f"contract problems: {len(report.problems)}")
        for problem in report.problems[:10]:
            lines.append("  " + problem.as_line())

    limited = report.evidence_limited_cases
    lines.append(f"contract-clean: {'yes' if report.contract_clean else 'no'}")
    lines.append(f"certifiable: {'yes' if report.certifiable else 'no'}")
    if limited:
        lines.append(
            f"evidence-limited cases (written INCOMPLETE, not certified complete): {len(limited)}"
        )
        lines.append("  " + ", ".join(limited))
        lines.append(
            "  limitation: the supplied evidence does not settle every copy/retention duty for "
            "these cases, so the audit keeps them INCOMPLETE with their reviewed plan rather "
            "than inventing a COMPLETE."
        )
        if output is not None:
            lines.append(
                f"  disclosure: {output} is written for submission with these cases INCOMPLETE; "
                "see code/evaluation/evaluation_report.md for the per-case limit."
            )
    return "\n".join(lines)


def _is_root_output(path: Path) -> bool:
    """True when ``path`` resolves to the repository-root submission artifact.

    ``--allow-partial`` is a diagnostic escape hatch and must never be able to overwrite the
    real ``output.csv``, whatever alias (relative path, ``..`` segment, case-variant) is used.
    """

    try:
        return path.resolve() == DEFAULT_OUTPUT.resolve()
    except OSError:  # pragma: no cover - defensive; an unresolvable path is not the root artifact
        return False


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - deletion audit runner")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help=(
            "participant dataset directory (default: $GHOSTWATCH_DATASET, then <repo>/dataset). "
            "An explicit value always takes precedence over the environment."
        ),
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="root output.csv path")
    parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="write draft predictions + gap report under code/evaluation/ instead of the final output",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "diagnostic escape hatch, never a final submission: write the run to --output even "
            "when it is not contract-clean. Refuses to touch the root output.csv path."
        ),
    )
    parser.add_argument(
        "--require-certifiable",
        action="store_true",
        help=(
            "strict release gate: refuse to write the output while any evidence-limited case "
            "remains unresolved (the pre-T04 fail-closed behaviour). The default release gate is "
            "contract-cleanliness, which still blocks on any schema/citation/order problem."
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="suppress progress lines")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        dataset_dir = resolve_dataset_dir(args.dataset)
    except DatasetNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    dataset = load_dataset(dataset_dir)

    # ``--allow-partial`` is a diagnostic escape hatch for a *non-final* run and must never be
    # able to touch the repository-root submission artifact, whatever the run's contract
    # cleanliness is. Checked before auditing so the refusal is independent of the run result
    # (T04: the split gate made a contract-clean run writable, which would otherwise have let
    # this flag reach the root path).
    if args.allow_partial and not args.diagnostic and _is_root_output(args.output):
        print(
            "refusing --allow-partial for the root output.csv path; use --diagnostic instead",
            file=sys.stderr,
        )
        return 2

    mode = "diagnostic" if args.diagnostic else "normal"
    report = audit_dataset(dataset, mode=mode, progress=not args.quiet)

    print(render_run_summary(report, output=None if args.diagnostic else args.output))

    if args.diagnostic:
        predictions, gaps = write_diagnostic(report, dataset)
        print(f"diagnostic draft written: {predictions}")
        print(f"diagnostic gap report written: {gaps}")
        print("root output.csv NOT touched (diagnostic mode)")
        return 0

    # ------------------------------------------------------------------ release gate (T04)
    # The gate has two independent conditions and they are checked in this order.
    #
    # 1. Contract cleanliness always blocks. A malformed, uncited or misordered answer is
    #    never written as final, no matter how many cases are decided.
    if not report.contract_clean:
        print(
            f"REFUSING to write {args.output}: the run has {len(report.problems)} contract "
            f"problem(s) and is not a valid answer.",
            file=sys.stderr,
        )
        if args.allow_partial:
            if _is_root_output(args.output):
                print(
                    "refusing --allow-partial for the root output.csv path; use --diagnostic instead",
                    file=sys.stderr,
                )
                return 2
            atomic_write(args.output, render_csv(report.rows))
            print(f"wrote non-final partial output to {args.output} (not a submission answer)", file=sys.stderr)
            return 3
        return 1

    # 2. Certifiability blocks only in strict mode. By default an evidence-limited case is
    #    recorded, disclosed and written as INCOMPLETE (its reviewed plan is honest); the
    #    competition contract requires a row for every case, and refusing the write would
    #    withhold the mandatory deliverable rather than improve it.
    if args.require_certifiable and not report.certifiable:
        print(
            f"REFUSING to write {args.output}: --require-certifiable is set and "
            f"{len(report.evidence_limited_cases)} evidence-limited case(s) remain unresolved "
            f"({', '.join(report.evidence_limited_cases)}).",
            file=sys.stderr,
        )
        return 1

    atomic_write(args.output, render_csv(report.rows))
    print(f"wrote {args.output} ({len(report.rows)} rows)")
    if not report.certifiable:
        print(
            f"note: {len(report.evidence_limited_cases)} evidence-limited case(s) are written "
            f"INCOMPLETE and disclosed in the run summary: {', '.join(report.evidence_limited_cases)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(run())
