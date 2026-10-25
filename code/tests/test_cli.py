"""T03/T04 acceptance tests for the terminal runner (``code/main.py``).

These pin the runner's contract behaviours:

* exactly one sorted row per request id, with the contracted schema for every row;
* deterministic output across two runs;
* the split release gate (T04): a **contract** problem always refuses the write and preserves
  an existing ``output.csv``, while a contract-clean run whose only remaining limitation is a
  genuine **evidence** gap writes the root ``output.csv`` and discloses the affected cases;
* ``--require-certifiable`` restores the strict fail-closed behaviour;
* the prediction path never reads the sample labels (``sample_output.csv``);
* diagnostic mode writes drafts to ``code/evaluation/`` and never touches the root output.

The gate tests use a disposable fixture output location, never the real repo-root
``output.csv``, except :func:`test_final_output_has_one_sorted_contract_row_per_case`, which
deliberately reads the real submission artifact after the T04 release run.

The frozen audit-core digest the default T04 run must reproduce:

``1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899``
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

import main as runner  # noqa: E402

#: SHA-256 over the canonical row serialization of the accepted T02 audit core. Unchanged by
#: T04: the split gate changes only whether the run may write, never what it decides.
FROZEN_CORE_DIGEST = "1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899"

#: The four genuine, disclosed evidence limits (T04 parent decision record).
EVIDENCE_LIMITED_CASES = ("case_46", "case_55", "case_61", "case_63")


@pytest.fixture(scope="module")
def real_report():
    """One audit of the real dataset, reused across the read-only assertions."""

    dataset = runner.load_dataset(REPO_ROOT / "dataset")
    return runner.audit_dataset(dataset, mode="normal")


def test_all_request_ids_once_sorted(real_report) -> None:
    """Exactly one output row per request id, sorted by ``case_id``."""

    dataset = runner.load_dataset(REPO_ROOT / "dataset")
    expected_ids = sorted(request.case_id for request in dataset.requests)
    rows = real_report.rows
    case_ids = [row[0] for row in rows]

    assert len(rows) == len(expected_ids) == 518
    assert case_ids == sorted(case_ids)
    assert case_ids == expected_ids
    assert len(set(case_ids)) == len(case_ids)


def test_every_row_matches_the_contracted_schema(real_report) -> None:
    """The runner emits zero contract problems over the real dataset."""

    assert real_report.problems == [], [p.as_line() for p in real_report.problems[:10]]
    for _case_id, status, steps_json in real_report.rows:
        payload = json.loads(steps_json)
        assert isinstance(payload, list)
        for offset, step in enumerate(payload, start=1):
            assert set(step) == {
                "step_no",
                "phase",
                "system_id",
                "resource_id",
                "operation",
                "state",
                "evidence_id",
            }
            assert step["step_no"] == offset
        if status == "NOT_APPLICABLE":
            assert payload == []


def test_output_is_deterministic() -> None:
    """Two independent runs produce byte-identical rows and digest."""

    dataset = runner.load_dataset(REPO_ROOT / "dataset")
    first = runner.audit_dataset(dataset, mode="normal")
    second = runner.audit_dataset(dataset, mode="normal")
    assert first.rows == second.rows
    assert first.digest() == second.digest()
    assert first.digest() == second.case_digest


def _contract_problem_injector(monkeypatch, case_id: str = "case_46") -> None:
    """Make ``runner.audit_dataset`` report a genuine contract problem for one case.

    This is the honest way to test the contract gate: the injected problem is a real
    :class:`runner.Problem` of a kind the validator itself produces, not a mock of the gate.
    """

    real_validate_row = runner.validate_row

    def validate_row(case_id_arg, status, steps_json, *, manifest_ids, activity_ids, audit_ids):
        problems = real_validate_row(
            case_id_arg,
            status,
            steps_json,
            manifest_ids=manifest_ids,
            activity_ids=activity_ids,
            audit_ids=audit_ids,
        )
        if case_id_arg == case_id:
            problems = list(problems) + [
                runner.Problem(case_id, "unknown_citation", "step 1 cites unknown id 'evidence_bogus'")
            ]
        return problems

    monkeypatch.setattr(runner, "validate_row", validate_row)
    # ``audit_dataset`` resolves the name from this module's globals, so the patch above is
    # what the run actually calls.


def test_invalid_run_does_not_replace_output(tmp_path, monkeypatch) -> None:
    """A **contract** problem refuses the write and leaves an existing output byte-for-byte intact.

    T04 re-expression: the previous revision used the four evidence limits as the trigger. The
    release gate is now split, so this test targets a genuine contract problem instead.
    """

    sentinel = tmp_path / "output.csv"
    sentinel_bytes = b"case_id,deletion_status,steps_json\ncase_XX,COMPLETE,[]\n"
    sentinel.write_bytes(sentinel_bytes)

    _contract_problem_injector(monkeypatch)

    exit_code = runner.run(
        [
            "--dataset",
            str(REPO_ROOT / "dataset"),
            "--output",
            str(sentinel),
            "--quiet",
        ]
    )

    assert exit_code == 1, "a contract-invalid run must exit non-zero"
    assert sentinel.read_bytes() == sentinel_bytes, "the previous output must be untouched"


def test_normal_run_writes_final_output_when_only_evidence_limits_remain(tmp_path) -> None:
    """The default run writes a real 518-row answer when the only limits are evidence gaps."""

    out = tmp_path / "output.csv"
    exit_code = runner.run(
        ["--dataset", str(REPO_ROOT / "dataset"), "--output", str(out), "--quiet"]
    )

    assert exit_code == 0, "a contract-clean run must write the final output"
    with out.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 518
    ids = [row["case_id"] for row in rows]
    assert ids == sorted(ids)
    assert len(set(ids)) == 518

    body = "".join(f"{row['case_id']}\t{row['deletion_status']}\t{row['steps_json']}\n" for row in rows)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() == FROZEN_CORE_DIGEST


def test_contract_problem_still_refuses_and_preserves_output(tmp_path, monkeypatch) -> None:
    """A contract problem refuses the root-path write and preserves the sentinel bytes."""

    sentinel = tmp_path / "sentinel.csv"
    sentinel_bytes = b"case_id,deletion_status,steps_json\ncase_ZZ,NOT_APPLICABLE,[]\n"
    sentinel.write_bytes(sentinel_bytes)

    _contract_problem_injector(monkeypatch, "case_55")

    exit_code = runner.run(
        ["--dataset", str(REPO_ROOT / "dataset"), "--output", str(sentinel), "--quiet"]
    )
    assert exit_code == 1
    assert sentinel.read_bytes() == sentinel_bytes


def test_require_certifiable_refuses_on_evidence_limits(tmp_path) -> None:
    """``--require-certifiable`` restores the strict gate: refuse while evidence limits remain."""

    sentinel = tmp_path / "output.csv"
    sentinel_bytes = b"SENTINEL\n"
    sentinel.write_bytes(sentinel_bytes)

    exit_code = runner.run(
        [
            "--dataset",
            str(REPO_ROOT / "dataset"),
            "--output",
            str(sentinel),
            "--require-certifiable",
            "--quiet",
        ]
    )
    assert exit_code == 1, "strict mode must refuse on the four evidence-limited cases"
    assert sentinel.read_bytes() == sentinel_bytes

    # The refusal names the four cases.
    report = runner.audit_dataset(runner.load_dataset(REPO_ROOT / "dataset"), mode="normal")
    assert report.evidence_limited_cases == list(EVIDENCE_LIMITED_CASES)
    assert not report.certifiable
    assert report.contract_clean


def test_final_output_has_one_sorted_contract_row_per_case() -> None:
    """The real root ``output.csv`` is a valid 518-row contract answer (T04 deliverable)."""

    root_output = REPO_ROOT / "output.csv"
    assert root_output.is_file(), (
        "the T04 release run must have written the repository-root output.csv "
        "(run: python code/main.py --quiet)"
    )

    with root_output.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        raw_rows = list(reader)

    assert header == ["case_id", "deletion_status", "steps_json"]
    assert len(raw_rows) == 518

    ids = [row[0] for row in raw_rows]
    assert ids == sorted(ids)
    assert len(set(ids)) == 518

    dataset = runner.load_dataset(REPO_ROOT / "dataset")
    expected_ids = sorted(request.case_id for request in dataset.requests)
    assert ids == expected_ids

    manifest_ids = frozenset(entry.file_id for entry in dataset.evidence_manifest)
    activity_ids = frozenset(event.activity_id for event in dataset.activity)
    audit_ids = frozenset(entry.audit_id for entry in dataset.audit_log)

    for case_id, status, steps_json in raw_rows:
        problems = runner.validate_row(
            case_id,
            status,
            steps_json,
            manifest_ids=manifest_ids,
            activity_ids=activity_ids,
            audit_ids=audit_ids,
        )
        assert problems == [], [p.as_line() for p in problems]

    # The four evidence-limited cases are present, honestly INCOMPLETE, with a non-empty plan.
    by_id = {row[0]: row for row in raw_rows}
    for case_id in EVIDENCE_LIMITED_CASES:
        assert case_id in by_id
        assert by_id[case_id][1] == "INCOMPLETE", f"{case_id} must stay INCOMPLETE"
        assert json.loads(by_id[case_id][2]) != [], f"{case_id} must carry its reviewed plan"


def test_run_summary_discloses_evidence_limited_cases(capsys) -> None:
    """The run summary names all four evidence-limited cases and states the limitation."""

    report = runner.audit_dataset(runner.load_dataset(REPO_ROOT / "dataset"), mode="normal")
    summary = runner.render_run_summary(report, output=REPO_ROOT / "output.csv")

    assert "contract-clean: yes" in summary
    assert "certifiable: no" in summary
    assert "evidence-limited cases" in summary
    for case_id in EVIDENCE_LIMITED_CASES:
        assert case_id in summary, f"{case_id} must be named in the run summary"
    # It must be described as a limitation, never as certified complete deletion.
    assert "not certified complete" in summary or "does not settle" in summary

    # And the CLI actually prints it (exit 0 path).
    exit_code = runner.run(
        ["--dataset", str(REPO_ROOT / "dataset"), "--diagnostic", "--quiet"]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "diagnostic" in captured.out.casefold()


def test_usage_report_proves_output_equality_not_mere_existence() -> None:
    """The usage report claims the submitted ``output.csv`` *matches* the measured run.

    Existence alone is not causality: the measured summary must carry the file's row count and
    digest and assert they equal the audit's own rows/digest (T04 precision fix).
    """

    from evaluation import usage

    summary = usage.measure_deterministic_run()
    submitted = summary["submitted_output"]

    assert submitted["exists"] is True
    assert submitted["matches_this_run"] is True, submitted["detail"]
    assert submitted["rows"] == summary["requests"] == 518
    assert submitted["digest"] == summary["digest"] == FROZEN_CORE_DIGEST

    rendered = usage.render_usage_report(summary)
    assert "matches this run exactly" in rendered
    assert "written by this run" not in rendered
    # The measured-zero paragraphs are unchanged by the precision fix.
    assert "zero" in rendered.casefold()

    # A mismatching file must be reported as a mismatch, never silently claimed as a match.
    tampered = dict(summary)
    tampered["submitted_output"] = {
        "path": submitted["path"],
        "exists": True,
        "rows": 517,
        "digest": "0" * 64,
        "matches_this_run": False,
        "detail": "differs",
    }
    mismatch = usage.render_usage_report(tampered)
    assert "does **not** match this run" in mismatch


def test_generated_usage_report_makes_only_the_equality_claim() -> None:
    """The submitted usage report must not claim the measured run wrote the file (T04 precision).

    ``measure_deterministic_run`` never writes ``output.csv``; it verifies the shipped file. The
    generated report must therefore make the *equality* claim only, and the stale
    ``written by this run`` phrasing must never reappear.
    """

    text = (REPO_ROOT / "code" / "evaluation" / "usage_report.md").read_text(encoding="utf-8")

    assert "matches this run exactly" in text
    assert "written by this run" not in text
    assert "writes the submitted" not in text
    # The equality claim carries the real counts and digest, not just a boolean.
    assert "518 rows and digest `1ca178f1f71eaa27f263ebf6fa5451d6fd9f472f6b71ddf1f4e276b4b0a51899`" in text
    # The measured-zero token/cost paragraphs are unchanged by the precision fix.
    assert "unavailable" in text.casefold()


def test_reports_describe_final_output_and_disclosed_limits() -> None:
    """The regenerated evaluation report states the root output was written and names the four."""

    text = (REPO_ROOT / "code" / "evaluation" / "evaluation_report.md").read_text(encoding="utf-8")

    # It must say the deliverable exists (the pre-T04 narrative claimed it never would, and the
    # old row asserted "Final `output.csv` written | **No**").
    assert "**Yes** — the root answer was written by this run" in text
    assert "Final `output.csv` written | **No**" not in text
    assert "**The deliverable is not submission-ready.**" not in text

    for case_id in EVIDENCE_LIMITED_CASES:
        assert case_id in text, f"{case_id} must be disclosed in the evaluation report"

    # The disclosure must be explicitly non-certifying.
    folded = text.casefold()
    assert "evidence-limited" in folded or "evidence limited" in folded
    assert "not certified" in folded or "not a certified" in folded or "cannot certify" in folded


def test_t04_disclosure_gate_constants_are_consistent() -> None:
    """The report/README disclosure and the runner agree on the four limited cases."""

    report = runner.audit_dataset(runner.load_dataset(REPO_ROOT / "dataset"), mode="normal")
    assert report.evidence_limited_cases == list(EVIDENCE_LIMITED_CASES)
    assert report.contract_clean is True
    assert report.certifiable is False
    assert report.ok is False  # strict semantics preserved
    # The frozen digest is what the core actually produces (T04 must not change decisions).
    assert report.case_digest == FROZEN_CORE_DIGEST


def test_allow_partial_refuses_the_root_output_path(tmp_path) -> None:
    """``--allow-partial`` can never be used to overwrite the real root ``output.csv``."""

    exit_code = runner.run(
        ["--dataset", str(REPO_ROOT / "dataset"), "--quiet", "--allow-partial"]
    )
    # Refuses the root path with a dedicated, non-zero exit code.
    assert exit_code == 2


def test_diagnostic_mode_never_writes_root_output(tmp_path, monkeypatch) -> None:
    """Diagnostic mode writes drafts under code/evaluation and never the root output."""

    predictions = tmp_path / "preds.csv"
    gaps = tmp_path / "gaps.md"
    monkeypatch.setattr(runner, "DIAGNOSTIC_PREDICTIONS", predictions)
    monkeypatch.setattr(runner, "DIAGNOSTIC_GAPS", gaps)

    root_output = REPO_ROOT / "output.csv"
    existed_before = root_output.exists()

    exit_code = runner.run(["--dataset", str(REPO_ROOT / "dataset"), "--diagnostic", "--quiet"])

    assert exit_code == 0
    assert predictions.is_file()
    assert gaps.is_file()
    assert root_output.exists() == existed_before

    # The draft must be a valid predictions CSV with 518 sorted rows.
    with predictions.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 518
    assert [row["case_id"] for row in rows] == sorted(row["case_id"] for row in rows)
    assert "NOT a submission answer" in gaps.read_text(encoding="utf-8")


def test_csv_quoting_handles_embedded_quotes() -> None:
    """The renderer quotes fields containing commas or quotes."""

    text = runner.render_csv([("case_q", "COMPLETE", '[{"evidence_id":""}]')])
    lines = text.strip().splitlines()
    assert lines[0] == "case_id,deletion_status,steps_json"
    assert '"' in lines[1]


def test_digest_recipe_is_stable() -> None:
    """The digest equals a sha256 over the documented canonical row serialization."""

    dataset = runner.load_dataset(REPO_ROOT / "dataset")
    report = runner.audit_dataset(dataset, mode="normal")
    expected = report.digest()
    assert len(expected) == 64
    assert expected == report.case_digest


def test_external_dataset_path_is_accepted(tmp_path) -> None:
    """``--dataset`` pointing outside the repository audits the same requests."""

    import shutil

    external = tmp_path / "supplied dataset"
    shutil.copytree(REPO_ROOT / "dataset", external)

    report = runner.audit_dataset(runner.load_dataset(external), mode="normal")
    baseline = runner.audit_dataset(runner.load_dataset(REPO_ROOT / "dataset"), mode="normal")
    assert len(report.rows) == 518
    assert report.case_digest == baseline.case_digest


def test_diagnostic_mode_ignores_explicit_output(tmp_path, monkeypatch) -> None:
    """``--diagnostic`` never writes ``--output``, even when one is supplied."""

    predictions = tmp_path / "preds.csv"
    gaps = tmp_path / "gaps.md"
    monkeypatch.setattr(runner, "DIAGNOSTIC_PREDICTIONS", predictions)
    monkeypatch.setattr(runner, "DIAGNOSTIC_GAPS", gaps)

    victim = tmp_path / "victim.csv"
    victim.write_bytes(b"sentinel\n")

    exit_code = runner.run(
        [
            "--dataset",
            str(REPO_ROOT / "dataset"),
            "--diagnostic",
            "--output",
            str(victim),
            "--quiet",
        ]
    )
    assert exit_code == 0
    assert victim.read_bytes() == b"sentinel\n"
    assert predictions.is_file()


def test_runner_dataset_precedence_cli_over_env_over_default(tmp_path, monkeypatch) -> None:
    """The runner resolves ``--dataset`` > ``GHOSTWATCH_DATASET`` > ``<repo>/dataset``.

    The environment fallback documented in the README/extracted layout must actually be
    implemented (the fix1 review found the runner ignored it and silently used the
    repository dataset).
    """

    import shutil

    external = tmp_path / "external dataset with spaces"
    shutil.copytree(REPO_ROOT / "dataset", external)

    # 1. Explicit argument resolved directly.
    assert runner.resolve_dataset_dir(external) == external
    # 2. Environment is honoured when the argument is omitted.
    monkeypatch.setenv("GHOSTWATCH_DATASET", str(external))
    assert runner.resolve_dataset_dir() == external
    # 3. An explicit argument still wins over the environment.
    monkeypatch.setenv("GHOSTWATCH_DATASET", str(tmp_path / "bogus"))
    assert runner.resolve_dataset_dir(external) == external


def test_runner_invalid_environment_path_fails_clearly(tmp_path, monkeypatch) -> None:
    """An invalid ``GHOSTWATCH_DATASET`` fails with a clear exit-2 error, never a silent fallback."""

    monkeypatch.setenv("GHOSTWATCH_DATASET", str(tmp_path / "does-not-exist"))

    # The resolver raises rather than silently reverting to the repository dataset.
    with pytest.raises(runner.DatasetNotFoundError):
        runner.resolve_dataset_dir()

    # The CLI surfaces it as a clear non-zero exit with no traceback.
    assert runner.run(["--quiet"]) == 2


def test_runner_env_dataset_is_actually_audited(tmp_path, monkeypatch) -> None:
    """With the environment set (no ``--dataset``) the runner audits the supplied copy."""

    import shutil

    external = tmp_path / "supplied dataset"
    shutil.copytree(REPO_ROOT / "dataset", external)
    monkeypatch.setenv("GHOSTWATCH_DATASET", str(external))

    report = runner.audit_dataset(runner.load_dataset(runner.resolve_dataset_dir()), mode="normal")
    baseline = runner.audit_dataset(runner.load_dataset(REPO_ROOT / "dataset"), mode="normal")
    assert len(report.rows) == 518
    assert report.case_digest == baseline.case_digest
