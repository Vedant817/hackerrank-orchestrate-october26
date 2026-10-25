"""T03 acceptance tests for the evaluation harness (``code/evaluation``).

These pin the harness's contract:

* sample labels never enter the prediction path (the loader is only reached after
  predictions exist, and its call graph is asserted);
* the metrics genuinely detect a wrong evidence id and a wrong step order;
* the three required authored cases exist, cover historical identifiers / temporal
  recreation / tombstone-retention, and pass;
* the usage reporter derives calls/tokens from measured data and never invents a rate.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from evaluation import custom_cases, main as evaluation  # noqa: E402


def _step(phase, operation, system_id, resource_id, state, evidence_id=""):
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def test_metrics_detect_wrong_evidence_and_sequence() -> None:
    """A wrong evidence id and a swapped step order are both detected."""

    expected_steps = [
        _step("FINDING", "REPORT_REMAINING_RECORD", "account_service", "account_1", "PRESENT", "evidence_01"),
        _step("REMEDIATION", "DELETE_RECORD", "account_service", "account_1", "ABSENT", ""),
        _step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_1", "ABSENT", ""),
    ]
    labels = {"case_x": ("INCOMPLETE", expected_steps)}

    # Correct prediction: perfect score.
    good = evaluation.Prediction(case_id="case_x", deletion_status="INCOMPLETE", steps=list(expected_steps))
    good_result = evaluation.score_predictions("good", {"case_x": good}, labels)
    assert good_result.status_accuracy == 1.0
    assert good_result.step_precision == 1.0
    assert good_result.step_recall == 1.0
    assert good_result.sequence_accuracy == 1.0
    assert good_result.evidence_accuracy == 1.0
    assert good_result.field_accuracy == 1.0

    # Wrong evidence id: the exact-step identity no longer matches (recall drops) *and* the
    # evidence/field metrics drop, because evidence is a scored field rather than an
    # all-or-nothing condition on the pair.
    wrong_evidence_steps = list(expected_steps)
    wrong_evidence_steps[0] = _step(
        "FINDING", "REPORT_REMAINING_RECORD", "account_service", "account_1", "PRESENT", "evidence_99"
    )
    wrong_evidence = evaluation.Prediction(
        case_id="case_x", deletion_status="INCOMPLETE", steps=wrong_evidence_steps
    )
    wrong_result = evaluation.score_predictions("wrong-evidence", {"case_x": wrong_evidence}, labels)
    assert wrong_result.step_recall < 1.0
    assert wrong_result.evidence_accuracy < 1.0
    assert wrong_result.field_accuracy < 1.0
    assert wrong_result.sequence_accuracy == 0.0

    # Swapped remediation/verification order: same steps, wrong sequence.
    swapped_steps = [expected_steps[0], expected_steps[2], expected_steps[1]]
    swapped = evaluation.Prediction(case_id="case_x", deletion_status="INCOMPLETE", steps=swapped_steps)
    swapped_result = evaluation.score_predictions("swapped", {"case_x": swapped}, labels)
    assert swapped_result.sequence_accuracy == 0.0
    # The step *set* is unchanged, so precision/recall stay perfect.
    assert swapped_result.step_precision == 1.0
    assert swapped_result.step_recall == 1.0


def test_status_error_is_counted() -> None:
    labels = {"case_y": ("COMPLETE", [_step("VERIFICATION", "VERIFY_RECORD_ABSENT", "a", "account_1", "ABSENT", "evidence_01")])}
    wrong = evaluation.Prediction(
        case_id="case_y",
        deletion_status="INCOMPLETE",
        steps=[_step("VERIFICATION", "VERIFY_RECORD_ABSENT", "a", "account_1", "ABSENT", "evidence_01")],
    )
    result = evaluation.score_predictions("status", {"case_y": wrong}, labels)
    assert result.status_accuracy == 0.0
    assert result.step_precision == 1.0


def test_field_metric_is_not_circular() -> None:
    """A single wrong scored field is an error, and never shrinks the denominator.

    Regression for the review finding that the previous alignment keyed on the six
    serialized fields and then re-scored a subset of them, so a wrong field silently
    removed the pair from the denominator and left field accuracy at 100%.
    """

    expected_steps = [
        _step("FINDING", "REPORT_REMAINING_RECORD", "account_service", "account_1", "PRESENT", "evidence_01"),
        _step("REMEDIATION", "DELETE_RECORD", "account_service", "account_1", "ABSENT", ""),
        _step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_1", "ABSENT", ""),
    ]
    labels = {"case_x": ("INCOMPLETE", expected_steps)}

    exact = evaluation.score_predictions(
        "exact",
        {"case_x": evaluation.Prediction("case_x", "INCOMPLETE", [dict(s) for s in expected_steps])},
        labels,
    )
    assert exact.field_accuracy == 1.0
    assert exact.field_total == 3 * len(evaluation.ALIGN_FIELDS)
    assert exact.field_errors == 0

    for field, wrong in (
        ("system_id", "WRONG_SERVICE"),
        ("resource_id", "account_999"),
        ("state", "ABSENT"),
        ("evidence_id", "evidence_99"),
    ):
        mutated = [dict(step) for step in expected_steps]
        mutated[0][field] = wrong
        result = evaluation.score_predictions(
            f"wrong-{field}",
            {"case_x": evaluation.Prediction("case_x", "INCOMPLETE", mutated)},
            labels,
        )
        assert result.field_total == exact.field_total, f"{field}: denominator shrank"
        assert result.field_errors == 1, f"{field}: expected exactly one field error"
        assert result.field_accuracy < 1.0, f"{field}: wrong value not detected"


def test_alignment_key_is_disjoint_from_scored_fields() -> None:
    """The alignment key must not contain any scored field (non-circularity invariant)."""

    assert not (set(evaluation.ALIGNMENT_KEY) & set(evaluation.ALIGN_FIELDS))
    assert set(evaluation.ALIGNMENT_KEY) | set(evaluation.ALIGN_FIELDS) <= set(evaluation.STEP_KEY_FIELDS)


def test_missing_and_extra_steps_increase_denominators() -> None:
    """Missing, extra, duplicate and permuted steps are all handled explicitly."""

    expected_steps = [
        _step("FINDING", "REPORT_REMAINING_RECORD", "account_service", "account_1", "PRESENT", "evidence_01"),
        _step("REMEDIATION", "DELETE_RECORD", "account_service", "account_1", "ABSENT", ""),
        _step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_1", "ABSENT", ""),
    ]
    labels = {"case_x": ("INCOMPLETE", expected_steps)}
    full_denominator = 3 * len(evaluation.ALIGN_FIELDS)

    # Missing a step: one unmatched label step contributes its scored fields as errors.
    missing = evaluation.score_predictions(
        "missing",
        {"case_x": evaluation.Prediction("case_x", "INCOMPLETE", [dict(s) for s in expected_steps[:2]])},
        labels,
    )
    assert missing.unmatched_expected == 1
    assert missing.unmatched_predicted == 0
    assert missing.field_total == full_denominator
    assert missing.field_accuracy < 1.0

    # An extra step: one unmatched predicted step also contributes scored-field errors.
    extra_steps = [dict(s) for s in expected_steps] + [
        _step("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_1", "PRESENT", "evidence_02")
    ]
    extra = evaluation.score_predictions(
        "extra", {"case_x": evaluation.Prediction("case_x", "INCOMPLETE", extra_steps)}, labels
    )
    assert extra.unmatched_predicted == 1
    assert extra.field_total == 4 * len(evaluation.ALIGN_FIELDS)
    assert extra.field_errors == len(evaluation.ALIGN_FIELDS)

    # A duplicate step is an extra step, not a silent merge.
    duplicate = evaluation.score_predictions(
        "duplicate",
        {
            "case_x": evaluation.Prediction(
                "case_x",
                "INCOMPLETE",
                [dict(s) for s in expected_steps] + [dict(expected_steps[0])],
            )
        },
        labels,
    )
    assert duplicate.unmatched_predicted == 1
    assert duplicate.step_fp == 1
    assert duplicate.field_errors == len(evaluation.ALIGN_FIELDS)

    # A permutation keeps the multiset (perfect precision/recall) but breaks the sequence.
    permuted = evaluation.score_predictions(
        "permuted",
        {
            "case_x": evaluation.Prediction(
                "case_x", "INCOMPLETE", [expected_steps[0], expected_steps[2], expected_steps[1]]
            )
        },
        labels,
    )
    assert permuted.step_precision == 1.0 and permuted.step_recall == 1.0
    assert permuted.sequence_accuracy == 0.0
    assert permuted.field_errors == 0
    assert permuted.field_total == full_denominator


def test_field_alignment_matches_across_duplicated_operations() -> None:
    """Two same-(phase, operation) steps align one-to-one, in order, and score fields."""

    expected_steps = [
        _step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_1", "ABSENT", ""),
        _step("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_2", "ABSENT", ""),
    ]
    labels = {"case_dup": ("COMPLETE", expected_steps)}

    # In canonical order: both pairs align and every scored field agrees.
    in_order = evaluation.score_predictions(
        "in-order",
        {"case_dup": evaluation.Prediction("case_dup", "COMPLETE", [dict(s) for s in expected_steps])},
        labels,
    )
    assert in_order.aligned_pairs == 2
    assert in_order.unmatched_expected == 0 and in_order.unmatched_predicted == 0
    assert in_order.field_accuracy == 1.0

    # Reversed within the group: positional pairing surfaces the resource mismatch instead of
    # silently realigning the two steps.
    reversed_steps = [expected_steps[1], expected_steps[0]]
    reversed_result = evaluation.score_predictions(
        "reversed",
        {"case_dup": evaluation.Prediction("case_dup", "COMPLETE", reversed_steps)},
        labels,
    )
    assert reversed_result.aligned_pairs == 2
    assert reversed_result.unmatched_expected == 0 and reversed_result.unmatched_predicted == 0
    assert reversed_result.field_errors == 2  # resource_1/2 disagreed in both pairs
    assert reversed_result.field_accuracy < 1.0
    # The exact-step multiset is unaffected, so precision/recall stay perfect.
    assert reversed_result.step_precision == 1.0 and reversed_result.step_recall == 1.0


def test_public_sample_census_matches_the_reported_numbers() -> None:
    """The census the report publishes is derived from the evaluator, not transcribed."""

    result = evaluation.evaluate_dataset()
    assert result.step_fn == 56
    assert result.step_fp == 7
    assert result.step_tp == 137
    # Net difference: predicted - label = (TP + FP) - (TP + FN) = FP - FN.
    assert result.step_fp - result.step_fn == -49
    assert result.fn_by_op[("account_service", "VERIFY_RECORD_ABSENT")] == 28
    assert result.fp_by_op[("integration_service", "REPORT_ACTIVE_DATA_FLOW")] == 1
    assert sum(result.fp_by_case_op.values()) == 7
    # Per-operation totals must reconcile with the headline counts.
    assert sum(result.fn_by_op.values()) == result.step_fn
    assert sum(result.fp_by_op.values()) == result.step_fp


def test_external_dataset_path_is_honoured(tmp_path) -> None:
    """The harness can score a dataset supplied outside the repository."""

    import shutil

    external = tmp_path / "dataset with spaces"
    shutil.copytree(REPO_ROOT / "dataset", external)
    result = evaluation.evaluate_dataset(external)
    baseline = evaluation.evaluate_dataset()
    assert result.cases == baseline.cases == 32
    assert result.status_correct == baseline.status_correct
    assert result.step_fn == baseline.step_fn
    assert evaluation.resolve_dataset_dir(external) == external


def test_missing_external_dataset_fails_clearly(tmp_path) -> None:
    """A missing or incomplete dataset path reports a clear error."""

    with pytest.raises(FileNotFoundError):
        evaluation.resolve_dataset_dir(tmp_path / "does-not-exist")

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        evaluation.resolve_dataset_dir(empty)


def test_dataset_env_var_is_honoured(tmp_path, monkeypatch) -> None:
    """``GHOSTWATCH_DATASET`` is the documented fallback for a supplied dataset."""

    monkeypatch.setenv("GHOSTWATCH_DATASET", str(REPO_ROOT / "dataset"))
    assert evaluation.resolve_dataset_dir() == REPO_ROOT / "dataset"


def test_both_report_mirrors_are_byte_identical() -> None:
    """``code/evaluation/`` and root ``evaluation/`` report copies must not drift."""

    for name in ("evaluation_report.md", "usage_report.md"):
        primary = REPO_ROOT / "code" / "evaluation" / name
        mirror = REPO_ROOT / "evaluation" / name
        assert primary.is_file(), f"missing {primary}"
        assert mirror.is_file(), f"missing {mirror}"
        assert primary.read_bytes() == mirror.read_bytes(), f"{name} mirrors differ"


def test_report_census_matches_the_live_evaluator() -> None:
    """The published census is reproducible from the harness, not hand-written."""

    from evaluation import report_gen

    sample = evaluation.evaluate_dataset()
    text = report_gen.build_evaluation_report(sample, custom_cases.run_all())

    assert f"| Case-status accuracy | {sample.status_correct}/{sample.cases} |" in text
    assert f"| Field accuracy (independent alignment) | {sample.field_matches['__total__']}/{sample.field_total} |" in text
    assert f"(FN): **{sample.step_fn}**" in text
    assert f"(FP): **{sample.step_fp}**" in text
    assert f"**{sample.step_fp - sample.step_fn}**" in text
    # The headline metric rows must be the live values, not the retired tautological ones.
    assert f"| Field accuracy (independent alignment) | {sample.field_matches['__total__']}/{sample.field_total} |" in text
    assert "| Field accuracy (independent alignment) | 685/685 |" not in text
    assert "| Evidence agreement (independent alignment) | 55/55 |" not in text
    # The retired metric must be described as tautological, never as a measured strength.
    assert "tautological" in text


def test_sample_labels_never_enter_predictions() -> None:
    """The prediction callable runs to completion before any label is loaded."""

    order: list[str] = []
    labels_path = REPO_ROOT / "dataset" / "sample_output.csv"
    requests_path = REPO_ROOT / "dataset" / "sample_deletion_requests.csv"

    original_load_labels = evaluation.load_labels

    def spy_load_labels(path=None):
        order.append("labels")
        return original_load_labels(path)

    def predict(row):
        order.append("predict")
        return evaluation.Prediction(case_id=row["case_id"], deletion_status="COMPLETE", steps=[])

    evaluation.load_labels = spy_load_labels
    try:
        evaluation.run_sample_evaluation(predict, labels_path=labels_path, requests_path=requests_path)
    finally:
        evaluation.load_labels = original_load_labels

    assert "predict" in order and "labels" in order
    assert order.index("labels") > max(
        index for index, name in enumerate(order) if name == "predict"
    ), "labels must be loaded only after every prediction exists"


def test_sample_evaluation_runs_and_reports_denominators() -> None:
    """The real sample evaluation produces metrics with non-trivial denominators."""

    result = evaluation.evaluate_dataset()
    assert result.cases == 32
    assert 0 <= result.status_correct <= 32
    assert result.step_tp + result.step_fn > 0
    assert result.field_total > 0
    assert result.evidence_total >= 0
    # The harness must never open the labels during prediction; this run is label-free.
    assert not result.missing_cases


@pytest.mark.parametrize("name", ["historical_identifier", "temporal_recreation", "tombstone_retention"])
def test_three_custom_cases(name) -> None:
    """The three contract-required authored cases exist and pass."""

    names = {case.name for case in custom_cases.CASES}
    assert name in names
    case = next(case for case in custom_cases.CASES if case.name == name)
    record = custom_cases.run_case(case)
    assert record["passed"], record["note"]
    assert record["predicted_status"] == record["expected_status"]


def test_custom_cases_cover_the_required_behaviours() -> None:
    blobs = " ".join(
        f"{case.name} {case.focus} {case.expected_behaviour}" for case in custom_cases.CASES
    ).casefold()
    assert "historical" in blobs
    assert "recreation" in blobs or "temporal" in blobs
    assert "tombstone" in blobs and ("retention" in blobs or "retain" in blobs)
    assert len(custom_cases.CASES) >= 3


def test_usage_is_actual_not_estimated_tokens() -> None:
    """The usage summary reports measured counts and never invents a cost rate."""

    from evaluation import usage

    summary = usage.measure_deterministic_run()
    assert summary["model_calls"] == 0
    assert summary["input_tokens"] == 0
    assert summary["output_tokens"] == 0
    # Cost rates are unavailable, so the report must say so rather than fabricate a number.
    rendered = usage.render_usage_report(summary)
    assert "unavailable" in rendered.casefold()
    assert "0" in rendered
    # Development-agent usage must be called out as separate from runtime inference.
    assert "development" in rendered.casefold()


def test_evidence_denominator_split_reconciles() -> None:
    """The published evidence denominator is 55 aligned + 20 unmatched = 75, not 75 aligned."""

    result = evaluation.evaluate_dataset()
    assert result.evidence_aligned_total == 55
    assert result.evidence_unmatched_total == 20
    assert result.evidence_aligned_total + result.evidence_unmatched_total == result.evidence_total == 75
    # Only the aligned portion can ever match, so the ceiling is 55/75.
    assert result.evidence_matches <= result.evidence_aligned_total


def test_run_sample_evaluation_defaults_labels_to_supplied_dataset(tmp_path) -> None:
    """``run_sample_evaluation(dataset_dir=X)`` defaults labels to ``X/sample_output.csv``.

    A distinct external label/reference pair proves the supplied dataset is honoured and the
    repository labels are never consulted (no prediction-label leakage).
    """

    import csv

    external = tmp_path / "external labels dataset"
    external.mkdir()
    # Minimal requests file with one case, plus a *distinct* reference label for it.
    with (external / "sample_deletion_requests.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"])
        writer.writerow(["case_ext", "x@example.com", "2026-03-01T00:00:00Z", "COMPLETE", "2026-03-02T00:00:00Z", "2026-03-10T00:00:00Z", "delete"])
    label_steps = [
        {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service",
         "resource_id": "account_ext", "operation": "VERIFY_RECORD_ABSENT",
         "state": "ABSENT", "evidence_id": "evidence_ext"}
    ]
    import json as _json

    with (external / "sample_output.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        writer.writerow(["case_ext", "COMPLETE", _json.dumps(label_steps)])

    def predict(row):
        # Echo the external label back, so a perfect score proves the external file was read.
        return evaluation.Prediction(case_id=row["case_id"], deletion_status="COMPLETE", steps=[dict(s) for s in label_steps])

    result = evaluation.run_sample_evaluation(predict, dataset_dir=external)
    assert result.cases == 1
    assert result.status_correct == 1
    assert result.evidence_total == 1 and result.evidence_matches == 1


def test_custom_cases_rejects_unknown_flags() -> None:
    """The self-contained authored-case runner rejects ``--dataset`` rather than ignoring it."""

    from evaluation import custom_cases

    with pytest.raises(SystemExit):
        custom_cases.main(["--dataset", "somewhere"])


def test_report_gen_docstring_commands_are_verified() -> None:
    """``report_gen`` advertises only working commands and documents its dataset resolution."""

    from evaluation import report_gen

    doc = report_gen.__doc__ or ""
    assert "python -m code.evaluation.report_gen" not in doc
    assert "python -m evaluation.report_gen" in doc
    assert "--dataset" in doc  # states it takes no --dataset flag


def test_evaluator_script_mode_and_module_mode_agree(tmp_path) -> None:
    """Both documented evaluation entry points run and agree (script mode was broken in fix1)."""

    import json as _json
    import subprocess

    def run_json(args: list[str], cwd: Path) -> dict:
        completed = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8"
        )
        assert completed.returncode == 0, completed.stderr
        assert "Traceback" not in completed.stderr, completed.stderr
        return _json.loads(completed.stdout)

    script = run_json([sys.executable, "code/evaluation/main.py", "--json"], REPO_ROOT)
    module = run_json([sys.executable, "-m", "evaluation.main", "--json"], CODE_DIR)
    assert script["status_correct"] == module["status_correct"] == 27
    assert script["field_total"] == module["field_total"] == 792


def test_report_gen_resolves_dataset_via_env(tmp_path, monkeypatch) -> None:
    """``report_gen`` honours ``GHOSTWATCH_DATASET`` (no hardcoded repo dataset)."""

    import shutil

    from evaluation import report_gen

    monkeypatch.setenv("GHOSTWATCH_DATASET", str(REPO_ROOT / "dataset"))
    assert report_gen._resolve_dataset() == REPO_ROOT / "dataset"

    # A distinct external dataset is resolved from the environment, proving the env var is
    # genuinely consulted rather than a coincidental match to the repo default.
    external = tmp_path / "external dataset"
    shutil.copytree(REPO_ROOT / "dataset", external)
    monkeypatch.setenv("GHOSTWATCH_DATASET", str(external))
    assert report_gen._resolve_dataset() == external

    # The resolver is the evaluator's documented one, so the precedence is shared, not duplicated.
    from evaluation import main as ev

    assert ev.resolve_dataset_dir(None) == external


def test_report_gen_missing_dataset_fails_cleanly(tmp_path, monkeypatch, capsys) -> None:
    """A missing/invalid dataset makes ``report_gen.main()`` exit 2, never a traceback."""

    from evaluation import report_gen

    monkeypatch.setenv("GHOSTWATCH_DATASET", str(tmp_path / "does-not-exist"))
    # Guard against accidentally touching live report files: point the write roots at a temp dir.
    monkeypatch.setattr(report_gen, "REPO_ROOT", tmp_path, raising=True)
    code = report_gen.main()
    assert code == 2
    captured = capsys.readouterr()
    assert "dataset directory not found" in captured.err
    assert "Traceback" not in captured.err


def test_usage_invalid_dataset_exits_two(tmp_path, monkeypatch, capsys) -> None:
    """``usage`` normalizes an invalid dataset to a clean exit 2 (matches runner/evaluator)."""

    from evaluation import usage

    monkeypatch.setenv("GHOSTWATCH_DATASET", str(tmp_path / "does-not-exist"))
    code = usage.main([])
    assert code == 2
    captured = capsys.readouterr()
    assert "dataset directory not found" in captured.err
    assert "Traceback" not in captured.err


def test_usage_explicit_dataset_overrides_invalid_env(tmp_path, monkeypatch, capsys) -> None:
    """An explicit ``--dataset`` wins over a bad ``GHOSTWATCH_DATASET`` for ``usage``."""

    from evaluation import usage

    monkeypatch.setenv("GHOSTWATCH_DATASET", str(tmp_path / "does-not-exist"))
    code = usage.main(["--dataset", str(REPO_ROOT / "dataset")])
    assert code == 0
    captured = capsys.readouterr()
    assert '"requests": 518' in captured.out


def test_usage_missing_explicit_dataset_exits_two(tmp_path, capsys) -> None:
    """A missing explicit ``--dataset`` path also exits 2 with a clear diagnostic."""

    from evaluation import usage

    code = usage.main(["--dataset", str(tmp_path / "nope")])
    assert code == 2
    captured = capsys.readouterr()
    assert "dataset directory not found" in captured.err
    assert "Traceback" not in captured.err
