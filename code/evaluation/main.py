"""Ghost Data Still Exists - evaluation harness.

The harness measures the accepted audit core against the **public** sample answers
(``dataset/sample_output.csv``) and against a set of authored fixtures
(:mod:`evaluation.custom_cases`).

Isolation rule (T03 build-notes): the labels are read **only** inside this module, after
predictions have already been produced from participant inputs. The prediction path never
imports or receives a label. ``run_sample_evaluation`` therefore takes a callable that
maps a request to a prediction; the label file is opened afterwards and never handed back.

Metrics reported (with explicit denominators):

* **exact-step** precision / recall / F1 (micro) and whole-array exact-sequence match, over
  the six-field identity (``phase``, ``operation``, ``system_id``, ``resource_id``,
  ``state``, ``evidence_id``) — a *separate* metric family, never mixed with field scoring;
* **field accuracy** over an independent one-to-one alignment that deliberately does *not*
  use the fields being scored, so a wrong field is counted as a field error instead of
  deleting the pair from the denominator;
* **evidence agreement** over the same independent alignment;
* **sequence accuracy**: exact array equality plus position-wise order agreement.

The harness is deterministic and offline: no model is called, so it never fabricates
token usage. See ``usage_report.md`` for the measured runtime usage (zero model calls for
the deterministic run).

Alignment contract (why the field metric is not circular)
---------------------------------------------------------

Earlier revisions aligned steps on the full six-field identity and then re-scored those same
fields, which is a tautology: an alignment could only exist when every scored field already
agreed, so ``field_accuracy`` was definitionally 100% and could never detect a wrong field.
The current design separates the two concerns:

* ``STEP_KEY_FIELDS`` = the six serialized fields — used **only** for the exact-step
  precision/recall/F1 and the whole-array exact-sequence metric.
* ``ALIGNMENT_KEY`` = ``(phase, operation)`` — used **only** to group steps for field scoring.
  Neither element is scored there, and the scored fields (``system_id``, ``resource_id``,
  ``state``, ``evidence_id``) are disjoint from it, so a mismatch in a scored field is
  observable.
* ``ALIGN_FIELDS`` = ``(system_id, resource_id, state, evidence_id)`` — the scored fields.

Within an alignment group the assignment is a deterministic **positional one-to-one** match, so
extra predicted steps become ``unmatched_predicted``, missing label steps become
``unmatched_expected``, and misaligned pairs surface as per-field mismatches. Denominators are
cumulative over the evaluation, never narrowed by a mismatch:

``field_total = ALIGNED_PAIRS * 4 + UNMATCHED_EXPECTED * 4 + UNMATCHED_PREDICTED * 4``

Missing, extra, duplicate and permuted steps therefore all *increase* the denominator and the
``field_errors`` count rather than shrinking them. A wrong evidence id is a scored-field
mismatch, so it counts as an error instead of silently removing the pair.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"
SAMPLE_LABELS = DATASET_DIR / "sample_output.csv"

#: Exact-step identity for precision/recall/F1 and whole-array exact-sequence match.
STEP_KEY_FIELDS = ("phase", "operation", "system_id", "resource_id", "state", "evidence_id")

#: Grouping key for field scoring. Deliberately disjoint from ``ALIGN_FIELDS`` so the field
#: metric is not conditioned on the values it measures.
ALIGNMENT_KEY = ("phase", "operation")

#: The fields scored within an alignment group (``evidence_id`` at the field level rather than
#: as an all-or-nothing condition on the pair).
ALIGN_FIELDS = ("system_id", "resource_id", "state", "evidence_id")

#: The four scored fields in a fixed order.
_FIELD_ORDER = ("system_id", "resource_id", "state", "evidence_id")


# --------------------------------------------------------------------------------------
# Label loading (evaluation-only)
# --------------------------------------------------------------------------------------


def load_labels(path: Path | None = None) -> dict[str, tuple[str, list[dict]]]:
    """Load ``sample_output.csv`` as ``case_id -> (status, steps)``.

    This is the **only** place the label file is opened. It is called by the evaluation
    driver after predictions exist, never by the prediction path.
    """

    import csv

    target = path or SAMPLE_LABELS
    labels: dict[str, tuple[str, list[dict]]] = {}
    with target.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            labels[row["case_id"]] = (row["deletion_status"], json.loads(row["steps_json"]))
    return labels


# --------------------------------------------------------------------------------------
# Prediction shape
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Prediction:
    case_id: str
    deletion_status: str
    steps: list[dict]


def prediction_from_row(case_id: str, status: str, steps_json: str) -> Prediction:
    return Prediction(case_id=case_id, deletion_status=status, steps=list(json.loads(steps_json)))


def load_predictions(path: Path) -> dict[str, Prediction]:
    """Load a predictions CSV (the runner's output format)."""

    import csv

    predictions: dict[str, Prediction] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            predictions[row["case_id"]] = prediction_from_row(
                row["case_id"], row["deletion_status"], row["steps_json"]
            )
    return predictions


# --------------------------------------------------------------------------------------
# Alignment
# --------------------------------------------------------------------------------------


def _step_key(step: Mapping[str, object]) -> tuple:
    """The six-field identity used **only** for exact-step precision/recall and sequences.

    ``step_no`` is deliberately excluded: numbering is validated separately by the runner's
    schema gate, so a correct plan is not penalised for numbering alone.
    """

    return tuple(step.get(name) for name in STEP_KEY_FIELDS)


def _align_key(step: Mapping[str, object]) -> tuple:
    """The grouping key used **only** by the field/evidence metric.

    ``(phase, operation)`` is disjoint from :data:`ALIGN_FIELDS`, so this alignment never
    conditions on the values being scored.
    """

    return tuple(step.get(name) for name in ALIGNMENT_KEY)


def _lcs_pairs(left: Sequence, right: Sequence) -> list[tuple[int, int]]:
    """Longest-common-subsequence index pairs, used for order-sensitive alignment."""

    n, m = len(left), len(right)
    table = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            if left[i] == right[j]:
                table[i][j] = table[i + 1][j + 1] + 1
            else:
                table[i][j] = max(table[i + 1][j], table[i][j + 1])
    pairs: list[tuple[int, int]] = []
    i = j = 0
    while i < n and j < m:
        if left[i] == right[j]:
            pairs.append((i, j))
            i += 1
            j += 1
        elif table[i + 1][j] >= table[i][j + 1]:
            i += 1
        else:
            j += 1
    return pairs


def _pair_score(expected_step: Mapping[str, object], predicted_step: Mapping[str, object]) -> int:
    """Number of :data:`ALIGN_FIELDS` that agree for one candidate pair."""

    return sum(
        1 for name in ALIGN_FIELDS if expected_step.get(name) == predicted_step.get(name)
    )


def _one_to_one(
    expected: Sequence[Mapping[str, object]],
    predicted: Sequence[Mapping[str, object]],
) -> list[tuple[int, int]]:
    """Deterministic positional one-to-one alignment within one ``(phase, operation)`` group.

    The two sequences are matched in order, ``min(len(expected), len(predicted))`` pairs deep.
    This is deliberate and predictable:

    * it is a genuine one-to-one assignment, so duplicates and permutations never collapse;
    * it does **not** inspect any scored field, so it cannot condition the field metric on the
      values being measured (the property whose absence made the previous metric circular);
    * it is stable under dictionary/iteration order, so the metric is reproducible.

    The cost is that a group whose members are permuted *and* differ in a scored field will
    score those differences positionally rather than semantically. Step order is itself part of
    the contract (canonical ``(phase, operation, system_id, resource_id)`` order, validated by
    the runner), so positional matching within an operation group is the intended, honest
    reading: a mis-ordered group surfaces as field errors rather than being silently realigned.
    Whole-array ordering is measured separately by the exact-sequence metric.
    """

    return [(index, index) for index in range(min(len(expected), len(predicted)))]


# --------------------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class CaseScore:
    case_id: str
    status_correct: bool
    expected_status: str
    predicted_status: str
    expected_steps: int
    predicted_steps: int
    matched_steps: int
    exact_sequence: bool
    order_agreement: float
    # Exact-step multiset counts (six-field identity), used for precision/recall/F1.
    step_tp: int = 0
    step_fp: int = 0
    step_fn: int = 0
    # Field/evidence counts over the independent alignment.
    field_matches: Counter = field(default_factory=Counter)
    field_total: int = 0
    field_errors: int = 0
    aligned_pairs: int = 0
    unmatched_expected: int = 0
    unmatched_predicted: int = 0
    evidence_matches: int = 0
    evidence_total: int = 0
    # Split of ``evidence_total`` by provenance: only evidence ids on aligned pairs can
    # match, so the unmatched portion is a structural ceiling, stated in the report.
    evidence_aligned_total: int = 0
    evidence_unmatched_total: int = 0
    # Per-(system_id, operation) census of the exact-step differences.
    fn_by_op: Counter = field(default_factory=Counter)
    fp_by_op: Counter = field(default_factory=Counter)
    fp_by_case_op: Counter = field(default_factory=Counter)
    fn_by_case_op: Counter = field(default_factory=Counter)
    fp_cases: Counter = field(default_factory=Counter)


@dataclass(slots=True)
class EvaluationResult:
    label: str
    cases: int
    status_correct: int
    per_case: list[CaseScore] = field(default_factory=list)
    step_tp: int = 0
    step_fp: int = 0
    step_fn: int = 0
    sequence_exact: int = 0
    field_matches: Counter = field(default_factory=Counter)
    field_total: int = 0
    field_errors: int = 0
    aligned_pairs: int = 0
    unmatched_expected: int = 0
    unmatched_predicted: int = 0
    evidence_matches: int = 0
    evidence_total: int = 0
    evidence_aligned_total: int = 0
    evidence_unmatched_total: int = 0
    missing_cases: list[str] = field(default_factory=list)
    extra_cases: list[str] = field(default_factory=list)
    # Census keyed by (system_id, operation) and by (case_id, system_id, operation).
    fn_by_op: Counter = field(default_factory=Counter)
    fp_by_op: Counter = field(default_factory=Counter)
    fn_by_case_op: Counter = field(default_factory=Counter)
    fp_by_case_op: Counter = field(default_factory=Counter)

    # ---- derived ratios (guarded against zero denominators) ---------------------------

    @property
    def status_accuracy(self) -> float:
        return self.status_correct / self.cases if self.cases else 0.0

    @property
    def step_precision(self) -> float:
        denom = self.step_tp + self.step_fp
        return self.step_tp / denom if denom else 0.0

    @property
    def step_recall(self) -> float:
        denom = self.step_tp + self.step_fn
        return self.step_tp / denom if denom else 0.0

    @property
    def step_f1(self) -> float:
        precision, recall = self.step_precision, self.step_recall
        return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    @property
    def sequence_accuracy(self) -> float:
        return self.sequence_exact / self.cases if self.cases else 0.0

    @property
    def field_accuracy(self) -> float:
        denom = self.aligned_pairs + self.unmatched_expected + self.unmatched_predicted
        return self.field_matches["__total__"] / (denom * len(ALIGN_FIELDS)) if denom else 0.0

    @property
    def evidence_accuracy(self) -> float:
        return self.evidence_matches / self.evidence_total if self.evidence_total else 0.0

    def as_markdown_rows(self) -> list[str]:
        def pct(value: float) -> str:
            return f"{value * 100:.1f}%"

        return [
            f"| Case-status accuracy | {self.status_correct}/{self.cases} | {pct(self.status_accuracy)} |",
            f"| Exact-step precision (micro) | {self.step_tp}/{self.step_tp + self.step_fp} | {pct(self.step_precision)} |",
            f"| Exact-step recall (micro) | {self.step_tp}/{self.step_tp + self.step_fn} | {pct(self.step_recall)} |",
            f"| Exact-step F1 (micro) | - | {pct(self.step_f1)} |",
            f"| Exact-sequence match | {self.sequence_exact}/{self.cases} | {pct(self.sequence_accuracy)} |",
            f"| Field accuracy (independent alignment) | {self.field_matches['__total__']}/{self.field_total} | {pct(self.field_accuracy)} |",
            f"| Evidence agreement (independent alignment) | {self.evidence_matches}/{self.evidence_total} | {pct(self.evidence_accuracy)} |",
        ]


def score_case(case_id: str, expected_status: str, expected_steps: Sequence[dict], prediction: Prediction) -> CaseScore:
    """Score one case: status, exact-step multiset, field alignment, evidence and order."""

    predicted_steps = prediction.steps
    status_correct = prediction.deletion_status == expected_status

    expected_keys = [_step_key(step) for step in expected_steps]
    predicted_keys = [_step_key(step) for step in predicted_steps]

    # ---- exact-step multiset (six-field identity): precision / recall / F1 ------------
    expected_counter = Counter(expected_keys)
    predicted_counter = Counter(predicted_keys)
    matched = sum((expected_counter & predicted_counter).values())
    step_tp = matched
    step_fp = sum(predicted_counter.values()) - matched
    step_fn = sum(expected_counter.values()) - matched

    # Per-(system, operation) census, derived from the same exact-step definition.
    fn_by_op: Counter = Counter()
    for key, count in (expected_counter - predicted_counter).items():
        fn_by_op[(key[2], key[1])] += count  # (system_id, operation)
    fp_by_op: Counter = Counter()
    for key, count in (predicted_counter - expected_counter).items():
        fp_by_op[(key[2], key[1])] += count
    fp_by_case_op: Counter = Counter()
    for key in predicted_keys:
        if key not in expected_counter:
            fp_by_case_op[(case_id, key[2], key[1])] += 1
    fn_by_case_op: Counter = Counter()
    for key in expected_keys:
        if key not in predicted_counter:
            fn_by_case_op[(case_id, key[2], key[1])] += 1

    # ---- order-sensitive view (LCS over the same six-field identity) -----------------
    pairs = _lcs_pairs(expected_keys, predicted_keys)
    denom = max(len(expected_keys), len(predicted_keys), 1)
    order_agreement = len(pairs) / denom
    exact_sequence = list(expected_keys) == list(predicted_keys)

    # ---- independent field alignment: group by (phase, operation), then match 1:1 ----
    expected_groups: dict[tuple, list[int]] = {}
    for index, step in enumerate(expected_steps):
        expected_groups.setdefault(_align_key(step), []).append(index)
    predicted_groups: dict[tuple, list[int]] = {}
    for index, step in enumerate(predicted_steps):
        predicted_groups.setdefault(_align_key(step), []).append(index)

    field_matches: Counter = Counter()
    field_total = 0
    field_errors = 0
    evidence_matches = 0
    evidence_total = 0
    evidence_aligned_total = 0
    evidence_unmatched_total = 0
    aligned_pairs = 0
    unmatched_expected = 0
    unmatched_predicted = 0

    for group in sorted(
        set(expected_groups) | set(predicted_groups),
        key=lambda item: tuple("" if part is None else str(part) for part in item),
    ):
        expected_indexes = expected_groups.get(group, [])
        predicted_indexes = predicted_groups.get(group, [])
        assignment = _one_to_one(
            [expected_steps[i] for i in expected_indexes],
            [predicted_steps[j] for j in predicted_indexes],
        )
        matched_expected = {expected_indexes[i] for i, _ in assignment}
        matched_predicted = {predicted_indexes[j] for _, j in assignment}

        for local_expected, local_predicted in assignment:
            expected_step = expected_steps[expected_indexes[local_expected]]
            predicted_step = predicted_steps[predicted_indexes[local_predicted]]
            aligned_pairs += 1
            for name in ALIGN_FIELDS:
                field_total += 1
                if expected_step.get(name) == predicted_step.get(name):
                    field_matches[name] += 1
                    field_matches["__total__"] += 1
                else:
                    field_errors += 1
            # Evidence agreement is a field-level comparison: a wrong or absent id is an
            # error, never a silent removal of the pair from the denominator.
            if expected_step.get("evidence_id", ""):
                evidence_total += 1
                evidence_aligned_total += 1
                if predicted_step.get("evidence_id", "") == expected_step.get("evidence_id"):
                    evidence_matches += 1

        for index in expected_indexes:
            if index not in matched_expected:
                unmatched_expected += 1
                # An unpaired label step contributes all of its scored fields as errors.
                field_total += len(ALIGN_FIELDS)
                field_errors += len(ALIGN_FIELDS)
                if expected_steps[index].get("evidence_id", ""):
                    evidence_total += 1
                    evidence_unmatched_total += 1
        for index in predicted_indexes:
            if index not in matched_predicted:
                unmatched_predicted += 1
                field_total += len(ALIGN_FIELDS)
                field_errors += len(ALIGN_FIELDS)

    return CaseScore(
        case_id=case_id,
        status_correct=status_correct,
        expected_status=expected_status,
        predicted_status=prediction.deletion_status,
        expected_steps=len(expected_steps),
        predicted_steps=len(predicted_steps),
        matched_steps=matched,
        exact_sequence=exact_sequence,
        order_agreement=order_agreement,
        step_tp=step_tp,
        step_fp=step_fp,
        step_fn=step_fn,
        field_matches=field_matches,
        field_total=field_total,
        field_errors=field_errors,
        aligned_pairs=aligned_pairs,
        unmatched_expected=unmatched_expected,
        unmatched_predicted=unmatched_predicted,
        evidence_matches=evidence_matches,
        evidence_total=evidence_total,
        evidence_aligned_total=evidence_aligned_total,
        evidence_unmatched_total=evidence_unmatched_total,
        fn_by_op=fn_by_op,
        fp_by_op=fp_by_op,
        fp_by_case_op=fp_by_case_op,
        fn_by_case_op=fn_by_case_op,
        fp_cases=Counter({case_id: step_fp}) if step_fp else Counter(),
    )


def score_predictions(
    label: str,
    predictions: Mapping[str, Prediction],
    labels: Mapping[str, tuple[str, list[dict]]],
) -> EvaluationResult:
    """Score a set of predictions against the given labels."""

    result = EvaluationResult(label=label, cases=len(labels), status_correct=0)
    for case_id, (expected_status, expected_steps) in sorted(labels.items()):
        prediction = predictions.get(case_id)
        if prediction is None:
            result.missing_cases.append(case_id)
            prediction = Prediction(case_id=case_id, deletion_status="", steps=[])
        score = score_case(case_id, expected_status, expected_steps, prediction)
        result.per_case.append(score)
        if score.status_correct:
            result.status_correct += 1
        result.step_tp += score.step_tp
        result.step_fp += score.step_fp
        result.step_fn += score.step_fn
        result.field_matches.update(score.field_matches)
        result.field_total += score.field_total
        result.field_errors += score.field_errors
        result.aligned_pairs += score.aligned_pairs
        result.unmatched_expected += score.unmatched_expected
        result.unmatched_predicted += score.unmatched_predicted
        result.evidence_matches += score.evidence_matches
        result.evidence_total += score.evidence_total
        result.evidence_aligned_total += score.evidence_aligned_total
        result.evidence_unmatched_total += score.evidence_unmatched_total
        result.fn_by_op.update(score.fn_by_op)
        result.fp_by_op.update(score.fp_by_op)
        result.fn_by_case_op.update(score.fn_by_case_op)
        result.fp_by_case_op.update(score.fp_by_case_op)
        if score.exact_sequence:
            result.sequence_exact += 1
    for case_id in predictions:
        if case_id not in labels:
            result.extra_cases.append(case_id)
    return result


# --------------------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------------------


def resolve_dataset_dir(dataset: str | Path | None = None) -> Path:
    """Resolve the participant dataset directory portably.

    Precedence: an explicit argument, then ``GHOSTWATCH_DATASET``, then ``<repo>/dataset``.
    The path is validated up front so a missing or incomplete dataset fails with a clear
    message instead of a traceback deep inside the ingest layer.
    """

    candidate = dataset if dataset is not None else os.environ.get("GHOSTWATCH_DATASET") or DATASET_DIR
    path = Path(candidate).expanduser()
    if not path.is_dir():
        raise FileNotFoundError(
            f"dataset directory not found: {path} "
            "(pass --dataset PATH or set GHOSTWATCH_DATASET)"
        )
    missing = [
        name
        for name in (
            "deletion_requests.csv",
            "sample_deletion_requests.csv",
            "sample_output.csv",
            "user_identities.csv",
        )
        if not (path / name).is_file()
    ]
    if missing:
        raise FileNotFoundError(f"dataset directory {path} is missing: {', '.join(missing)}")
    return path


def run_sample_evaluation(
    predict: Callable[[dict], Prediction],
    *,
    labels_path: Path | None = None,
    requests_path: Path | None = None,
    dataset_dir: str | Path | None = None,
) -> EvaluationResult:
    """Evaluate ``predict`` on the public sample requests.

    ``predict`` receives one raw sample request row (a dict of the participant request
    columns) and returns a :class:`Prediction`. Each prediction is computed *before* the
    label file is opened, so a label can never influence a prediction.
    """

    import csv

    base = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
    request_file = requests_path or (base / "sample_deletion_requests.csv")
    with request_file.open("r", encoding="utf-8", newline="") as stream:
        requests = list(csv.DictReader(stream))

    predictions: dict[str, Prediction] = {}
    for row in requests:
        predictions[row["case_id"]] = predict(row)

    # Default the labels to the *supplied* dataset, so an external dataset is honoured
    # fully (a caller cannot accidentally mix an external dataset with repository labels).
    resolved_labels = labels_path or (base / "sample_output.csv")
    labels = load_labels(resolved_labels)  # opened only now
    return score_predictions("public sample (32)", predictions, labels)


def prediction_from_audit(case_id: str, result) -> Prediction:
    """Adapter from the core ``AuditResult`` to a :class:`Prediction`."""

    return Prediction(case_id=case_id, deletion_status=result.deletion_status, steps=json.loads(result.steps_json))


def evaluate_dataset(
    dataset_dir: str | Path | None = None,
    *,
    labels_path: Path | None = None,
) -> EvaluationResult:
    """Run the real core over the public sample requests and score the result.

    This is the offline driver used by ``code/evaluation/main.py`` and the tests. It
    imports the audit core only here, keeps the prediction step label-free, and opens the
    labels afterwards. ``dataset_dir`` may point anywhere (e.g. a separately extracted
    submission layout) and defaults to :func:`resolve_dataset_dir`.
    """

    import sys

    code_dir = REPO_ROOT / "code"
    if str(code_dir) not in sys.path:
        sys.path.insert(0, str(code_dir))

    from ghostwatch.ingest import load_dataset, parse_timestamp  # local import
    from ghostwatch.planner import ParticipantContext, audit

    resolved = resolve_dataset_dir(dataset_dir)
    labels_path = labels_path or (resolved / "sample_output.csv")
    dataset = load_dataset(resolved, include_samples=True)
    context = ParticipantContext(dataset)

    def predict(row: dict) -> Prediction:
        request = dataset.request(row["case_id"]) if row["case_id"] in dataset.case_ids else None
        if request is None:
            # Sample request not part of the evaluation set: build a lightweight view.
            from ghostwatch.ingest import DeletionRequest

            request = DeletionRequest(
                case_id=row["case_id"],
                email=row["email"],
                requested_at=parse_timestamp(row["requested_at"]),
                reported_status=row["reported_status"],
                reported_at=parse_timestamp(row["reported_at"]),
                audit_at=parse_timestamp(row["audit_at"]),
                request_text=row["request_text"],
            )
        result = audit(request, context)
        return prediction_from_audit(row["case_id"], result)

    return run_sample_evaluation(
        predict,
        labels_path=labels_path,
        requests_path=resolved / "sample_deletion_requests.csv",
        dataset_dir=resolved,
    )


def render_census(result: EvaluationResult) -> str:
    """Render the per-operation / per-system / per-case exact-step census.

    The numbers come from the evaluator itself (the same exact-step definition used by the
    precision/recall metrics), so the report can never drift from the harness.
    """

    lines = ["### Exact-step difference census (micro, 6-field identity)", ""]
    lines.append(
        "False negatives are label steps with no identical predicted step; false positives are "
        "predicted steps with no identical label step. Both are counted as multisets, so a "
        "step that exists with a different `evidence_id` is simultaneously one FN and one FP."
    )
    lines.append("")
    lines.append(f"- Matched steps (TP): {result.step_tp}")
    lines.append(f"- Missing label steps (FN): {result.step_fn}")
    lines.append(f"- Extra predicted steps (FP): {result.step_fp}")
    lines.append(
        f"- Net difference (predicted - label): {result.step_tp + result.step_fp - (result.step_tp + result.step_fn)}"
    )
    lines.append("")
    lines.append("| Operation | Missing (FN) | Extra (FP) |")
    lines.append("| --- | --- | --- |")
    for operation in sorted(
        {operation for _system, operation in result.fn_by_op}
        | {operation for _system, operation in result.fp_by_op}
    ):
        fn = sum(count for (_system, op), count in result.fn_by_op.items() if op == operation)
        fp = sum(count for (_system, op), count in result.fp_by_op.items() if op == operation)
        lines.append(f"| `{operation}` | {fn} | {fp} |")
    lines.append(f"| **Total** | **{result.step_fn}** | **{result.step_fp}** |")
    lines.append("")
    lines.append("| System | Operation | Missing (FN) | Extra (FP) |")
    lines.append("| --- | --- | --- | --- |")
    for (system, operation), count in sorted(result.fn_by_op.items()):
        extra = result.fp_by_op.get((system, operation), 0)
        lines.append(f"| `{system}` | `{operation}` | {count} | {extra} |")
    for (system, operation), count in sorted(result.fp_by_op.items()):
        if (system, operation) not in result.fn_by_op:
            lines.append(f"| `{system}` | `{operation}` | 0 | {count} |")
    lines.append("")
    return "\n".join(lines)


def format_report(result: EvaluationResult) -> str:
    """Render the evaluation result as a Markdown section."""

    lines = [f"### {result.label}", ""]
    lines.append("| Metric | Count | Rate |")
    lines.append("| --- | --- | --- |")
    lines.extend(result.as_markdown_rows())
    lines.append("")
    lines.append(
        f"Field-alignment counts: aligned pairs {result.aligned_pairs}, unmatched label steps "
        f"{result.unmatched_expected}, unmatched predicted steps {result.unmatched_predicted}, "
        f"field errors {result.field_errors}."
    )
    lines.append("")
    if result.missing_cases:
        lines.append(f"- Missing predictions: {', '.join(result.missing_cases)}")
    if result.extra_cases:
        lines.append(f"- Extra predictions: {', '.join(result.extra_cases)}")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# CLI: produce a full metrics report (sample + authored cases)
# --------------------------------------------------------------------------------------


def _import_custom_cases():
    """Import :mod:`evaluation.custom_cases` in package *or* script mode.

    ``python code/evaluation/main.py`` runs this module as ``__main__`` with no parent
    package, so a relative import fails with ``ImportError: attempted relative import with
    no known parent package`` — the exact defect the reviewers found in the first
    documented reproduce command. This adapter imports the sibling module by plain name in
    script mode (the code directory is already on ``sys.path`` via the sys.path fix below)
    and relatively in package mode, so both documented entry points work.
    """

    try:
        from . import custom_cases  # package mode: python -m evaluation.main
    except ImportError:  # script mode: python code/evaluation/main.py
        import custom_cases  # type: ignore[no-redef]
    return custom_cases


def build_full_report(dataset_dir: str | Path | None = None) -> str:
    """Run the public-sample and authored-case evaluations and render one Markdown report."""

    custom_cases = _import_custom_cases()

    resolved = resolve_dataset_dir(dataset_dir)
    sample = evaluate_dataset(resolved)
    authored = custom_cases.run_all()

    lines = ["# Ghost Data Still Exists - evaluation metrics", ""]
    lines.append(
        "Measured with the deterministic audit core over the **public** sample requests and "
        "the authored fixtures. Sample labels are read only inside this harness, after "
        "predictions exist."
    )
    lines.append("")
    lines.append(f"- Dataset: `{resolved}`")
    lines.append("")
    lines.append("## 1. Public sample requests (32)")
    lines.append("")
    lines.append(format_report(sample))
    lines.append("## 2. Exact-step difference census")
    lines.append("")
    lines.append(render_census(sample))
    lines.append("## 3. Authored evaluation cases")
    lines.append("")
    lines.append(custom_cases.format_report(authored))
    return "\n".join(lines)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - evaluation harness")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="participant dataset directory (default: $GHOSTWATCH_DATASET or <repo>/dataset)",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable metrics instead of Markdown")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    try:
        resolved = resolve_dataset_dir(args.dataset)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.json:
        result = evaluate_dataset(resolved)
        print(
            json.dumps(
                {
                    "dataset": str(resolved),
                    "cases": result.cases,
                    "status_correct": result.status_correct,
                    "step_tp": result.step_tp,
                    "step_fp": result.step_fp,
                    "step_fn": result.step_fn,
                    "sequence_exact": result.sequence_exact,
                    "field_matches": result.field_matches["__total__"],
                    "field_total": result.field_total,
                    "field_errors": result.field_errors,
                    "aligned_pairs": result.aligned_pairs,
                    "unmatched_expected": result.unmatched_expected,
                    "unmatched_predicted": result.unmatched_predicted,
                    "evidence_matches": result.evidence_matches,
                    "evidence_total": result.evidence_total,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    print(build_full_report(resolved))
    return 0


if __name__ == "__main__":  # pragma: no cover - manual run
    raise SystemExit(main())
