"""The submission schema: phases, operations, states and the ``steps_json`` encoder.

Everything the grader parses lives here so the vocabulary can only ever be one of the
allowed values. The module is deliberately small and side-effect free:

* :data:`PHASES` fixes the phase order ``FINDING`` -> ``REMEDIATION`` -> ``VERIFICATION``.
* :data:`OPERATIONS` fixes each operation's phase and its legal state, exactly as the
  problem statement's table lists them, plus the canonical rank used to order steps
  inside a phase (operation order in the table, then ``system_id``, then
  ``resource_id``).
* :class:`Step` validates every field and refuses to serialize an operation whose state
  is not the one policy assigns it.

Nothing here reads the dataset, and nothing here can invent a phase, operation or state:
:func:`operation_spec` raises :class:`SchemaViolation` for anything else.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Iterable, Mapping, Sequence

# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------


class StepError(RuntimeError):
    """Base class for step/schema problems."""


class SchemaViolation(StepError):
    """A step names a phase, operation or state outside the allowed vocabulary."""


# --------------------------------------------------------------------------------------
# Canonical vocabulary
# --------------------------------------------------------------------------------------

#: Phase order is significant; the grader preserves array order.
PHASES: tuple[str, ...] = ("FINDING", "REMEDIATION", "VERIFICATION")

PHASE_RANK: Mapping[str, int] = {phase: index for index, phase in enumerate(PHASES)}

#: ``operation -> (phase, state, canonical rank)``. The rank reproduces the row order of
#: the problem statement's operation table, so ordering by rank equals "operation order
#: in the table, then system_id, then resource_id".
OPERATIONS: Mapping[str, tuple[str, str, int]] = {
    # FINDING ----------------------------------------------------------------
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT", 0),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT", 1),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE", 2),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE", 3),
    # REMEDIATION ------------------------------------------------------------
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED", 0),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED", 1),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT", 2),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED", 3),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED", 4),
    # VERIFICATION -----------------------------------------------------------
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT", 0),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT", 1),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED", 2),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED", 3),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED", 4),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED", 5),
}

#: ``operation -> state`` convenience view.
OPERATION_STATE: Mapping[str, str] = {name: spec[1] for name, spec in OPERATIONS.items()}

#: ``operation -> phase`` convenience view.
OPERATION_PHASE: Mapping[str, str] = {name: spec[0] for name, spec in OPERATIONS.items()}

#: Remediation operation that answers a given finding operation. Used by the planner so a
#: finding always has a matching repair; the mapping is structural, not case-specific.
FINDING_REMEDY: Mapping[str, str] = {
    "REPORT_REMAINING_RECORD": "DELETE_RECORD",
    "REPORT_EXPOSED_PII": "REDACT_RECORD",
    "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW",
    "REPORT_RESTORE_RISK": "BLOCK_RESTORE",
}

#: Remediation operation that answers a given finding's exposed state, when the remedy
#: depends on the required treatment rather than the finding kind. ``DELETE``/``RETAIN``
#: fall back to :data:`FINDING_REMEDY`.
TREATMENT_REMEDY: Mapping[str, str] = {
    "DELETE": "DELETE_RECORD",
    "REDACT": "REDACT_RECORD",
    "ANONYMIZE": "ANONYMIZE_RECORD",
    "PRESERVE_TOMBSTONE": "REDACT_RECORD",
}

#: Remediation -> the verification operation that proves it.
REMEDY_VERIFICATION: Mapping[str, str] = {
    "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
    "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
    "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
}

#: Treatment -> the verification operation that proves a *retained* record is intact.
RETAIN_VERIFICATION = "VERIFY_RECORD_PRESENT"

STEP_FIELDS: tuple[str, ...] = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)


def operation_spec(operation: str) -> tuple[str, str, int]:
    """Return ``(phase, state, rank)`` for ``operation`` or raise loudly."""

    try:
        return OPERATIONS[operation]
    except KeyError as exc:
        raise SchemaViolation(
            f"unknown operation {operation!r}; allowed operations are {sorted(OPERATIONS)}"
        ) from exc


def is_evidence_free_phase(phase: str) -> bool:
    """Proposed remediation and future verification carry no evidence_id.

    A ``VERIFICATION`` step may cite evidence on a COMPLETE case; the planner sets that
    explicitly. This helper only answers the structural question for the INCOMPLETE case,
    where both remediation and verification describe future work.
    """

    return phase in {"REMEDIATION", "VERIFICATION"}


# --------------------------------------------------------------------------------------
# Step
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Step:
    """One entry of ``steps_json``.

    ``step_no`` is assigned during serialization, so it is not part of the constructor:
    building steps out of order and numbering them at the end keeps the numbering honest
    even when a planner appends phases in several passes.
    """

    phase: str
    system_id: str
    resource_id: str
    operation: str
    evidence_id: str = ""

    def __post_init__(self) -> None:
        phase, state, _rank = operation_spec(self.operation)
        if self.phase != phase:
            raise SchemaViolation(
                f"operation {self.operation!r} belongs to phase {phase!r}, not {self.phase!r}"
            )
        if not self.system_id:
            raise SchemaViolation(f"step for {self.operation!r} has an empty system_id")
        if not self.resource_id:
            raise SchemaViolation(f"step for {self.operation!r} has an empty resource_id")
        if state not in _STATES:
            raise SchemaViolation(f"operation {self.operation!r} declares unknown state {state!r}")

    @property
    def state(self) -> str:
        """The single legal state for this operation."""

        return OPERATION_STATE[self.operation]

    @property
    def rank(self) -> int:
        return OPERATIONS[self.operation][2]

    @property
    def phase_rank(self) -> int:
        return PHASE_RANK[self.phase]

    def sort_key(self) -> tuple[int, int, str, str]:
        """Canonical order: phase, then operation rank, then system_id, then resource_id."""

        return (self.phase_rank, self.rank, self.system_id, self.resource_id)

    def as_dict(self, step_no: int) -> dict[str, object]:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


_STATES = frozenset({spec[1] for spec in OPERATIONS.values()})


def order_steps(steps: Iterable[Step]) -> list[Step]:
    """Return ``steps`` in canonical order, de-duplicated by their full identity.

    Two steps are the same step when every serialized field except ``step_no`` matches.
    De-duplication happens *before* numbering so a planner that sees the same record from
    two evidence files still emits one ranked instruction.
    """

    unique: dict[tuple[str, str, str, str, str], Step] = {}
    for step in steps:
        unique.setdefault(
            (step.phase, step.operation, step.system_id, step.resource_id, step.evidence_id),
            step,
        )
    return sorted(unique.values(), key=Step.sort_key)


def number_steps(steps: Sequence[Step]) -> list[dict[str, object]]:
    """Validate, order and number ``steps`` starting from 1."""

    ordered = order_steps(steps)
    payload: list[dict[str, object]] = []
    for index, step in enumerate(ordered, start=1):
        payload.append(step.as_dict(index))
    return payload


def steps_json(steps: Sequence[Step]) -> str:
    """Serialize ``steps`` as canonical JSON.

    ``separators`` and ``sort_keys`` are fixed so two runs that produce the same steps
    produce byte-identical output, which the determinism test relies on.
    """

    return json.dumps(number_steps(steps), separators=(",", ":"), sort_keys=True)


def validate_steps_payload(payload: object) -> list[str]:
    """Return a list of contract violations for a decoded ``steps_json`` payload.

    An empty list means the payload satisfies §6.3/§6.4: exact fields, consecutive step
    numbers from 1, allowed phase/operation/state triples, and phase grouping order.
    """

    problems: list[str] = []
    if not isinstance(payload, list):
        return [f"steps_json must be a JSON array, found {type(payload).__name__}"]
    seen_phase_rank = -1
    for offset, entry in enumerate(payload, start=1):
        if not isinstance(entry, dict):
            problems.append(f"step {offset}: not a JSON object")
            continue
        missing = [field for field in STEP_FIELDS if field not in entry]
        extra = [field for field in entry if field not in STEP_FIELDS]
        if missing:
            problems.append(f"step {offset}: missing fields {missing}")
        if extra:
            problems.append(f"step {offset}: unexpected fields {extra}")
        if missing:
            continue
        if entry["step_no"] != offset:
            problems.append(
                f"step {offset}: step_no is {entry['step_no']!r}, expected {offset}"
            )
        operation = entry["operation"]
        if operation not in OPERATIONS:
            problems.append(f"step {offset}: unknown operation {operation!r}")
            continue
        phase, state, _rank = OPERATIONS[operation]
        if entry["phase"] != phase:
            problems.append(
                f"step {offset}: operation {operation!r} requires phase {phase!r}"
            )
        if entry["state"] != state:
            problems.append(
                f"step {offset}: operation {operation!r} requires state {state!r}"
            )
        rank = PHASE_RANK.get(entry["phase"], -1)
        if rank < 0:
            problems.append(f"step {offset}: unknown phase {entry['phase']!r}")
        elif rank < seen_phase_rank:
            problems.append(f"step {offset}: phase {entry['phase']!r} is out of order")
        else:
            seen_phase_rank = rank
        for field in ("system_id", "resource_id"):
            if not isinstance(entry[field], str) or not entry[field]:
                problems.append(f"step {offset}: {field} must be a non-empty string")
        if not isinstance(entry["evidence_id"], str):
            problems.append(f"step {offset}: evidence_id must be a string")
    return problems
