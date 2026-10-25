"""T02 acceptance tests for the submission schema module.

The schema module is the single place that knows the allowed phases, operations and states.
These tests pin that vocabulary to the problem statement, prove the validator detects the
mistakes a planner could make (wrong phase, wrong state, bad numbering, stray fields), and
prove serialization is deterministic.
"""

from __future__ import annotations

import json

import pytest

from ghostwatch.schema import (
    FINDING_REMEDY,
    OPERATIONS,
    OPERATION_PHASE,
    OPERATION_STATE,
    PHASES,
    PHASE_RANK,
    REMEDY_VERIFICATION,
    STEP_FIELDS,
    TREATMENT_REMEDY,
    SchemaViolation,
    Step,
    is_evidence_free_phase,
    number_steps,
    operation_spec,
    order_steps,
    steps_json,
    validate_steps_payload,
)


def test_phase_order_is_finding_remediation_verification() -> None:
    assert PHASES == ("FINDING", "REMEDIATION", "VERIFICATION")
    assert PHASE_RANK == {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def test_vocabulary_has_no_invented_entries() -> None:
    """The schema exposes exactly the fifteen documented operations and six states."""

    assert len(OPERATIONS) == 15
    assert set(OPERATION_STATE.values()) == {
        "PRESENT",
        "ACTIVE",
        "DISABLED",
        "BLOCKED",
        "ABSENT",
        "REDACTED",
        "ANONYMIZED",
    }
    assert all(phase in PHASES for phase in OPERATION_PHASE.values())


def test_operation_spec_rejects_unknown_operations() -> None:
    with pytest.raises(SchemaViolation):
        operation_spec("DO_SOMETHING_ELSE")


def test_step_requires_matching_phase_and_state() -> None:
    # Legal step.
    step = Step("FINDING", "account_service", "account_1", "REPORT_REMAINING_RECORD", "evidence_01")
    assert step.state == "PRESENT"
    assert step.as_dict(1)["phase"] == "FINDING"

    # Wrong phase for the operation.
    with pytest.raises(SchemaViolation):
        Step("REMEDIATION", "account_service", "account_1", "REPORT_REMAINING_RECORD", "evidence_01")

    # Empty identifiers are refused.
    with pytest.raises(SchemaViolation):
        Step("FINDING", "", "account_1", "REPORT_REMAINING_RECORD", "evidence_01")
    with pytest.raises(SchemaViolation):
        Step("FINDING", "account_service", "", "REPORT_REMAINING_RECORD", "evidence_01")


def test_step_fields_are_exactly_the_contract_fields() -> None:
    assert STEP_FIELDS == (
        "step_no",
        "phase",
        "system_id",
        "resource_id",
        "operation",
        "state",
        "evidence_id",
    )
    step = Step("VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT", "evidence_01")
    assert set(step.as_dict(7)) == set(STEP_FIELDS)


def test_number_steps_is_consecutive_from_one() -> None:
    steps = [
        Step("FINDING", "s", "r2", "REPORT_REMAINING_RECORD", "evidence_02"),
        Step("FINDING", "s", "r1", "REPORT_REMAINING_RECORD", "evidence_01"),
    ]
    payload = number_steps(steps)
    assert [entry["step_no"] for entry in payload] == [1, 2]
    assert [entry["resource_id"] for entry in payload] == ["r1", "r2"]


def test_order_steps_is_canonical_and_stable() -> None:
    a = Step("FINDING", "b", "r1", "REPORT_REMAINING_RECORD", "evidence_02")
    b = Step("FINDING", "a", "r9", "REPORT_REMAINING_RECORD", "evidence_02")
    c = Step("FINDING", "a", "r1", "REPORT_EXPOSED_PII", "evidence_01")
    # REPORT_REMAINING_RECORD ranks before REPORT_EXPOSED_PII, so both remaining-record
    # steps precede the exposed-PII step; within a rank the sort is by system then resource.
    ordered = [(s.operation, s.system_id, s.resource_id) for s in order_steps([a, b, c])]
    assert ordered == [
        ("REPORT_REMAINING_RECORD", "a", "r9"),
        ("REPORT_REMAINING_RECORD", "b", "r1"),
        ("REPORT_EXPOSED_PII", "a", "r1"),
    ]


def test_steps_json_is_deterministic_json() -> None:
    steps = [
        Step("FINDING", "s", "r", "REPORT_REMAINING_RECORD", "evidence_01"),
        Step("REMEDIATION", "s", "r", "DELETE_RECORD"),
        Step("VERIFICATION", "s", "r", "VERIFY_RECORD_ABSENT"),
    ]
    first = steps_json(steps)
    second = steps_json(list(reversed(steps)))
    assert first == second
    assert json.loads(first) == json.loads(second)
    # Compact separators are used so the output is byte-stable.
    assert ", " not in first


def test_validate_steps_payload_accepts_a_real_plan() -> None:
    payload = json.loads(
        steps_json(
            [
                Step("FINDING", "account_service", "account_1", "REPORT_REMAINING_RECORD", "evidence_01"),
                Step("REMEDIATION", "account_service", "account_1", "DELETE_RECORD"),
                Step("VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT"),
            ]
        )
    )
    assert validate_steps_payload(payload) == []


def test_validate_steps_payload_detects_each_violation() -> None:
    good = {
        "step_no": 1,
        "phase": "FINDING",
        "system_id": "account_service",
        "resource_id": "account_1",
        "operation": "REPORT_REMAINING_RECORD",
        "state": "PRESENT",
        "evidence_id": "evidence_01",
    }

    def mutate(**changes):
        entry = dict(good)
        entry.update(changes)
        return [entry]

    assert validate_steps_payload("not an array")
    assert validate_steps_payload(mutate(step_no=2))
    assert validate_steps_payload(mutate(operation="NOPE"))
    assert validate_steps_payload(mutate(state="ABSENT"))
    assert validate_steps_payload(mutate(phase="REMEDIATION"))
    assert validate_steps_payload(mutate(system_id=""))
    assert validate_steps_payload(mutate(resource_id=""))
    assert validate_steps_payload(mutate(evidence_id=None))
    assert validate_steps_payload([{**good, "extra": "x"}])
    assert validate_steps_payload([{k: v for k, v in good.items() if k != "state"}])


def test_validate_steps_payload_detects_phase_disorder() -> None:
    payload = [
        {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "s",
            "resource_id": "r",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "evidence_01",
        },
        {
            "step_no": 2,
            "phase": "FINDING",
            "system_id": "s",
            "resource_id": "r",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "evidence_01",
        },
    ]
    problems = validate_steps_payload(payload)
    assert any("out of order" in problem for problem in problems)


def test_remedy_maps_are_complete_and_consistent() -> None:
    """Every finding has a remedy and every remediation has a verification operation."""

    for finding, remedy in FINDING_REMEDY.items():
        assert OPERATION_PHASE[finding] == "FINDING"
        assert OPERATION_PHASE[remedy] == "REMEDIATION"
        assert remedy in REMEDY_VERIFICATION
    for treatment, remedy in TREATMENT_REMEDY.items():
        assert OPERATION_PHASE[remedy] == "REMEDIATION"
    assert set(REMEDY_VERIFICATION) == {
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
    }


def test_is_evidence_free_phase() -> None:
    assert is_evidence_free_phase("REMEDIATION")
    assert is_evidence_free_phase("VERIFICATION")
    assert not is_evidence_free_phase("FINDING")
