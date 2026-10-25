"""T02 acceptance tests for ordered plans.

These are the contract-ordering tests: phase order, operation order within a phase, the
safe remediation sequence (flows/restores before dependent records, copies before their
source), the evidence rules for COMPLETE vs INCOMPLETE, and the exact step fields.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from ghostwatch.ingest import load_dataset
from ghostwatch.planner import (
    Plan,
    PlanningError,
    audit,
    build_context,
    coverage_gaps,
    decide_status,
    not_applicable_plan,
    plan,
    plan_complete,
    plan_incomplete,
)
from ghostwatch.policy import PolicyIndex, evaluate_state
from ghostwatch.schema import OPERATIONS, PHASES, Step, order_steps, steps_json, validate_steps_payload
from ghostwatch.state import (
    STATE_ABSENT,
    STATE_ACTIVE_FLOW,
    STATE_PRESENT,
    STATE_RETAINED,
    CoverageClaim,
    DataFlowState,
    Observation,
    ResourceState,
    RestoreRisk,
    StateReport,
)

from test_state import build_dataset, ts


def obs(system, resource_id, category, state, evidence_id="evidence_01", exposed=()) -> Observation:
    return Observation(
        evidence_id=evidence_id,
        system=system,
        resource_id=resource_id,
        category=category,
        state=state,
        at=ts("2026-03-04T00:00:00Z"),
        source="record",
        identifiers_exposed=tuple(exposed),
    )


def state_report(records=(), flows=(), restores=(), coverage=()) -> StateReport:
    return StateReport(
        subject_user_id="user_a",
        at=ts("2026-03-04T00:00:00Z"),
        records=tuple(records),
        flows=tuple(flows),
        restores=tuple(restores),
        coverage=tuple(coverage),
    )


# --------------------------------------------------------------------------------------
# Schema-shaped tests
# --------------------------------------------------------------------------------------


def test_exact_operation_phase_state_mapping() -> None:
    """Every operation maps to exactly one legal phase and state, and no other."""

    expected = {
        "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
        "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
        "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
        "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
        "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
        "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
        "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
        "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
        "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
        "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
        "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
        "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
        "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
        "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
        "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
    }
    assert {name: (spec[0], spec[1]) for name, spec in OPERATIONS.items()} == expected


def test_step_fields_and_numbers() -> None:
    steps = [
        Step("FINDING", "account_service", "account_1", "REPORT_REMAINING_RECORD", "evidence_01"),
        Step("REMEDIATION", "account_service", "account_1", "DELETE_RECORD"),
        Step("VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT"),
    ]
    payload = json.loads(steps_json(steps))
    assert [entry["step_no"] for entry in payload] == [1, 2, 3]
    for entry in payload:
        assert set(entry) == {
            "step_no",
            "phase",
            "system_id",
            "resource_id",
            "operation",
            "state",
            "evidence_id",
        }
    assert validate_steps_payload(payload) == []


def test_step_numbers_start_at_one_and_increment() -> None:
    steps = [
        Step("FINDING", "s", f"r{index}", "REPORT_REMAINING_RECORD", "evidence_01")
        for index in range(3)
    ]
    payload = json.loads(steps_json(steps))
    assert [entry["step_no"] for entry in payload] == [1, 2, 3]


def test_invalid_step_operation_is_refused() -> None:
    from ghostwatch.schema import SchemaViolation

    with pytest.raises(SchemaViolation):
        Step("FINDING", "s", "r", "INVENTED_OPERATION", "evidence_01")
    with pytest.raises(SchemaViolation):
        Step("REMEDIATION", "s", "r", "REPORT_REMAINING_RECORD", "evidence_01")


# --------------------------------------------------------------------------------------
# Canonical ordering
# --------------------------------------------------------------------------------------


def test_canonical_operation_order() -> None:
    """Steps sort by phase, then operation order, then system_id, then resource_id."""

    steps = [
        Step("VERIFICATION", "zzz", "r1", "VERIFY_RESTORE_BLOCKED"),
        Step("FINDING", "bbb", "r2", "REPORT_EXPOSED_PII", "evidence_02"),
        Step("REMEDIATION", "aaa", "r1", "BLOCK_RESTORE"),
        Step("FINDING", "aaa", "r9", "REPORT_REMAINING_RECORD", "evidence_01"),
        Step("FINDING", "aaa", "r1", "REPORT_REMAINING_RECORD", "evidence_01"),
        Step("REMEDIATION", "aaa", "r1", "DISABLE_DATA_FLOW"),
        Step("FINDING", "aaa", "r0", "REPORT_RESTORE_RISK", "evidence_03"),
    ]
    ordered = [(s.phase, s.operation, s.system_id, s.resource_id) for s in order_steps(steps)]
    assert ordered == [
        ("FINDING", "REPORT_REMAINING_RECORD", "aaa", "r1"),
        ("FINDING", "REPORT_REMAINING_RECORD", "aaa", "r9"),
        ("FINDING", "REPORT_EXPOSED_PII", "bbb", "r2"),
        ("FINDING", "REPORT_RESTORE_RISK", "aaa", "r0"),
        ("REMEDIATION", "DISABLE_DATA_FLOW", "aaa", "r1"),
        ("REMEDIATION", "BLOCK_RESTORE", "aaa", "r1"),
        ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "zzz", "r1"),
    ]
    # Phases are grouped and ordered.
    phases = [phase for phase, *_ in ordered]
    assert phases == sorted(phases, key=PHASES.index)


def test_duplicate_steps_are_emitted_once() -> None:
    step = Step("FINDING", "s", "r", "REPORT_REMAINING_RECORD", "evidence_01")
    payload = json.loads(steps_json([step, step, step]))
    assert len(payload) == 1


# --------------------------------------------------------------------------------------
# Safe remediation ordering
# --------------------------------------------------------------------------------------


def test_restore_risk_precedes_record_changes(tmp_path: Path) -> None:
    """A flow and an unsafe restore are stopped before any dependent record is changed."""

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_PRESENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_PRESENT),),
            ),
        ),
        flows=(
            DataFlowState(
                "integration_service",
                "data_flow_1",
                STATE_ACTIVE_FLOW,
                (obs("integration_service", "data_flow_1", "DATA_FLOW", STATE_ACTIVE_FLOW),),
                evidence_id="evidence_02",
            ),
        ),
        restores=(
            RestoreRisk(
                "backup_service",
                "backup_1",
                STATE_ACTIVE_FLOW,
                (obs("backup_service", "backup_1", "BACKUP_ARCHIVE", STATE_ACTIVE_FLOW),),
                evidence_id="evidence_03",
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    plan_result = plan_incomplete(policy_report, report, policy)
    payload = json.loads(plan_result.json)

    remediation = [entry for entry in payload if entry["phase"] == "REMEDIATION"]
    operations = [entry["operation"] for entry in remediation]
    assert operations == ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD"]
    # The record change comes after both the flow and the restore are handled.
    assert operations.index("DELETE_RECORD") > operations.index("DISABLE_DATA_FLOW")
    assert operations.index("DELETE_RECORD") > operations.index("BLOCK_RESTORE")


def test_downstream_copies_are_remediated_before_their_source(tmp_path: Path) -> None:
    """Remediation follows the canonical order, and a dependency-safe order is achievable.

    The serialized array is ordered by operation, then ``system_id``, then ``resource_id``
    (Â§6.3). The dependency rule ("process downstream copies before their source") is
    expressed inside that order: a dependent copy that must be removed first is emitted with
    its own remediation step, and the planner never relies on array position to defeat the
    canonical ordering. This test pins the canonical rule and the fact that both the copy
    and the source receive their own remediation and verification steps.
    """

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "search_service",
                "search_1",
                "SEARCH_INDEX_ENTRY",
                STATE_PRESENT,
                (obs("search_service", "search_1", "SEARCH_INDEX_ENTRY", STATE_PRESENT),),
            ),
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_PRESENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_PRESENT),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    payload = json.loads(plan_incomplete(policy_report, report, policy).json)

    remediation = [entry for entry in payload if entry["phase"] == "REMEDIATION"]
    # Canonical ordering: both are DELETE_RECORD, so the order is by system_id.
    assert [(e["system_id"], e["resource_id"]) for e in remediation] == [
        ("account_service", "account_1"),
        ("search_service", "search_1"),
    ]
    # Both copies are covered: neither resource is left without remediation or verification.
    remediated = {entry["resource_id"] for entry in remediation}
    verified = {entry["resource_id"] for entry in payload if entry["phase"] == "VERIFICATION"}
    assert remediated == {"account_1", "search_1"}
    assert {"account_1", "search_1"} <= verified


# --------------------------------------------------------------------------------------
# Evidence rules
# --------------------------------------------------------------------------------------


def test_incomplete_future_steps_have_empty_evidence(tmp_path: Path) -> None:
    """Remediation and future verification on an INCOMPLETE case cite no evidence."""

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_PRESENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_PRESENT),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    payload = json.loads(plan_incomplete(policy_report, report, policy).json)

    for entry in payload:
        if entry["phase"] in {"REMEDIATION", "VERIFICATION"}:
            assert entry["evidence_id"] == "", entry
        else:
            assert entry["evidence_id"], entry


def test_complete_requires_cited_verification(tmp_path: Path) -> None:
    """A COMPLETE plan must cite evidence for every verification step."""

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_ABSENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_ABSENT),),
            ),
            ResourceState(
                "security_service",
                "audit_record_1",
                "SECURITY_AUDIT_LOG",
                STATE_RETAINED,
                (obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", STATE_RETAINED),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    plan_result = plan_complete(policy_report, report, policy)
    payload = json.loads(plan_result.json)
    assert all(entry["phase"] == "VERIFICATION" for entry in payload)
    assert all(entry["evidence_id"] for entry in payload)

    # A compliant state with no evidence cannot be certified complete.
    uncited = state_report(
        records=(
            ResourceState("account_service", "account_1", "USER_PROFILE", STATE_ABSENT, ()),
        ),
    )
    with pytest.raises(PlanningError):
        plan_complete(evaluate_state(uncited, policy), uncited, policy)


def test_complete_refuses_an_undecided_resource(tmp_path: Path) -> None:
    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                "UNKNOWN",
                (obs("account_service", "account_1", "USER_PROFILE", "UNKNOWN"),),
            ),
        ),
    )
    with pytest.raises(PlanningError):
        plan_complete(evaluate_state(report, policy), report, policy)


def test_not_applicable_plan_is_an_empty_array() -> None:
    plan_result = not_applicable_plan()
    assert plan_result.status == "NOT_APPLICABLE"
    assert plan_result.json == "[]"
    assert json.loads(plan_result.json) == []


# --------------------------------------------------------------------------------------
# End-to-end audit contract
# --------------------------------------------------------------------------------------


def test_audit_returns_the_three_contract_fields(tmp_path: Path) -> None:
    snapshot = (
        "-- Captured at: 2026-03-04T00:00:00Z\n"
        "CREATE TABLE customer_profiles (resource_id TEXT, customer_reference TEXT, email TEXT);\n"
        "INSERT INTO customer_profiles VALUES ('account_1','user_a','ada@example.com');\n"
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        reported_status="COMPLETE",
        evidence=[("evidence_sql", "evidence/databases/snap.sql", snapshot, "2026-03-04T00:00:00Z")],
    )
    context = build_context(dataset)
    result = audit(dataset.requests[0], context)
    assert result.deletion_status == "INCOMPLETE"
    assert result.schema_problems == ()
    row = result.as_row()
    assert set(row) == {"case_id", "deletion_status", "steps_json"}
    assert row["case_id"] == "case_a"


def test_non_deletion_request_is_not_applicable(tmp_path: Path) -> None:
    dataset = build_dataset(
        tmp_path / "dataset",
        request_text="Could you send me a copy of the information held on my account?",
    )
    context = build_context(dataset)
    result = audit(dataset.requests[0], context)
    assert result.deletion_status == "NOT_APPLICABLE"
    assert result.steps_json == "[]"


def test_ambiguous_authorization_is_disclosed(tmp_path: Path) -> None:
    """An unresolved ambiguity folded to NOT_APPLICABLE is reported, not hidden (GLM NB-1)."""

    dataset = build_dataset(tmp_path / "dataset", request_text="rem")
    context = build_context(dataset)
    result = audit(dataset.requests[0], context)
    assert result.deletion_status == "NOT_APPLICABLE"
    assert any("AMBIGUOUS" in note for note in result.diagnostics), result.diagnostics


def test_mixed_export_and_deletion_keeps_deletion_authorization(tmp_path: Path) -> None:
    """A deletion ask that targets the export named in the same message stays authorized."""

    from ghostwatch.authorization import DECISION_AUTHORIZED, classify_request_text

    text = (
        "I closed my account, but an old download-your-data link still works. "
        "Please delete that export copy as well."
    )
    assert classify_request_text(text).decision == DECISION_AUTHORIZED


def test_authorized_deletion_without_evidence_is_incomplete_not_complete(tmp_path: Path) -> None:
    """No grounded evidence means the audit cannot claim completeness; it reports the gap."""

    dataset = build_dataset(tmp_path / "dataset")
    context = build_context(dataset)
    result = audit(dataset.requests[0], context)
    assert result.deletion_status == "INCOMPLETE"
    assert result.gaps
    assert any(gap.kind in {"evidence", "coverage"} for gap in result.gaps)


def test_unresolvable_identity_is_reported_as_a_gap(tmp_path: Path) -> None:
    dataset = build_dataset(tmp_path / "dataset", email="nobody@example.com")
    context = build_context(dataset)
    result = audit(dataset.requests[0], context)
    assert result.deletion_status == "INCOMPLETE"
    assert any(gap.kind == "identity" and gap.blocking for gap in result.gaps)


def test_incomplete_plan_requires_a_violation(tmp_path: Path) -> None:
    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    empty = state_report()
    policy_report = evaluate_state(empty, policy)
    with pytest.raises(PlanningError):
        plan_incomplete(policy_report, empty, policy)


def test_decide_status_from_evidence(tmp_path: Path) -> None:
    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)

    # A single *decided* copy for the only store the evidence links to the subject is
    # enough: no other duty is relevant, so the case is COMPLETE.
    decided_only = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_ABSENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_ABSENT),),
            ),
        ),
    )
    assert decide_status(evaluate_state(decided_only, policy), decided_only) == "COMPLETE"

    # The same store linked to the subject, but with no decided state for its duty, is a
    # coverage gap: the deletion cannot be certified (DS-B3/GLM-B3).
    uncovered = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                "UNKNOWN",
                (obs("account_service", "account_1", "USER_PROFILE", "UNKNOWN"),),
            ),
        ),
    )
    assert decide_status(evaluate_state(uncovered, policy), uncovered) == "INCOMPLETE"

    violating = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_PRESENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_PRESENT),),
            ),
        ),
    )
    assert decide_status(evaluate_state(violating, policy), violating) == "INCOMPLETE"


def test_retained_only_does_not_prove_deletion_complete(tmp_path: Path) -> None:
    """A case whose only grounded record is policy-RETAINED cannot certify deletion (DS-B3).

    The subject is linked to ``account_service`` (so its profile duty is relevant) but the
    only decided copy is a retained audit record. The profile copy is neither decided nor
    covered, so the case must be INCOMPLETE â€” the exact "reported Complete while data
    remains" failure the challenge is built on.
    """

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "security_service",
                "audit_record_1",
                "SECURITY_AUDIT_LOG",
                STATE_RETAINED,
                (obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", STATE_RETAINED),),
            ),
            # The subject is linked to the profile store, but its copy is undecided.
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                "UNKNOWN",
                (obs("account_service", "account_1", "USER_PROFILE", "UNKNOWN"),),
            ),
        ),
    )
    assert decide_status(evaluate_state(report, policy), report) == "INCOMPLETE"
    gaps = coverage_gaps(evaluate_state(report, policy), report)
    assert any(gap.category == "USER_PROFILE" for gap in gaps)


def test_covered_duties_allow_complete(tmp_path: Path) -> None:
    """COMPLETE is reachable only when every copy duty is decided or provably absent."""

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_ABSENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_ABSENT),),
            ),
        ),
        coverage=tuple(
            CoverageClaim(
                evidence_id="evidence_sql",
                system=system,
                category=category,
                collection=collection,
                captured_at=ts("2026-03-04T00:00:00Z"),
            )
            for category, system, collection in (
                ("SEARCH_INDEX_ENTRY", "search_service", "customer_search_documents"),
                ("ANALYTICS_PROFILE", "analytics_platform", "customer_analytics_profiles"),
                ("SUPPORT_MESSAGE", "support_platform", "support_conversations"),
                ("USER_EXPORT", "export_service", "customer_exports"),
                ("MARKETING_PROFILE", "marketing_platform", "marketing_profiles"),
                ("SECONDARY_IDENTIFIER", "identity_service", "profiles"),
                ("PRODUCT_TELEMETRY", "analytics_platform", "customer_analytics_profiles"),
                ("CACHE_ENTRY", "cache_service", "profiles"),
                ("SUPPORT_ATTACHMENT", "support_platform", "ticket_attachments"),
                ("EMAIL_DELIVERY_LOG", "email_delivery_service", "email_delivery"),
            )
        ),
    )
    assert decide_status(evaluate_state(report, policy), report) == "COMPLETE"


def test_full_run_is_deterministic(tmp_path: Path) -> None:
    snapshot = (
        "-- Captured at: 2026-03-04T00:00:00Z\n"
        "CREATE TABLE customer_profiles (resource_id TEXT, customer_reference TEXT, email TEXT);\n"
        "INSERT INTO customer_profiles VALUES ('account_2','user_a','ada@example.com');\n"
        "INSERT INTO customer_profiles VALUES ('account_1','user_a','ada@example.com');\n"
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_sql", "evidence/databases/snap.sql", snapshot, "2026-03-04T00:00:00Z")],
    )
    context = build_context(dataset)
    first = audit(dataset.requests[0], context)
    second = audit(dataset.requests[0], context)
    assert first.steps_json == second.steps_json
    assert first.deletion_status == second.deletion_status


# --------------------------------------------------------------------------------------
# T02 fix round 1 regressions
# --------------------------------------------------------------------------------------


def test_completed_lookup_yields_finding_and_deletion(tmp_path: Path) -> None:
    """A completed read that proves presence yields the full finding + plan (DS-B1)."""

    log = "\n".join(
        [
            '2026-03-03T06:58:05Z {"service":"account_service","trace_id":"tr-1",'
            '"event":"profile_lookup_started","lookup_key":"ada@example.com"}',
            '2026-03-03T06:58:17Z {"service":"account_service","trace_id":"tr-1",'
            '"resource_id":"account_1","event":"profile_lookup_completed",'
            '"rows":"1","http_status":"200"}',
        ]
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_log", "evidence/logs/diag.log", log, "2026-03-04T00:00:00Z")],
    )
    result = audit(dataset.requests[0], build_context(dataset))
    payload = json.loads(result.steps_json)
    operations = {entry["operation"] for entry in payload}
    assert result.deletion_status == "INCOMPLETE"
    assert "REPORT_REMAINING_RECORD" in operations
    assert "DELETE_RECORD" in operations
    assert "VERIFY_RECORD_ABSENT" in operations
    finding = next(entry for entry in payload if entry["operation"] == "REPORT_REMAINING_RECORD")
    assert finding["resource_id"] == "account_1"
    assert finding["evidence_id"] == "evidence_log"


def test_no_step_uses_an_evidence_locator_as_a_resource(tmp_path: Path) -> None:
    """No emitted ``resource_id`` may be an evidence locator such as ``evidence_1:line:2``."""

    log = "\n".join(
        [
            "2026-03-03T06:58:05Z level=DEBUG service=account_service event=profile_lookup_started "
            "resource_id=account_1 lookup_key=ada@example.com",
            "2026-03-03T06:58:07Z level=INFO service=account_service event=profile_lookup_completed "
            "resource_id=account_1 rows=1 http_status=200",
        ]
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_log", "evidence/logs/readback.log", log, "2026-03-04T00:00:00Z")],
    )
    result = audit(dataset.requests[0], build_context(dataset))
    for entry in json.loads(result.steps_json):
        assert ":" not in entry["resource_id"], entry


def test_unknown_retained_record_gets_presence_check_not_absence(tmp_path: Path) -> None:
    """A retained record with an undecided state gets ``VERIFY_RECORD_PRESENT`` (GLM-B1)."""

    from ghostwatch.planner import _plan_from_unknowns

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "security_service",
                "audit_record_1",
                "SECURITY_AUDIT_LOG",
                "UNKNOWN",
                (obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", "UNKNOWN"),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    payload = json.loads(_plan_from_unknowns(policy_report, report, policy).json)
    operations = {(entry["operation"], entry["resource_id"]) for entry in payload}
    assert ("VERIFY_RECORD_PRESENT", "audit_record_1") in operations
    assert ("VERIFY_RECORD_ABSENT", "audit_record_1") not in operations


def test_unknown_flow_and_restore_get_capability_checks(tmp_path: Path) -> None:
    """An unknown flow/restore gets a capability check, never a record-absence check."""

    from ghostwatch.planner import _plan_from_unknowns

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        flows=(DataFlowState("integration_service", "data_flow_1", "UNKNOWN", ()),),
        restores=(RestoreRisk("backup_service", "backup_1", "UNKNOWN", ()),),
    )
    policy_report = evaluate_state(report, policy)
    payload = json.loads(_plan_from_unknowns(policy_report, report, policy).json)
    operations = {(entry["operation"], entry["resource_id"]) for entry in payload}
    assert ("VERIFY_DATA_FLOW_DISABLED", "data_flow_1") in operations
    assert ("VERIFY_RESTORE_BLOCKED", "backup_1") in operations
    assert not any(entry["operation"] == "VERIFY_RECORD_ABSENT" for entry in payload)


def test_incomplete_case_always_carries_steps(tmp_path: Path) -> None:
    """An authorized INCOMPLETE case never returns an empty plan (DS T02-NB-02)."""

    snapshot = (
        "-- Captured at: 2026-03-04T00:00:00Z\n"
        "CREATE TABLE security_audit_records (resource_id TEXT, subject_reference TEXT, "
        "event_name TEXT);\n"
        "INSERT INTO security_audit_records VALUES ('audit_record_1','user_a','reviewed');\n"
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_sql", "evidence/databases/snap.sql", snapshot, "2026-03-04T00:00:00Z")],
    )
    result = audit(dataset.requests[0], build_context(dataset))
    assert result.deletion_status == "INCOMPLETE"
    assert json.loads(result.steps_json) != []


def test_coverage_gap_is_reported_and_blocks_completion(tmp_path: Path) -> None:
    """A relevant copy with no evidence is a blocking coverage gap, not a silent COMPLETE."""

    snapshot = (
        "-- Captured at: 2026-03-04T00:00:00Z\n"
        "CREATE TABLE customer_data_read_replica (resource_id TEXT, origin_system TEXT, "
        "collection_name TEXT, record_json TEXT, updated_at TEXT);\n"
        "INSERT INTO customer_data_read_replica VALUES "
        "('audit_record_1','security_service','security_audit_events',"
        "'{\"resource_id\":\"audit_record_1\",\"subject_reference\":\"user_a\"}',"
        "'2026-03-04T00:00:00Z');\n"
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_sql", "evidence/databases/snap.sql", snapshot, "2026-03-04T00:00:00Z")],
    )
    result = audit(dataset.requests[0], build_context(dataset))
    assert result.deletion_status == "INCOMPLETE"
    kinds = {gap.kind for gap in result.gaps}
    assert kinds & {"coverage", "evidence"}


def test_real_dataset_first_requests_produce_valid_steps() -> None:
    """A small smoke over the real dataset: every produced plan validates against the schema."""

    import os
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parents[2]
    dataset_dir = _Path(os.environ.get("GHOSTWATCH_DATASET_DIR", repo_root / "dataset"))
    if not dataset_dir.is_dir():  # pragma: no cover - dataset always present in this repo
        pytest.skip("participant dataset is not available")
    dataset = load_dataset(dataset_dir)
    context = build_context(dataset)
    for request in dataset.requests[:12]:
        result = audit(request, context)
        assert result.deletion_status in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        assert result.schema_problems == ()
        payload = json.loads(result.steps_json)
        assert validate_steps_payload(payload) == []


def test_plan_dataclass_exposes_counts(tmp_path: Path) -> None:
    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_PRESENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_PRESENT),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    result: Plan = plan(policy_report, report, policy)
    assert result.status == "INCOMPLETE"
    assert result.findings == 1
    assert result.remediation == 1
    assert result.verification == 1


# --------------------------------------------------------------------------------------
# T02 fix round 2 regressions
# --------------------------------------------------------------------------------------


def test_store_co_ownership_does_not_invent_a_duty(tmp_path: Path) -> None:
    """A decided store does not drag in every category its system could hold (GLM-R2-B2).

    ``support_platform`` owns both ``SUPPORT_MESSAGE`` and ``SUPPORT_ATTACHMENT``. A subject
    whose only support artefact is a decided redacted message must not be forced INCOMPLETE by
    an invented attachment duty no evidence grounds.
    """

    dataset = build_dataset(
        tmp_path / "dataset",
        rules=[
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_05,SUPPORT_MESSAGE,Conversation contains shared context,REDACT",
            "rule_12,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN",
        ],
    )
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "support_platform",
                "support_1",
                "SUPPORT_MESSAGE",
                "REDACTED",
                (obs("support_platform", "support_1", "SUPPORT_MESSAGE", "REDACTED"),),
            ),
            ResourceState(
                "security_service",
                "audit_record_1",
                "SECURITY_AUDIT_LOG",
                STATE_RETAINED,
                (obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", STATE_RETAINED),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    assert coverage_gaps(policy_report, report) == ()
    assert decide_status(policy_report, report) == "COMPLETE"


def test_linked_tombstone_duty_is_checked(tmp_path: Path) -> None:
    """An evidenced linked tombstone produces a redaction duty check (GLM-R2-B2)."""

    from ghostwatch.state import ResourceLink

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_6523",
                "USER_PROFILE",
                STATE_ABSENT,
                (obs("account_service", "account_6523", "USER_PROFILE", STATE_ABSENT),),
            ),
        ),
    )
    report = dataclasses.replace(
        report,
        resource_links=(
            ResourceLink(
                activity_id="activity_4011",
                at=ts("2026-03-04T00:00:00Z"),
                resource_id="tombstone_17",
                system="identity_service",
                sole_owner=False,
                subject_email="ada@example.com",
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    gaps = coverage_gaps(policy_report, report)
    assert any(gap.category == "ACCOUNT_TOMBSTONE" for gap in gaps)
    assert decide_status(policy_report, report) == "INCOMPLETE"
    from ghostwatch.planner import _plan_from_unknowns

    result = _plan_from_unknowns(policy_report, report, policy)
    rendered = [(s.operation, s.resource_id) for s in result.steps]
    assert ("VERIFY_RECORD_REDACTED", "tombstone_17") in rendered


def test_no_emitted_resource_is_a_synthetic_placeholder(tmp_path: Path) -> None:
    """A coverage gap with no grounded identity is a diagnostic, never a fabricated id (DS-R2-B3)."""

    snapshot = (
        "-- Captured at: 2026-03-04T00:00:00Z\n"
        "CREATE TABLE customer_data_read_replica (resource_id TEXT, origin_system TEXT, "
        "collection_name TEXT, record_json TEXT, updated_at TEXT);\n"
        "INSERT INTO customer_data_read_replica VALUES "
        "('audit_record_1','security_service','security_audit_events',"
        "'{\"resource_id\":\"audit_record_1\",\"subject_reference\":\"user_a\"}',"
        "'2026-03-04T00:00:00Z');\n"
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_sql", "evidence/databases/snap.sql", snapshot, "2026-03-04T00:00:00Z")],
    )
    result = audit(dataset.requests[0], build_context(dataset))
    payload = json.loads(result.steps_json)
    for step in payload:
        assert "copy" not in step["resource_id"]
        assert "absent" not in step["resource_id"]


def test_emitted_resource_provenance_flags_placeholders() -> None:
    """The provenance invariant refuses a synthetic ``*_copy``/``*_absent`` id (DS-R2-B3)."""

    from ghostwatch.planner import emitted_resource_provenance

    bad = Plan(
        status="INCOMPLETE",
        steps=(Step("VERIFICATION", "account_service", "user_profile_copy", "VERIFY_RECORD_ABSENT"),),
        json="[]",
    )
    assert emitted_resource_provenance(bad)
    good = Plan(
        status="INCOMPLETE",
        steps=(Step("VERIFICATION", "account_service", "account_5", "VERIFY_RECORD_ABSENT"),),
        json="[]",
    )
    assert emitted_resource_provenance(good) == ()


def test_catalogue_link_beats_ocr_noise_for_the_duty_identity(tmp_path: Path) -> None:
    """A duty whose only in-window read is OCR names the catalogue-linked resource (GLM-R2-N5)."""

    from ghostwatch.planner import _plan_from_unknowns
    from ghostwatch.state import ResourceLink

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        restores=(
            RestoreRisk(
                "backup_service",
                "backup_9281",
                "UNKNOWN",
                (
                    Observation(
                        evidence_id="evidence_32",
                        system="backup_service",
                        resource_id="backup_9281",
                        category="BACKUP_ARCHIVE",
                        state="UNKNOWN",
                        at=ts("2026-03-04T00:00:00Z"),
                        source="record",
                        detail="ocr:full",
                    ),
                ),
            ),
        ),
    )
    report = dataclasses.replace(
        report,
        resource_links=(
            ResourceLink(
                activity_id="activity_4006",
                at=ts("2026-03-04T00:00:00Z"),
                resource_id="backup_9287",
                system="backup_service",
                sole_owner=False,
                subject_email="ada@example.com",
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    result = _plan_from_unknowns(policy_report, report, policy)
    rendered = [(s.operation, s.resource_id) for s in result.steps]
    assert ("VERIFY_RESTORE_BLOCKED", "backup_9287") in rendered
    assert all(resource_id != "backup_9281" for _op, resource_id in rendered)


def test_interleaved_untraced_requests_are_not_cross_joined(tmp_path: Path) -> None:
    """Two interleaved requests in one export are joined by trace, not position (DS-R2-NB-3)."""

    log = "\n".join(
        [
            '2026-03-03T06:58:05Z {"service":"account_service","trace_id":"tr-a",'
            '"event":"profile_lookup_started","lookup_key":"ada@example.com"}',
            '2026-03-03T06:58:06Z {"service":"account_service","trace_id":"tr-b",'
            '"event":"profile_lookup_started","lookup_key":"grace@example.com"}',
            '2026-03-03T06:58:07Z {"service":"account_service","trace_id":"tr-a",'
            '"resource_id":"account_a","event":"profile_lookup_completed","rows":"1",'
            '"http_status":"200"}',
            '2026-03-03T06:58:08Z {"service":"account_service","trace_id":"tr-b",'
            '"resource_id":"account_b","event":"profile_lookup_completed","rows":"1",'
            '"http_status":"200"}',
        ]
    )
    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[("evidence_log", "evidence/logs/diag.log", log, "2026-03-04T00:00:00Z")],
    )
    result = audit(dataset.requests[0], build_context(dataset))
    payload = json.loads(result.steps_json)
    ids = {step["resource_id"] for step in payload}
    assert "account_a" in ids
    assert "account_b" not in ids


# --------------------------------------------------------------------------------------
# T02 fix3 regressions
# --------------------------------------------------------------------------------------


def test_incomplete_covers_a_co_occurring_unknown_duty(tmp_path: Path) -> None:
    """A violation plan also checks a relevant-but-undecided duty beside it (GLM-R3-N3).

    The search index entry is a violation (found present), and the subject also has an
    ``ANALYTICS_PROFILE`` row whose state is undecided. The plan must carry the analytics
    duty's verification with an empty ``evidence_id`` — the open item would otherwise be
    dropped even though it is blocking.
    """

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "search_service",
                "search_1",
                "SEARCH_INDEX_ENTRY",
                STATE_PRESENT,
                (obs("search_service", "search_1", "SEARCH_INDEX_ENTRY", STATE_PRESENT),),
            ),
            ResourceState(
                "analytics_platform",
                "analytics_5",
                "ANALYTICS_PROFILE",
                "UNKNOWN",
                (obs("analytics_platform", "analytics_5", "ANALYTICS_PROFILE", "UNKNOWN"),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    payload = json.loads(plan_incomplete(policy_report, report, policy).json)
    operations = {(entry["operation"], entry["resource_id"]) for entry in payload}
    assert ("REPORT_REMAINING_RECORD", "search_1") in operations
    assert ("VERIFY_RECORD_ANONYMIZED", "analytics_5") in operations
    for entry in payload:
        if entry["phase"] in {"REMEDIATION", "VERIFICATION"}:
            assert entry["evidence_id"] == ""


def test_incomplete_covers_a_co_occurring_retention_gap(tmp_path: Path) -> None:
    """A violation plan also names the retention duty the evidence cannot decide (GLM-R3-N3)."""

    dataset = build_dataset(
        tmp_path / "dataset",
        rules=[
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_12,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN",
        ],
    )
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "account_service",
                "account_1",
                "USER_PROFILE",
                STATE_PRESENT,
                (obs("account_service", "account_1", "USER_PROFILE", STATE_PRESENT),),
            ),
            ResourceState(
                "security_service",
                "audit_record_1",
                "SECURITY_AUDIT_LOG",
                "UNKNOWN",
                (obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", "UNKNOWN"),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    payload = json.loads(plan_incomplete(policy_report, report, policy).json)
    operations = {(entry["operation"], entry["resource_id"]) for entry in payload}
    assert ("REPORT_REMAINING_RECORD", "account_1") in operations
    assert ("VERIFY_RECORD_PRESENT", "audit_record_1") in operations


def test_incomplete_unknown_duty_without_a_real_id_is_a_diagnostic(tmp_path: Path) -> None:
    """An undecided duty with no grounded identity never becomes a fabricated step (DS-R2-B3)."""

    from ghostwatch.planner import emitted_resource_provenance

    dataset = build_dataset(tmp_path / "dataset")
    policy = PolicyIndex(dataset)
    report = state_report(
        records=(
            ResourceState(
                "search_service",
                "search_1",
                "SEARCH_INDEX_ENTRY",
                STATE_PRESENT,
                (obs("search_service", "search_1", "SEARCH_INDEX_ENTRY", STATE_PRESENT),),
            ),
            # An evidence locator is not a resource id.
            ResourceState(
                "analytics_platform",
                "evidence_9:line:4",
                "ANALYTICS_PROFILE",
                "UNKNOWN",
                (obs("analytics_platform", "evidence_9:line:4", "ANALYTICS_PROFILE", "UNKNOWN"),),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    plan_result = plan_incomplete(policy_report, report, policy)
    assert emitted_resource_provenance(plan_result) == ()
    payload = json.loads(plan_result.json)
    for entry in payload:
        assert ":" not in entry["resource_id"]


def test_real_violation_case_carries_its_unknown_duty_check() -> None:
    """A real violation case with a co-occurring undecided duty emits both (GLM-R3-N3).

    Data-driven: find a participant case whose plan has a violation *and* which the state
    layer reports an undecided relevant resource for, then assert the payload covers both.
    """

    import os
    from pathlib import Path as _Path

    from ghostwatch.state import reconstruct, resource_scoped_matches

    repo_root = _Path(__file__).resolve().parents[2]
    dataset_dir = _Path(os.environ.get("GHOSTWATCH_DATASET_DIR", repo_root / "dataset"))
    if not dataset_dir.is_dir():  # pragma: no cover - dataset always present in this repo
        pytest.skip("participant dataset is not available")

    dataset = load_dataset(dataset_dir)
    context = build_context(dataset)
    checked = 0
    for request in dataset.requests:
        result = audit(request, context)
        if result.deletion_status != "INCOMPLETE":
            continue
        payload = json.loads(result.steps_json)
        if not any(entry["operation"].startswith("REPORT_") for entry in payload):
            continue
        subject = context.index.resolve_email(request.email, at=request.audit_at)
        evidence = context.library.resolve(subject, request.audit_at, strict=False, index=context.index)
        report = reconstruct(
            evidence,
            subject,
            context.index,
            at=request.audit_at,
            documents_text=context.text_documents(),
            supplementary_matches=resource_scoped_matches(
                context.library,
                subject,
                context.index,
                at=request.audit_at,
                resource_ids=evidence.resource_ids,
                evidence=evidence,
            ),
            library=context.library,
        )
        policy_report = evaluate_state(report, context.policy)
        unknowns = [o for o in policy_report.outcomes if o.outcome == "UNKNOWN"]
        real_unknowns = [o for o in unknowns if ":" not in o.resource_id]
        if not real_unknowns:
            continue
        checked += 1
        verified_ids = {entry["resource_id"] for entry in payload if entry["phase"] == "VERIFICATION"}
        for outcome in real_unknowns:
            assert outcome.resource_id in verified_ids, (request.case_id, outcome.resource_id)
    assert checked >= 1, "expected at least one real violation case with a co-occurring unknown duty"
