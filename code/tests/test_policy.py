"""T02 acceptance tests for applying the supplied deletion policy.

Every case here uses the *supplied* rule vocabulary. The tests assert that policy only ever
maps a reconstructed state onto the action the rule row names, that retention is preserved,
and that a category with no rule is refused rather than guessed.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from conftest import RULE_HEADER, write_csv

from ghostwatch.ingest import DeletionRule, load_dataset
from ghostwatch.policy import (
    OUTCOME_COMPLIANT,
    OUTCOME_RETAINED,
    OUTCOME_UNKNOWN,
    OUTCOME_VIOLATION,
    PolicyError,
    PolicyIndex,
    canonical_system_id,
    evaluate_record,
    evaluate_state,
)
from ghostwatch.state import (
    STATE_ABSENT,
    STATE_ACTIVE_FLOW,
    STATE_ANONYMIZED,
    STATE_BLOCKED,
    STATE_DISABLED,
    STATE_PRESENT,
    STATE_REDACTED,
    STATE_RETAINED,
    STATE_UNKNOWN,
    Observation,
    ResourceState,
    StateReport,
    DataFlowState,
    RestoreRisk,
)

from test_state import build_dataset, state_for, ts


def make_record_state(system: str, resource_id: str, category: str, state: str, exposed=()) -> ResourceState:
    return ResourceState(
        system=system,
        resource_id=resource_id,
        category=category,
        state=state,
        observations=(
            Observation(
                evidence_id="evidence_01",
                system=system,
                resource_id=resource_id,
                category=category,
                state=state,
                at=ts("2026-03-04T00:00:00Z"),
                source="record",
                identifiers_exposed=tuple(exposed),
            ),
        ),
    )


@pytest.fixture
def policy(tmp_path: Path) -> PolicyIndex:
    dataset = load_dataset(
        build_dataset(tmp_path / "dataset").root
    )
    return PolicyIndex(dataset)


def test_policy_index_loads_supplied_categories(policy: PolicyIndex) -> None:
    assert "USER_PROFILE" in policy.categories
    assert "ACCOUNT_TOMBSTONE" in policy.categories
    assert policy.rule_for("USER_PROFILE").required_action == "DELETE"


def test_delete_rule_requires_absence(policy: PolicyIndex) -> None:
    present = make_record_state("account_service", "account_1", "USER_PROFILE", STATE_PRESENT)
    outcome = evaluate_record(present, policy)
    assert outcome.outcome == OUTCOME_VIOLATION
    assert outcome.required_action == "DELETE"
    assert outcome.required_state == STATE_ABSENT

    gone = make_record_state("account_service", "account_1", "USER_PROFILE", STATE_ABSENT)
    assert evaluate_record(gone, policy).outcome == OUTCOME_COMPLIANT


def test_anonymize_rule_requires_unlink(policy: PolicyIndex) -> None:
    identifiable = make_record_state(
        "analytics_platform", "analytics_1", "ANALYTICS_PROFILE", STATE_PRESENT
    )
    outcome = evaluate_record(identifiable, policy)
    assert outcome.outcome == OUTCOME_VIOLATION
    assert outcome.required_action == "ANONYMIZE"

    anonymized = make_record_state(
        "analytics_platform", "analytics_1", "ANALYTICS_PROFILE", STATE_ANONYMIZED
    )
    assert evaluate_record(anonymized, policy).outcome == OUTCOME_COMPLIANT


def test_retention_preserved(policy: PolicyIndex) -> None:
    """A security-audit record within retention is RETAINED, never a violation."""

    retained = make_record_state(
        "security_service", "audit_record_1", "SECURITY_AUDIT_LOG", STATE_RETAINED
    )
    outcome = evaluate_record(retained, policy)
    assert outcome.outcome == OUTCOME_RETAINED
    assert outcome.required_action == "RETAIN"
    assert not outcome.is_violation


def test_tombstone_rule_requires_direct_identifiers_removed(policy: PolicyIndex) -> None:
    clean = make_record_state(
        "identity_service", "tombstone_1", "ACCOUNT_TOMBSTONE", STATE_REDACTED
    )
    clean_outcome = evaluate_record(clean, policy)
    assert clean_outcome.outcome == OUTCOME_COMPLIANT
    assert clean_outcome.required_action == "REDACT"

    dirty = make_record_state(
        "identity_service",
        "tombstone_1",
        "ACCOUNT_TOMBSTONE",
        STATE_PRESENT,
        exposed=("email=ada@example.com",),
    )
    outcome = evaluate_record(dirty, policy)
    assert outcome.outcome == OUTCOME_VIOLATION
    assert outcome.required_action == "REDACT"


def test_tombstone_rule_preserves_the_stable_reference(tmp_path: Path) -> None:
    """``PRESERVE_TOMBSTONE`` retains the row and demands the direct identifiers go."""

    from conftest import RULE_HEADER, write_csv

    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        ["rule_15,ACCOUNT_TOMBSTONE,Stable reference needed,PRESERVE_TOMBSTONE"],
    )
    policy = PolicyIndex(load_dataset(root))

    clean = make_record_state(
        "identity_service", "tombstone_1", "ACCOUNT_TOMBSTONE", STATE_REDACTED
    )
    outcome = evaluate_record(clean, policy)
    assert outcome.outcome == OUTCOME_RETAINED
    assert outcome.required_action == "PRESERVE_TOMBSTONE"

    dirty = make_record_state(
        "identity_service",
        "tombstone_1",
        "ACCOUNT_TOMBSTONE",
        STATE_PRESENT,
        exposed=("email_hash=aa11",),
    )
    dirty_outcome = evaluate_record(dirty, policy)
    assert dirty_outcome.outcome == OUTCOME_VIOLATION
    assert "prohibited direct identifiers" in dirty_outcome.reason


def test_unknown_category_is_not_guessed(policy: PolicyIndex) -> None:
    record = make_record_state("mystery_service", "mystery_1", "MYSTERY", STATE_PRESENT)
    outcome = evaluate_record(record, policy)
    assert outcome.outcome == OUTCOME_UNKNOWN
    assert outcome.rule_id is None

    with pytest.raises(PolicyError):
        evaluate_record(record, policy, unknown_category_is_error=True)


def test_unknown_state_is_not_compliant(policy: PolicyIndex) -> None:
    record = make_record_state("account_service", "account_1", "USER_PROFILE", STATE_UNKNOWN)
    outcome = evaluate_record(record, policy)
    assert outcome.outcome == OUTCOME_UNKNOWN
    assert outcome.required_action == "DELETE"


def test_active_flow_and_restore_risk_are_violations(policy: PolicyIndex) -> None:
    report = StateReport(
        subject_user_id="user_a",
        at=ts("2026-03-04T00:00:00Z"),
        records=(),
        flows=(
            DataFlowState(
                system="integration_service",
                resource_id="data_flow_1",
                state=STATE_ACTIVE_FLOW,
                observations=(),
            ),
        ),
        restores=(
            RestoreRisk(
                system="backup_service",
                resource_id="backup_1",
                state=STATE_ACTIVE_FLOW,
                observations=(),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    violations = {outcome.resource_id for outcome in policy_report.violations()}
    assert violations == {"data_flow_1", "backup_1"}


def test_disabled_flow_and_blocked_restore_are_compliant(policy: PolicyIndex) -> None:
    report = StateReport(
        subject_user_id="user_a",
        at=ts("2026-03-04T00:00:00Z"),
        records=(),
        flows=(
            DataFlowState(
                system="integration_service",
                resource_id="data_flow_1",
                state=STATE_DISABLED,
                observations=(),
            ),
        ),
        restores=(
            RestoreRisk(
                system="backup_service",
                resource_id="backup_1",
                state=STATE_BLOCKED,
                observations=(),
            ),
        ),
    )
    policy_report = evaluate_state(report, policy)
    assert not policy_report.violations()


def test_flow_and_restore_records_are_not_double_counted(tmp_path: Path) -> None:
    """A flow record appears once as a process, not also as a stored record violation."""

    dataset = build_dataset(
        tmp_path / "dataset",
        evidence=[
            (
                "evidence_log",
                "evidence/logs/readback.log",
                "2026-03-04T07:00:00Z level=INFO service=integration_service "
                "event=connector_config_read_completed resource_id=data_flow_1 "
                "enabled=true customer_email=ada@example.com",
                "2026-03-04T00:00:00Z",
            ),
        ],
    )
    report = state_for(dataset)
    policy = PolicyIndex(dataset)
    policy_report = evaluate_state(report, policy)
    flow_outcomes = [o for o in policy_report.outcomes if o.category == "DATA_FLOW"]
    assert len(flow_outcomes) == 1
    assert flow_outcomes[0].outcome == OUTCOME_VIOLATION


def test_canonical_system_id_prefers_evidence_system() -> None:
    assert canonical_system_id("account_service", "USER_PROFILE") == "account_service"
    assert canonical_system_id(None, "ANALYTICS_PROFILE") == "analytics_platform"
    assert canonical_system_id("support_replica", "SUPPORT_MESSAGE") == "support_platform"
    assert canonical_system_id(None, "MYSTERY") == "unknown"


def test_condition_is_evaluated_not_ignored(tmp_path: Path) -> None:
    """A rule's supplied ``condition`` gates its action (DS T02-NB-01).

    ``SUPPORT_ATTACHMENT`` is DELETE only "Attachment belongs only to the deletion subject";
    ``SUPPORT_MESSAGE`` is REDACT when the conversation carries shared context. A record
    whose ground the condition cannot be decided from must not have the action applied.
    """

    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        [
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_05,SUPPORT_MESSAGE,"
            "\"Conversation contains shared customer, agent, or order context that must be retained\","
            "REDACT",
            "rule_06,SUPPORT_ATTACHMENT,Attachment belongs only to the deletion subject,DELETE",
            "rule_99,MYSTERY_CATEGORY,Some condition the dataset never defines,RETAIN",
        ],
    )
    policy = PolicyIndex(load_dataset(root))

    # A support message: the shared-context condition resolves to the REDACT treatment.
    message = make_record_state(
        "support_platform", "support_1", "SUPPORT_MESSAGE", STATE_PRESENT
    )
    message_outcome = evaluate_record(message, policy)
    assert message_outcome.required_action == "REDACT"
    assert message_outcome.outcome == OUTCOME_VIOLATION

    # A support attachment: the sole-owner condition is satisfied only for an attachment the
    # evidence grounds as the subject's own, so the DELETE duty applies there. A bare
    # attachment with no ownership ground falls back to the shared-context REDACT treatment
    # (GLM-R2-N1).
    attachment = make_record_state(
        "support_platform",
        "support_2",
        "SUPPORT_ATTACHMENT",
        STATE_PRESENT,
        exposed=("email=ada@example.com",),
    )
    attachment_outcome = evaluate_record(attachment, policy)
    assert attachment_outcome.required_action == "DELETE"

    ungrounded_attachment = make_record_state(
        "support_platform", "support_3", "SUPPORT_ATTACHMENT", STATE_PRESENT
    )
    ungrounded_outcome = evaluate_record(ungrounded_attachment, policy)
    assert ungrounded_outcome.required_action == "REDACT"

    # A condition the module cannot map to a ground is left UNKNOWN, never unconditionally
    # applied.
    mystery = make_record_state("mystery", "mystery_1", "MYSTERY_CATEGORY", STATE_PRESENT)
    mystery_outcome = evaluate_record(mystery, policy)
    assert mystery_outcome.outcome == OUTCOME_UNKNOWN
    assert mystery_outcome.required_action is None


def test_condition_unknown_is_not_applied_unconditionally(tmp_path: Path) -> None:
    """An unmappable condition yields UNKNOWN rather than the rule's action."""

    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        ["rule_01,USER_PROFILE,An unfamiliar supplied predicate,DELETE"],
    )
    policy = PolicyIndex(load_dataset(root))
    present = make_record_state("account_service", "account_1", "USER_PROFILE", STATE_PRESENT)
    outcome = evaluate_record(present, policy)
    assert outcome.outcome == OUTCOME_UNKNOWN
    assert outcome.required_action is None
    assert "cannot be decided" in outcome.reason


def test_present_flow_row_is_an_active_recreation_path(tmp_path: Path) -> None:
    """A present connector row without an enabled flag is still a live path (GLM NB-6)."""

    from ghostwatch.policy import _evaluate_flow

    outcome = _evaluate_flow(
        DataFlowState(
            system="integration_service",
            resource_id="data_flow_1",
            state=STATE_PRESENT,
            observations=(),
        )
    )
    assert outcome.outcome == OUTCOME_VIOLATION
    assert outcome.required_action == "DISABLE"


def test_duplicate_category_in_rules_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        [
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_02,USER_PROFILE,Always,DELETE",
        ],
    )
    dataset = load_dataset(root)
    with pytest.raises(PolicyError):
        PolicyIndex(dataset)


def test_rule_lookup_is_case_insensitive(policy: PolicyIndex) -> None:
    assert policy.rule_for("user_profile") is not None
    assert policy.resolve_category("user_profile") == "USER_PROFILE"


def test_rule_dataclass_contract_is_used_directly(tmp_path: Path) -> None:
    """The policy index reflects exactly the supplied rows, with no built-in rules."""

    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        ["rule_99,USER_PROFILE,Always,RETAIN"],
    )
    dataset = load_dataset(root)
    policy = PolicyIndex(dataset)
    rule: DeletionRule = policy.rule_for("USER_PROFILE")
    assert rule.required_action == "RETAIN"
    present = make_record_state("account_service", "account_1", "USER_PROFILE", STATE_PRESENT)
    assert evaluate_record(present, policy).outcome == OUTCOME_RETAINED


def _ts(value: str) -> _dt.datetime:  # pragma: no cover - helper kept for readability
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_sole_owner_condition_is_grounded_in_linked_evidence(tmp_path: Path) -> None:
    """The ``sole_owner`` condition is decided by real evidence, not a label default (GLM-R2-N1).

    ``evaluate_record`` receives the resource ids a catalogue/content link grounds as belonging
    to the subject alone. Without that ground, the safer shared-context REDACT treatment applies
    instead of the DELETE duty.
    """

    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        [
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_06,SUPPORT_ATTACHMENT,Attachment belongs only to the deletion subject,DELETE",
            "rule_05,SUPPORT_MESSAGE,Conversation contains shared context,REDACT",
        ],
    )
    policy = PolicyIndex(load_dataset(root))

    attachment = make_record_state(
        "support_platform", "support_2", "SUPPORT_ATTACHMENT", STATE_PRESENT
    )

    # Without a grounded sole-owner link, the shared-context REDACT treatment applies.
    ungrounded = evaluate_record(attachment, policy)
    assert ungrounded.required_action == "REDACT"

    # With the catalogue link grounding sole ownership, the DELETE duty applies.
    grounded = evaluate_record(
        attachment, policy, sole_owner_grounds=frozenset({"support_2"})
    )
    assert grounded.required_action == "DELETE"


def test_sole_owner_condition_unknown_state_is_not_satisfied(tmp_path: Path) -> None:
    """An unknown attachment state never satisfies the sole-owner condition (GLM-R2-N1)."""

    root = tmp_path / "dataset"
    build_dataset(root)
    write_csv(
        root / "deletion_rules.csv",
        RULE_HEADER,
        [
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_06,SUPPORT_ATTACHMENT,Attachment belongs only to the deletion subject,DELETE",
        ],
    )
    policy = PolicyIndex(load_dataset(root))
    attachment = make_record_state(
        "support_platform", "support_2", "SUPPORT_ATTACHMENT", STATE_UNKNOWN
    )
    outcome = evaluate_record(
        attachment, policy, sole_owner_grounds=frozenset({"support_2"})
    )
    assert outcome.required_action == "REDACT"
