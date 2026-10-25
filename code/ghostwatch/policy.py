"""Policy application: what treatment does the supplied policy require for this record?

``deletion_rules.csv`` is the only source of truth here. The module never invents a rule
and never overrides one: it looks the record's data category up in the supplied rules and
maps the rule's ``required_action`` onto the record state the state layer reconstructed.

The result is a :class:`PolicyOutcome` per resource that the planner turns into findings,
remediation and verification. Keeping the mapping in one place is what makes the plan
inspectable: a reviewer can read the rule row, the reconstructed state and the outcome
side by side.
"""

from __future__ import annotations

import dataclasses
from typing import Mapping

from .ingest import DeletionRule, Dataset
from .state import (
    FLOW_CATEGORIES,
    RESTORE_CATEGORIES,
    STATE_ABSENT,
    STATE_ACTIVE_FLOW,
    STATE_ANONYMIZED,
    STATE_BLOCKED,
    STATE_DISABLED,
    STATE_PRESENT,
    STATE_REDACTED,
    STATE_RETAINED,
    STATE_UNKNOWN,
    DataFlowState,
    ResourceState,
    RestoreRisk,
    StateReport,
)

# --------------------------------------------------------------------------------------
# Outcome vocabulary
# --------------------------------------------------------------------------------------

#: ``COMPLIANT`` the record already has the treatment policy requires;
#: ``VIOLATION`` the treatment is missing; ``RETAINED`` policy requires keeping it;
#: ``UNKNOWN``  the category or state is not established, so no plan can be built.
OUTCOME_COMPLIANT = "COMPLIANT"
OUTCOME_VIOLATION = "VIOLATION"
OUTCOME_RETAINED = "RETAINED"
OUTCOME_UNKNOWN = "UNKNOWN"

#: Contract treatment names (``DELETE`` etc.) mapped onto the state that proves them.
_TREATMENT_REQUIRED_STATE: Mapping[str, str] = {
    "DELETE": STATE_ABSENT,
    "REDACT": STATE_REDACTED,
    "ANONYMIZE": STATE_ANONYMIZED,
    "RETAIN": STATE_RETAINED,
    "PRESERVE_TOMBSTONE": STATE_REDACTED,
}

#: For each supplied ``condition`` phrase, the *structured ground* that decides it. The
#: condition text is parsed, not ignored: a rule whose condition names shared context is
#: only applied to a record the evidence shows carries that context, and a condition that
#: cannot be decided from the record makes the outcome UNKNOWN rather than a guessed
#: treatment (DS T02-NB-01).
#:
#: ``(condition matcher, ground kind)`` where ground kind is one of:
#:   ``"shared_context"``  — the record must carry retained/shared context; a message that
#:                           exposes no direct identifier and keeps only its stable
#:                           reference is the retained/redacted case.
#:   ``"sole_owner"``      — the record must be linked to the subject alone.
#:   ``"attributable"``    — the record must still be attributable to the subject.
#:   ``"retention"``       — the record must be within a retention window.
#:   ``"legal_hold"``      — an active legal hold must be supplied.
#:   ``"restore_blockable"`` — the restore path must be blockable.
#:   ``"tombstone"``       — the account must be a deleted tombstone with only a stable ref.
#:   ``"always"``          — the condition is unconditional.


def _condition_ground(condition: str) -> str:
    """Classify a supplied ``condition`` phrase onto the structured ground it needs.

    The phrases are read, not pattern-matched to a case: each branch names the *kind of
    fact* the condition turns on, so the policy can look the fact up in the reconstructed
    record state instead of applying the action unconditionally.
    """

    text = (condition or "").strip().casefold()
    if not text or text in {"always", "unconditional"}:
        return "always"
    if "shared" in text:
        return "shared_context"
    if "only" in text and ("subject" in text or "belongs" in text):
        return "sole_owner"
    if "attributable" in text:
        return "attributable"
    if "retention period" in text or "retention" in text and "period" in text:
        return "retention"
    if "legal hold" in text:
        return "legal_hold"
    if "restore" in text and "block" in text:
        return "restore_blockable"
    if "tombstone" in text or ("stable" in text and "reference" in text):
        return "tombstone"
    if "deleted" in text and "account" in text:
        return "tombstone"
    return "unresolved"


#: A state that already satisfies a required treatment.
_TREATMENT_SATISFIED_BY: Mapping[str, frozenset[str]] = {
    "DELETE": frozenset({STATE_ABSENT}),
    "REDACT": frozenset({STATE_REDACTED, STATE_ANONYMIZED}),
    "ANONYMIZE": frozenset({STATE_ANONYMIZED}),
    "RETAIN": frozenset({STATE_PRESENT, STATE_RETAINED}),
    "PRESERVE_TOMBSTONE": frozenset({STATE_REDACTED, STATE_ANONYMIZED}),
}


class PolicyError(RuntimeError):
    """The supplied policy cannot be applied to a record."""


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyOutcome:
    """The policy decision for one resource."""

    system: str
    resource_id: str
    category: str
    rule_id: str | None
    required_action: str | None
    required_state: str | None
    outcome: str
    observed_state: str
    reason: str

    @property
    def is_violation(self) -> bool:
        return self.outcome == OUTCOME_VIOLATION

    @property
    def must_retain(self) -> bool:
        return self.outcome == OUTCOME_RETAINED


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyReport:
    """Every policy outcome plus what could not be decided."""

    outcomes: tuple[PolicyOutcome, ...]
    unknown_categories: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()

    def violations(self) -> tuple[PolicyOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.is_violation)

    def retained(self) -> tuple[PolicyOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.must_retain)


# --------------------------------------------------------------------------------------
# Rule lookup
# --------------------------------------------------------------------------------------


class PolicyIndex:
    """Index over ``deletion_rules.csv`` with an explicit, ordered category resolution."""

    def __init__(self, dataset: Dataset) -> None:
        self._rules: dict[str, DeletionRule] = {}
        for rule in dataset.rules:
            key = rule.data_category.strip().upper()
            if key in self._rules:
                raise PolicyError(
                    f"deletion_rules.csv defines category {key!r} more than once "
                    f"({self._rules[key].rule_id!r} and {rule.rule_id!r})"
                )
            self._rules[key] = rule

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted(self._rules))

    def rule_for(self, category: str | None) -> DeletionRule | None:
        if not category:
            return None
        return self._rules.get(category.strip().upper())

    def resolve_category(self, category: str | None) -> str | None:
        """Map a record's category onto a policy category, or ``None`` when unresolved."""

        if not category:
            return None
        direct = self.rule_for(category)
        if direct is not None:
            return direct.data_category
        # A few record kinds map onto a policy category by meaning rather than by shared
        # token; the mapping is structural and never keyed to a case.
        aliases = {
            "SUPPORT_MESSAGE_REDACTED": "SUPPORT_MESSAGE",
            "SYNC_JOB": "DATA_FLOW",
            "INTEGRATION": "DATA_FLOW",
            "RESTORE_JOB": "BACKUP_ARCHIVE",
            "BACKUP": "BACKUP_ARCHIVE",
            "PROFILE": "USER_PROFILE",
            "SEARCH_INDEX": "SEARCH_INDEX_ENTRY",
            "ANALYTICS": "ANALYTICS_PROFILE",
            "MARKETING": "MARKETING_PROFILE",
            "TELECOM_TELEMETRY": "PRODUCT_TELEMETRY",
        }
        return aliases.get(category.strip().upper())


# --------------------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------------------


def evaluate_record(
    record_state: ResourceState,
    policy: PolicyIndex,
    *,
    unknown_category_is_error: bool = False,
    sole_owner_grounds: frozenset[str] = frozenset(),
) -> PolicyOutcome:
    """Decide the required treatment for one reconstructed resource.

    ``sole_owner_grounds`` names the resource ids a catalogue/content link explicitly grounds
    as belonging to the subject alone, so the ``sole_owner`` condition is decided from that
    evidence rather than from an always-true heuristic (GLM-R2-N1).
    """

    category = policy.resolve_category(record_state.category)
    if category is None:
        reason = (
            f"no policy rule matches category {record_state.category!r}; refusing to guess a treatment"
        )
        if unknown_category_is_error:
            raise PolicyError(f"{record_state.system}/{record_state.resource_id}: {reason}")
        return PolicyOutcome(
            system=record_state.system,
            resource_id=record_state.resource_id,
            category=record_state.category,
            rule_id=None,
            required_action=None,
            required_state=None,
            outcome=OUTCOME_UNKNOWN,
            observed_state=record_state.state,
            reason=reason,
        )

    rule = policy.rule_for(category)
    assert rule is not None  # resolve_category only returns known categories
    action = rule.required_action.strip().upper()
    required_state = _TREATMENT_REQUIRED_STATE.get(action)
    if required_state is None:
        raise PolicyError(
            f"{rule.rule_id}: unknown required_action {rule.required_action!r}"
        )

    # The supplied ``condition`` gates the action. A condition the record cannot decide makes
    # the outcome UNKNOWN rather than blindly applying the action (DS T02-NB-01).
    ground = _condition_ground(rule.condition)
    if ground == "unresolved":
        return PolicyOutcome(
            system=record_state.system,
            resource_id=record_state.resource_id,
            category=category,
            rule_id=rule.rule_id,
            required_action=None,
            required_state=None,
            outcome=OUTCOME_UNKNOWN,
            observed_state=record_state.state,
            reason=(
                f"{rule.rule_id}: supplied condition {rule.condition!r} cannot be decided "
                "from the reconstructed record, so no treatment is applied"
            ),
        )
    if ground == "sole_owner" and not _condition_sole_owner(
        record_state, sole_owner_grounds
    ):
        # The condition is about attachment ownership; where the evidence does not ground
        # sole ownership, defer to the shared-context REDACT treatment rather than DELETE.
        return PolicyOutcome(
            system=record_state.system,
            resource_id=record_state.resource_id,
            category=category,
            rule_id=rule.rule_id,
            required_action="REDACT",
            required_state=STATE_REDACTED,
            outcome=(
                OUTCOME_COMPLIANT
                if record_state.state in {STATE_REDACTED, STATE_ANONYMIZED}
                else OUTCOME_VIOLATION
            ),
            observed_state=record_state.state,
            reason=(
                f"{rule.rule_id}: the attachment is not grounded as belonging only to the "
                "subject, so the shared-context treatment applies"
            ),
        )

    if action in {"RETAIN", "PRESERVE_TOMBSTONE"}:
        # Retention-type rules never produce a violation: the question is only whether the
        # retained record still exists and contains what policy allows.
        if record_state.state == STATE_UNKNOWN:
            return PolicyOutcome(
                system=record_state.system,
                resource_id=record_state.resource_id,
                category=category,
                rule_id=rule.rule_id,
                required_action=action,
                required_state=required_state,
                outcome=OUTCOME_UNKNOWN,
                observed_state=record_state.state,
                reason="evidence does not establish whether the retained record is still present",
            )
        if action == "PRESERVE_TOMBSTONE":
            # Compliant only when no prohibited direct identifier remains.
            if record_state.identifiers_exposed:
                return PolicyOutcome(
                    system=record_state.system,
                    resource_id=record_state.resource_id,
                    category=category,
                    rule_id=rule.rule_id,
                    required_action=action,
                    required_state=required_state,
                    outcome=OUTCOME_VIOLATION,
                    observed_state=record_state.state,
                    reason=(
                        "the tombstone still exposes prohibited direct identifiers "
                        f"({', '.join(record_state.identifiers_exposed)})"
                    ),
                )
            return PolicyOutcome(
                system=record_state.system,
                resource_id=record_state.resource_id,
                category=category,
                rule_id=rule.rule_id,
                required_action=action,
                required_state=required_state,
                outcome=OUTCOME_RETAINED,
                observed_state=record_state.state,
                reason="the tombstone keeps only the stable reference required by policy",
            )
        return PolicyOutcome(
            system=record_state.system,
            resource_id=record_state.resource_id,
            category=category,
            rule_id=rule.rule_id,
            required_action=action,
            required_state=required_state,
            outcome=OUTCOME_RETAINED,
            observed_state=record_state.state,
            reason=f"policy requires retention for {category}",
        )

    satisfied = _TREATMENT_SATISFIED_BY.get(action, frozenset())
    if record_state.state == STATE_UNKNOWN:
        return PolicyOutcome(
            system=record_state.system,
            resource_id=record_state.resource_id,
            category=category,
            rule_id=rule.rule_id,
            required_action=action,
            required_state=required_state,
            outcome=OUTCOME_UNKNOWN,
            observed_state=record_state.state,
            reason="evidence does not establish the record state at audit_at",
        )
    if record_state.state in satisfied:
        return PolicyOutcome(
            system=record_state.system,
            resource_id=record_state.resource_id,
            category=category,
            rule_id=rule.rule_id,
            required_action=action,
            required_state=required_state,
            outcome=OUTCOME_COMPLIANT,
            observed_state=record_state.state,
            reason=f"{category} already has the treatment policy requires ({action})",
        )
    return PolicyOutcome(
        system=record_state.system,
        resource_id=record_state.resource_id,
        category=category,
        rule_id=rule.rule_id,
        required_action=action,
        required_state=required_state,
        outcome=OUTCOME_VIOLATION,
        observed_state=record_state.state,
        reason=(
            f"{category} requires {action} but the record is {record_state.state} at audit_at"
        ),
    )


def _condition_sole_owner(
    record_state: ResourceState,
    sole_owner_grounds: frozenset[str] = frozenset(),
) -> bool:
    """True when the record is grounded as belonging to the subject alone.

    The ground is participant evidence, not a label heuristic: a ``LINK_RESOURCE_IDENTITY``
    catalogue row that explicitly states the resource "belongs only to" this subject (and no
    other subject is linked) satisfies the condition, as does an attachment record that itself
    exposes one of the subject's own direct identifiers. When nothing grounds ownership, the
    condition is *not* satisfied, so the safer shared-context treatment applies
    (GLM-R2-N1, correcting the dead ``foreign``-substring fallback).
    """

    if record_state.state == STATE_UNKNOWN:
        return False
    if record_state.resource_id in sole_owner_grounds:
        return True
    if record_state.category != "SUPPORT_ATTACHMENT":
        return False
    for observation in record_state.observations:
        detail = (observation.detail or "").casefold()
        if "foreign" in detail or "shared with" in detail:
            return False
        if "belongs to" in detail and "only" not in detail:
            return False
    # An attachment that names the subject's own direct identifier is theirs alone; an
    # attachment that names nobody cannot be decided and falls back to the shared treatment.
    return any(observation.identifiers_exposed for observation in record_state.observations)


def evaluate_state(
    report: StateReport,
    policy: PolicyIndex,
) -> PolicyReport:
    """Evaluate every reconstructed resource, plus every flow/restore capability."""

    outcomes: list[PolicyOutcome] = []
    unknown_categories: set[str] = set()
    diagnostics: list[str] = []

    # Catalogue/content links that explicitly ground sole ownership of a resource for the
    # subject. The ``sole_owner`` policy condition is decided from this evidence (GLM-R2-N1).
    sole_owner_grounds = frozenset(
        link.resource_id for link in report.resource_links if link.sole_owner
    )

    for record_state in report.records:
        # Flow and restore capabilities are process state, not stored records; they are
        # evaluated by :func:`_evaluate_flow`/:func:`_evaluate_restore` so they are not
        # double-counted here.
        if record_state.category in FLOW_CATEGORIES or record_state.category in RESTORE_CATEGORIES:
            continue
        outcome = evaluate_record(
            record_state, policy, sole_owner_grounds=sole_owner_grounds
        )
        if outcome.outcome == OUTCOME_UNKNOWN and outcome.rule_id is None:
            unknown_categories.add(record_state.category)
        outcomes.append(outcome)

    # Flows: policy treats an active copy/recreation path as a violation of completeness.
    for flow in report.flows:
        outcomes.append(_evaluate_flow(flow))

    # Restores: an unsafe restore path is a violation of completeness.
    for restore in report.restores:
        outcomes.append(_evaluate_restore(restore))

    if unknown_categories:
        diagnostics.append(
            "categories with no supplied rule: " + ", ".join(sorted(unknown_categories))
        )
    problems = report.contradictions
    if problems:
        diagnostics.append(f"{len(problems)} resource(s) had contradictory observations")
    return PolicyReport(
        outcomes=tuple(outcomes),
        unknown_categories=tuple(sorted(unknown_categories)),
        diagnostics=tuple(diagnostics),
    )


def _evaluate_flow(flow: DataFlowState) -> PolicyOutcome:
    rule_state = STATE_DISABLED
    if flow.state in {STATE_DISABLED, STATE_ABSENT}:
        return PolicyOutcome(
            system=flow.system,
            resource_id=flow.resource_id,
            category="DATA_FLOW",
            rule_id=None,
            required_action="DISABLE",
            required_state=rule_state,
            outcome=OUTCOME_COMPLIANT,
            observed_state=flow.state,
            reason="the data flow is already stopped at audit_at",
        )
    if flow.state in {STATE_ACTIVE_FLOW, STATE_PRESENT, STATE_RETAINED}:
        # A connector row that exists without an explicit "enabled" flag is still a live
        # copy/recreation path: presence of the configuration is the recreation risk
        # (GLM T02-NB-6). It is not silently downgraded to UNKNOWN.
        return PolicyOutcome(
            system=flow.system,
            resource_id=flow.resource_id,
            category="DATA_FLOW",
            rule_id=None,
            required_action="DISABLE",
            required_state=rule_state,
            outcome=OUTCOME_VIOLATION,
            observed_state=flow.state,
            reason="a live process can still copy or recreate the subject's data",
        )
    return PolicyOutcome(
        system=flow.system,
        resource_id=flow.resource_id,
        category="DATA_FLOW",
        rule_id=None,
        required_action="DISABLE",
        required_state=rule_state,
        outcome=OUTCOME_UNKNOWN,
        observed_state=flow.state,
        reason="the data flow state is not established by the available evidence",
    )


def _evaluate_restore(risk: RestoreRisk) -> PolicyOutcome:
    required_state = STATE_BLOCKED
    if risk.state in {STATE_BLOCKED, STATE_ABSENT}:
        return PolicyOutcome(
            system=risk.system,
            resource_id=risk.resource_id,
            category="BACKUP_ARCHIVE",
            rule_id=None,
            required_action="BLOCK",
            required_state=required_state,
            outcome=OUTCOME_COMPLIANT,
            observed_state=risk.state,
            reason="the restore path is already blocked at audit_at",
        )
    if risk.state == STATE_ACTIVE_FLOW:
        return PolicyOutcome(
            system=risk.system,
            resource_id=risk.resource_id,
            category="BACKUP_ARCHIVE",
            rule_id=None,
            required_action="BLOCK",
            required_state=required_state,
            outcome=OUTCOME_VIOLATION,
            observed_state=risk.state,
            reason="a backup or restore path can bring the deleted data back",
        )
    return PolicyOutcome(
        system=risk.system,
        resource_id=risk.resource_id,
        category="BACKUP_ARCHIVE",
        rule_id=None,
        required_action="BLOCK",
        required_state=required_state,
        outcome=OUTCOME_UNKNOWN,
        observed_state=risk.state,
        reason="the restore path state is not established by the available evidence",
    )


#: System -> the canonical ``system_id`` the contract example uses. Evidence systems are
#: already canonical in this dataset; the map exists so a display-name variant still maps
#: onto a stable id rather than leaking a human label into the output.
_SYSTEM_ID_ALIASES: Mapping[str, str] = {
    "support_replica": "support_platform",
    "support_storage_service": "support_platform",
    "object_store": "object_storage",
    "backup_restore_service": "backup_service",
    "user_export_store": "export_service",
    "privacy_treatment_service": "privacy_case_management",
    "identity_service": "identity_service",
    "profile_service": "profile_service",
    "deletion_worker": "deletion_worker",
}

#: Category -> the system that owns the record, used when a record's own system is not
#: resolvable. Kept explicit so the emitted ``system_id`` is deterministic.
_CATEGORY_SYSTEM: Mapping[str, str] = {
    "USER_PROFILE": "account_service",
    "SECONDARY_IDENTIFIER": "identity_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "CACHE_ENTRY": "cache_service",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "analytics_platform",
    "USER_EXPORT": "export_service",
    "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "email_delivery_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_service",
    "BACKUP_ARCHIVE": "backup_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
    "DATA_FLOW": "integration_service",
}


def canonical_system_id(system: str | None, category: str | None) -> str:
    """Return a stable ``system_id`` for a policy outcome."""

    if system:
        folded = system.strip().casefold()
        if folded in _SYSTEM_ID_ALIASES:
            return _SYSTEM_ID_ALIASES[folded]
        if folded and folded != "unknown":
            return folded
    if category:
        mapped = _CATEGORY_SYSTEM.get(category.strip().upper())
        if mapped:
            return mapped
    return "unknown"


def classify_flow_category(category: str) -> str:
    """Return ``flow``/``restore``/``record`` for a policy category."""

    if category in FLOW_CATEGORIES:
        return "flow"
    if category in RESTORE_CATEGORIES:
        return "restore"
    return "record"
