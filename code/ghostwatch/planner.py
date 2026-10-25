"""Planning: turn reconstructed state and policy outcomes into ordered, safe steps.

The planner is where the ordering rules in the contract actually live:

* phases run ``FINDING`` -> ``REMEDIATION`` -> ``VERIFICATION``;
* inside a phase, steps sort by the operation order of the problem statement's table,
  then by ``system_id``, then by ``resource_id`` (:mod:`ghostwatch.schema` owns the ranks);
* remediation stops flows and blocks unsafe restores *before* it changes dependent
  records, and downstream copies are processed before their source records.

The last rule is modelled with a small, explicit dependency graph rather than a case
table: a ``USER_PROFILE`` is the source of the ``SEARCH_INDEX_ENTRY``, ``ANALYTICS_PROFILE``
and ``CACHE_ENTRY`` copies derived from it, so those copies are deleted first. That ordering
is a property of the data model, not of any particular case.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Mapping

from .authorization import (
    AuthorizationDecision,
    ModelUsage,
    SemanticClassifier,
    authorize,
    resolve_ambiguous_as_not_applicable,
)
from .evidence import EvidenceLibrary
from .identity import IdentityIndex, Subject
from .ingest import DeletionRequest, Dataset
from .policy import (
    OUTCOME_RETAINED,
    OUTCOME_UNKNOWN,
    OUTCOME_VIOLATION,
    PolicyIndex,
    PolicyOutcome,
    PolicyReport,
    canonical_system_id,
    evaluate_state,
)
from .schema import (
    REMEDY_VERIFICATION,
    RETAIN_VERIFICATION,
    TREATMENT_REMEDY,
    Step,
    steps_json,
    validate_steps_payload,
)
from .state import (
    COPY_DUTY_CATEGORIES,
    RETAIN_DUTY_CATEGORIES,
    StateReport,
    _category_from_resource_id,
    reconstruct,
    resource_scoped_matches,
)

#: ``category -> set(categories derived from it)``. A copy is remediated before its
#: source so nothing can be recreated from a live source after the copy is removed.
_DERIVED_FROM: Mapping[str, frozenset[str]] = {
    "USER_PROFILE": frozenset(
        {
            "SEARCH_INDEX_ENTRY",
            "ANALYTICS_PROFILE",
            "CACHE_ENTRY",
            "SUPPORT_MESSAGE",
            "SUPPORT_ATTACHMENT",
            "USER_EXPORT",
            "MARKETING_PROFILE",
            "PRODUCT_TELEMETRY",
            "DATA_FLOW",
            "BACKUP_ARCHIVE",
        }
    ),
}


class PlanningError(RuntimeError):
    """The planner was asked to build a plan it cannot justify."""


@dataclasses.dataclass(frozen=True, slots=True)
class Plan:
    """The serialized plan plus the provenance the runner reports."""

    status: str
    steps: tuple[Step, ...]
    json: str
    findings: int = 0
    remediation: int = 0
    verification: int = 0
    diagnostics: tuple[str, ...] = ()

    def as_row(self, case_id: str) -> dict[str, str]:
        return {"case_id": case_id, "deletion_status": self.status, "steps_json": self.json}


def _resource_rank(category: str, resource_id: str) -> tuple[int, str]:
    """Order copies before sources; ties broken by resource id."""

    sources = _DERIVED_FROM.get("USER_PROFILE", frozenset())
    is_derived = category in sources
    # Derived copies sort *first* within remediation.
    return (0 if is_derived else 1, resource_id)


def plan_incomplete(
    policy_report: PolicyReport,
    state_report: StateReport,
    policy: PolicyIndex,
) -> Plan:
    """Build findings + remediation + verification for an incomplete case."""

    violations = [outcome for outcome in policy_report.outcomes if outcome.outcome == OUTCOME_VIOLATION]
    if not violations:
        raise PlanningError(
            "plan_incomplete called with no policy violation; an incomplete case must name "
            "at least one remaining record, exposed identifier, active flow or restore risk"
        )
    findings: list[Step] = []
    remediation: list[Step] = []
    verification: list[Step] = []
    diagnostics: list[str] = []

    ordered_violations = sorted(
        violations,
        key=lambda outcome: (
            _remediation_rank(outcome),
            canonical_system_id(outcome.system, outcome.category),
            outcome.resource_id,
        ),
    )

    for outcome in ordered_violations:
        system_id = canonical_system_id(outcome.system, outcome.category)
        evidence_id = _evidence_for_outcome(outcome, state_report)
        finding, remedy, verify = _steps_for_violation(outcome, system_id, evidence_id)
        findings.append(finding)
        remediation.append(remedy)
        verification.append(verify)

    # Retained records that policy requires must still be verified present on an
    # incomplete case too, because remediation must not remove them.
    for outcome in sorted(policy_report.outcomes, key=lambda item: (item.category, item.resource_id)):
        if outcome.outcome != OUTCOME_RETAINED:
            continue
        system_id = canonical_system_id(outcome.system, outcome.category)
        verification.append(
            Step(
                phase="VERIFICATION",
                system_id=system_id,
                resource_id=outcome.resource_id,
                operation=RETAIN_VERIFICATION,
                evidence_id="",
            )
        )

    # Every *other* relevant duty the case still owes must also be checked here, not only the
    # remediated violations: an undecided resource beside a violation, and a coverage gap beside
    # a violation, are both open items the plan must close. They are emitted as future
    # verification checks with an empty ``evidence_id`` (GLM-R3-N3). A check always names a real
    # grounded resource — the subject's own recorded row, or a catalogue-linked resource whose id
    # names the category — and a duty with no grounded identity is a blocking diagnostic, never a
    # fabricated ``<category>_copy`` (DS-R2-B3).
    seen_verification = {(step.operation, step.system_id, step.resource_id) for step in verification}
    linked_by_category = _linked_resources_by_category(state_report)
    real_by_category = _real_resources_by_category(state_report)
    ocr_resources = _ocr_only_resources(state_report)
    unresolved_duties: list[str] = []
    for outcome in sorted(
        (item for item in policy_report.outcomes if item.outcome == OUTCOME_UNKNOWN),
        key=lambda item: (canonical_system_id(item.system, item.category), item.resource_id),
    ):
        resource_id = outcome.resource_id
        if resource_id in ocr_resources and outcome.category in linked_by_category:
            resource_id = linked_by_category[outcome.category]
        if not _is_real_resource_id(resource_id):
            unresolved_duties.append(f"{outcome.system}/{resource_id}")
            continue
        operation = _unknown_verification_operation(outcome)
        if operation is None:
            unresolved_duties.append(f"{outcome.system}/{resource_id}")
            continue
        system_id = canonical_system_id(outcome.system, outcome.category)
        key = (operation, system_id, resource_id)
        if key in seen_verification:
            continue
        seen_verification.add(key)
        verification.append(
            Step(
                phase="VERIFICATION",
                system_id=system_id,
                resource_id=resource_id,
                operation=operation,
                evidence_id="",
            )
        )
    for gap in (
        *coverage_gaps(policy_report, state_report),
        *missing_retention(policy_report, state_report),
    ):
        operation, system_hint = _duty_verification(gap.category)
        if operation is None:
            unresolved_duties.append(f"coverage:{gap.category}")
            continue
        resource_id = real_by_category.get(gap.category) or linked_by_category.get(gap.category)
        if not resource_id:
            unresolved_duties.append(f"coverage:{gap.category}")
            continue
        system_id = canonical_system_id(system_hint, gap.category)
        key = (operation, system_id, resource_id)
        if key in seen_verification:
            continue
        seen_verification.add(key)
        verification.append(
            Step(
                phase="VERIFICATION",
                system_id=system_id,
                resource_id=resource_id,
                operation=operation,
                evidence_id="",
            )
        )

    unknowns = [outcome for outcome in policy_report.outcomes if outcome.outcome == OUTCOME_UNKNOWN]
    if unknowns:
        diagnostics.append(
            f"{len(unknowns)} resource(s) could not be decided from evidence and are not "
            "remediated: "
            + ", ".join(f"{item.system}/{item.resource_id}" for item in unknowns[:8])
            + (" ..." if len(unknowns) > 8 else "")
        )
    if unresolved_duties:
        diagnostics.append(
            f"{len(unresolved_duties)} relevant duty/duties have no grounded resource identity "
            "and are reported as a blocking diagnostic rather than serialized under an invented "
            "id: "
            + ", ".join(unresolved_duties[:8])
            + (" ..." if len(unresolved_duties) > 8 else "")
        )

    steps = tuple(findings) + tuple(remediation) + tuple(verification)
    payload = steps_json(steps)
    return Plan(
        status="INCOMPLETE",
        steps=steps,
        json=payload,
        findings=len(findings),
        remediation=len(remediation),
        verification=len(verification),
        diagnostics=tuple(diagnostics),
    )


def _remediation_rank(outcome: PolicyOutcome) -> int:
    """Remediation order rank: flows, restores, then derived copies, then sources."""

    if outcome.category == "DATA_FLOW":
        return 0
    if outcome.category == "BACKUP_ARCHIVE":
        return 1
    _derived, resource_key = _resource_rank(outcome.category, outcome.resource_id)
    return 2 if _derived == 0 else 3


def _evidence_for_outcome(outcome: PolicyOutcome, state_report: StateReport) -> str:
    for record_state in state_report.records:
        if record_state.system == outcome.system and record_state.resource_id == outcome.resource_id:
            return record_state.evidence_id
    for flow in state_report.flows:
        if flow.system == outcome.system and flow.resource_id == outcome.resource_id:
            return flow.evidence_id
    for risk in state_report.restores:
        if risk.system == outcome.system and risk.resource_id == outcome.resource_id:
            return risk.evidence_id
    return ""


def _steps_for_violation(
    outcome: PolicyOutcome,
    system_id: str,
    evidence_id: str,
) -> tuple[Step, Step, Step]:
    """Return ``(finding, remediation, verification)`` for one violation."""

    category = outcome.category
    if category == "DATA_FLOW":
        finding_op, remedy_op = "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW"
    elif category == "BACKUP_ARCHIVE":
        finding_op, remedy_op = "REPORT_RESTORE_RISK", "BLOCK_RESTORE"
    else:
        remedy_op = TREATMENT_REMEDY.get(outcome.required_action or "", "DELETE_RECORD")
        if remedy_op == "DELETE_RECORD":
            finding_op = "REPORT_REMAINING_RECORD"
        else:
            finding_op = "REPORT_EXPOSED_PII"

    finding = Step(
        phase="FINDING",
        system_id=system_id,
        resource_id=outcome.resource_id,
        operation=finding_op,
        evidence_id=evidence_id,
    )
    remedy = Step(
        phase="REMEDIATION",
        system_id=system_id,
        resource_id=outcome.resource_id,
        operation=remedy_op,
        evidence_id="",
    )
    verify_op = REMEDY_VERIFICATION.get(remedy_op)
    if verify_op is None:  # pragma: no cover - guarded by the mapping above
        raise PlanningError(f"no verification operation for remedy {remedy_op!r}")
    verify = Step(
        phase="VERIFICATION",
        system_id=system_id,
        resource_id=outcome.resource_id,
        operation=verify_op,
        evidence_id="",
    )
    return finding, remedy, verify


def plan_complete(
    policy_report: PolicyReport,
    state_report: StateReport,
    policy: PolicyIndex,
) -> Plan:
    """Build the evidence-backed verification steps for a complete case.

    A ``COMPLETE`` case may only contain ``VERIFICATION`` steps, and each must cite the
    evidence that proves the compliant state, so an outcome without a citation is refused
    rather than emitted uncited. A copy duty proved *absent* by a covering snapshot is
    emitted as an evidence-backed ``VERIFY_RECORD_ABSENT`` so the plan actually proves the
    deletion rather than merely omitting a violation (GLM T02-B3).
    """

    steps: list[Step] = []
    seen_steps: set[tuple[str, str, str]] = set()
    for outcome in sorted(
        policy_report.outcomes,
        key=lambda item: (canonical_system_id(item.system, item.category), item.resource_id, item.category),
    ):
        if outcome.outcome == OUTCOME_VIOLATION:
            raise PlanningError(
                f"plan_complete called with a violation on {outcome.system}/{outcome.resource_id}"
            )
        if outcome.outcome == OUTCOME_UNKNOWN:
            raise PlanningError(
                f"plan_complete called without a decided state for "
                f"{outcome.system}/{outcome.resource_id}: "
                "an undecided resource cannot be certified complete"
            )
        evidence_id = _evidence_for_outcome(outcome, state_report)
        if not evidence_id:
            raise PlanningError(
                f"no evidence proves the compliant state of "
                f"{outcome.system}/{outcome.resource_id}; refusing to claim completeness"
            )
        system_id = canonical_system_id(outcome.system, outcome.category)
        step = _verification_for_compliant(outcome, system_id, evidence_id)
        key = (step.operation, step.system_id, step.resource_id)
        if key in seen_steps:
            continue
        seen_steps.add(key)
        steps.append(step)

    # Covered absence: a copy duty the evidence proves is gone gets its own evidence-backed
    # absence check, so the COMPLETE plan carries deletion proof for it (GLM T02-B3).
    decided = state_report.decoded_categories()
    real_by_category = _real_resources_by_category(state_report)
    for claim in state_report.coverage:
        if claim.category in decided:
            continue
        if claim.category not in COPY_DUTY_CATEGORIES:
            continue
        operation, system_hint = _duty_verification(claim.category)
        if operation is None:
            continue
        system_id = canonical_system_id(claim.system or system_hint, claim.category)
        # The identity is the subject's real row when one is recorded, otherwise the
        # evidence's own declared collection name — a participant-visible identifier for the
        # store's collection, never a fabricated ``<category>_absent`` per-subject copy
        # (DS-R2-B3). It is only produced for an explicitly complete listing.
        resource_id = real_by_category.get(claim.category) or claim.collection
        if not resource_id:
            continue
        key = (operation, system_id, resource_id)
        if key in seen_steps:
            continue
        seen_steps.add(key)
        steps.append(
            Step(
                phase="VERIFICATION",
                system_id=system_id,
                resource_id=resource_id,
                operation=operation,
                evidence_id=claim.evidence_id,
            )
        )

    if not steps:
        raise PlanningError(
            "a complete case must cite at least one evidence-backed verification step"
        )
    return Plan(
        status="COMPLETE",
        steps=tuple(steps),
        json=steps_json(steps),
        verification=len(steps),
        diagnostics=(
            "completeness rests on the stores the participant evidence links to the subject; "
            "a store the evidence never links to the subject is not part of this audit",
        ),
    )


def _verification_for_compliant(outcome: PolicyOutcome, system_id: str, evidence_id: str) -> Step:
    category = outcome.category
    if outcome.outcome == OUTCOME_RETAINED:
        operation = RETAIN_VERIFICATION
    elif category == "DATA_FLOW":
        operation = "VERIFY_DATA_FLOW_DISABLED"
    elif category == "BACKUP_ARCHIVE":
        operation = "VERIFY_RESTORE_BLOCKED"
    elif outcome.required_action == "ANONYMIZE" or outcome.observed_state == "ANONYMIZED":
        operation = "VERIFY_RECORD_ANONYMIZED"
    elif outcome.required_action == "REDACT" or outcome.observed_state == "REDACTED":
        operation = "VERIFY_RECORD_REDACTED"
    elif outcome.observed_state == "ABSENT":
        operation = "VERIFY_RECORD_ABSENT"
    else:
        operation = "VERIFY_RECORD_PRESENT"
    return Step(
        phase="VERIFICATION",
        system_id=system_id,
        resource_id=outcome.resource_id,
        operation=operation,
        evidence_id=evidence_id,
    )


@dataclasses.dataclass(frozen=True, slots=True)
class CoverageGap:
    """A data category a completeness claim cannot account for."""

    category: str
    reason: str


def coverage_gaps(policy_report: PolicyReport, state_report: StateReport) -> tuple[CoverageGap, ...]:
    """Return the copy duties a completeness claim cannot evidence.

    A deletion is complete only when *every relevant copy* has the required treatment
    (DS-B3 / GLM-B3). "No observed violation" is not enough, but "the platform might hold a
    copy" is not enough either: inventing a universal per-user resource set would fabricate
    duties. The rule therefore turns on **relevance**, which the evidence must establish:

    * A duty is *decided* when a resource of that category has a concrete state (compliant
      copy found, or remediated).
    * A duty is *covered* when an in-window snapshot explicitly declares the collection a
      complete listing and shows no row — the provable-absence case (GLM T02-B3, DS-R2-B2).
    * A duty is *relevant* when participant evidence grounds that exact category for the
      subject: a record of the category, a covering snapshot of it, a decided outcome, or a
      ``LINK_RESOURCE_IDENTITY`` catalogue row whose resource id names it. Store co-ownership
      alone is not relevance (GLM-R2-B2).

    Only relevant duties that are neither decided nor covered become gaps. A category the
    evidence never grounds for the subject is simply not part of this audit.
    """

    decided = state_report.decoded_categories()
    covered = state_report.covered_categories()
    relevant = _relevant_categories(policy_report, state_report)
    gaps: list[CoverageGap] = []
    for category in _DUTY_CATEGORIES:
        if category in decided or category in covered:
            continue
        if category not in relevant:
            continue
        gaps.append(
            CoverageGap(
                category=category,
                reason=(
                    f"the evidence links the subject to {category} storage but neither decides "
                    "the copy's state nor proves its absence, so the duty is not evidenced"
                ),
            )
        )
    return tuple(gaps)


#: Every category a completeness claim must account for: the deletion copy duties plus the
#: account tombstone, which policy redacts rather than deletes but still requires to be
#: accounted for (GLM-R2-B2).
_DUTY_CATEGORIES: tuple[str, ...] = (*COPY_DUTY_CATEGORIES, "ACCOUNT_TOMBSTONE")


#: A category is a copy duty only when participant evidence grounds it for the subject (a
#: record, a decided outcome, a covered snapshot, or a catalogue link naming its id). A
#: ``system -> owned categories`` table used to expand one linked row into every category
#: that system could hold; that invented duties no evidence could decide (GLM-R2-B2), so the
#: expansion is removed. ``ACCOUNT_TOMBSTONE`` is treated as a duty-bearing category for a
#: linked tombstone resource even though it is not deleted, because policy redacts it.
_TOMBSTONE_CATEGORY = "ACCOUNT_TOMBSTONE"


def _relevant_categories(
    policy_report: PolicyReport,
    state_report: StateReport,
) -> frozenset[str]:
    """Copy-duty categories the *evidence* grounds for this subject.

    A duty is relevant only when participant evidence ties the subject to that category:

    * a record whose derived category **is** that category (the subject's own row);
    * a decided policy outcome of that category;
    * a covered snapshot of that category's collection; or
    * a ``LINK_RESOURCE_IDENTITY`` catalogue row whose resource id names that category.

    Mere co-ownership of a system is not evidence: a subject linked to ``support_platform``
    by one support message is not thereby given an invented ``SUPPORT_ATTACHMENT`` duty that
    no evidence can ever decide (GLM-R2-B2). A duty the evidence never grounds is simply not
    part of this audit.
    """

    relevant: set[str] = set()
    # The subject's own records, by their *derived category* rather than their store's
    # capability list.
    for record in state_report.records:
        if record.category in COPY_DUTY_CATEGORIES:
            relevant.add(record.category)
    # A covered snapshot of a store grounds that store's own duty (not its siblings').
    for claim in state_report.coverage:
        if claim.category in COPY_DUTY_CATEGORIES:
            relevant.add(claim.category)
    # A policy outcome the state layer already produced grounds its category.
    for outcome in policy_report.outcomes:
        if outcome.category in COPY_DUTY_CATEGORIES:
            relevant.add(outcome.category)
    # A catalogue link grounds the category its resource id names — the linked resource is the
    # real identity the duty check must name (GLM-R2-B2), including an evidenced tombstone.
    for link in state_report.resource_links:
        category = _category_for_resource_id(link.resource_id)
        if category in COPY_DUTY_CATEGORIES or category == "ACCOUNT_TOMBSTONE":
            relevant.add(category)
    return frozenset(relevant)


def _category_for_resource_id(resource_id: str) -> str | None:
    """The data category a resource id's prefix names, or ``None`` (grounded, not guessed)."""

    derived = _category_from_resource_id(resource_id)
    if derived is None:
        return None
    return derived[1]


def missing_retention(
    policy_report: PolicyReport,
    state_report: StateReport,
) -> tuple[CoverageGap, ...]:
    """Return retention duties whose required record is *required to exist* but is unproven.

    Rules 12/13 require a record to be kept. If the evidence covers the store and shows no
    such record for the subject, retention is unproven and the case cannot be completed.
    """

    gaps: list[CoverageGap] = []
    accounted = state_report.decoded_categories() | state_report.covered_categories()
    for category in RETAIN_DUTY_CATEGORIES:
        if category in accounted:
            continue
        if not any(outcome.category == category for outcome in policy_report.outcomes):
            continue
        gaps.append(
            CoverageGap(
                category=category,
                reason=(
                    f"policy requires the subject's {category} record to be retained, but the "
                    "evidence does not establish that it is still present"
                ),
            )
        )
    return tuple(gaps)


def decide_status(
    policy_report: PolicyReport,
    state_report: StateReport,
) -> str:
    """Decide ``COMPLETE`` vs ``INCOMPLETE`` from evidence, never from a reported status.

    Complete requires: no violation, no undecided resource, no contradiction that leaves a
    copy unaccounted for, no active flow or unsafe restore path, and **evidence-backed
    coverage of every copy duty** — a retained-only observation cannot certify the copies
    policy requires to be deleted (DS-B3/GLM-B3).
    """

    if any(outcome.outcome == OUTCOME_VIOLATION for outcome in policy_report.outcomes):
        return "INCOMPLETE"
    if any(outcome.outcome == OUTCOME_UNKNOWN for outcome in policy_report.outcomes):
        return "INCOMPLETE"
    if state_report.contradictions:
        return "INCOMPLETE"
    if state_report.active_flows() or state_report.unsafe_restores():
        return "INCOMPLETE"
    if coverage_gaps(policy_report, state_report):
        return "INCOMPLETE"
    if missing_retention(policy_report, state_report):
        return "INCOMPLETE"
    return "COMPLETE"


def plan(
    policy_report: PolicyReport,
    state_report: StateReport,
    policy: PolicyIndex,
) -> Plan:
    """Decide the case and return the full plan."""

    status = decide_status(policy_report, state_report)
    if status == "COMPLETE":
        return plan_complete(policy_report, state_report, policy)
    return plan_incomplete(policy_report, state_report, policy)


def not_applicable_plan() -> Plan:
    """The ``NOT_APPLICABLE`` plan: an empty array, by contract."""

    return Plan(status="NOT_APPLICABLE", steps=(), json="[]")

# --------------------------------------------------------------------------------------
# Public audit interface
# --------------------------------------------------------------------------------------


class AuditError(RuntimeError):
    """The audit cannot produce a trustworthy answer for this request."""


@dataclasses.dataclass(frozen=True, slots=True)
class EvidenceGap:
    """A place where the audit could not establish a fact it needed."""

    kind: str        # "authorization" | "identity" | "evidence" | "category" | "contradiction"
    detail: str
    blocking: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class AuditResult:
    """The contract answer plus the provenance the runner reports."""

    case_id: str
    deletion_status: str
    steps_json: str
    authorization: AuthorizationDecision
    subject_user_id: str | None
    authorization_method: str
    gaps: tuple[EvidenceGap, ...] = ()
    diagnostics: tuple[str, ...] = ()
    model_usage: ModelUsage | None = None
    step_count: int = 0

    def as_row(self) -> dict[str, str]:
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status,
            "steps_json": self.steps_json,
        }

    @property
    def schema_problems(self) -> tuple[str, ...]:
        import json as _json

        try:
            payload = _json.loads(self.steps_json)
        except _json.JSONDecodeError as exc:
            return (f"steps_json is not valid JSON: {exc}",)
        return tuple(validate_steps_payload(payload))


class ParticipantContext:
    """Everything :func:`audit` needs, assembled once and reused for every request.

    Building the context is deliberately separate from auditing: the evidence library
    caches extraction, so a full run parses each evidence file once.
    """

    def __init__(
        self,
        dataset: Dataset,
        *,
        identity_index: IdentityIndex | None = None,
        evidence_library: EvidenceLibrary | None = None,
        policy_index: PolicyIndex | None = None,
        classifier: SemanticClassifier | None = None,
        include_text_state: bool = True,
    ) -> None:
        self.dataset = dataset
        self.index = identity_index or IdentityIndex(dataset.identities, dataset.audit_log)
        self.library = evidence_library or EvidenceLibrary(dataset, index=self.index)
        self.policy = policy_index or PolicyIndex(dataset)
        self.classifier = classifier
        self.include_text_state = include_text_state
        self._text_cache: dict[str, str] = {}

    def text_documents(self) -> Mapping[str, str]:
        """Raw text of every ``.txt`` evidence file, used for handover state rows."""

        if not self.include_text_state:
            return {}
        if not self._text_cache:
            for entry in self.dataset.evidence_manifest:
                if not entry.file_path.lower().endswith(".txt"):
                    continue
                document = self.library.document(entry.file_id, strict=False)
                if document is not None:
                    self._text_cache[entry.file_id] = document.text
        return self._text_cache


@dataclasses.dataclass(frozen=True, slots=True)
class _CaseInputs:
    subject: Subject | None
    subject_error: str | None
    state: StateReport | None
    policy: PolicyReport | None


def audit(
    request: DeletionRequest,
    participant_context: ParticipantContext,
) -> AuditResult:
    """Audit one request and return its contract answer plus diagnostics.

    The function fails *explicitly* rather than inventing proof:

    * a request that is not authorized for deletion returns ``NOT_APPLICABLE`` with ``[]``;
    * an identity that cannot be resolved returns ``INCOMPLETE`` with an identity gap, not
      a silent ``COMPLETE``;
    * a case with no grounded evidence but an authorized deletion is reported as
      ``INCOMPLETE`` with an evidence gap (the workflow cannot be shown to be complete);
    * a case whose steps would violate the step schema raises :class:`AuditError`.
    """

    gaps: list[EvidenceGap] = []
    diagnostics: list[str] = []

    raw_decision = authorize(request.request_text, classifier=participant_context.classifier)
    decision = resolve_ambiguous_as_not_applicable(raw_decision)
    if raw_decision.decision == "AMBIGUOUS":
        # The fallback to NOT_APPLICABLE is disclosed rather than hidden, so the runner can
        # report how often an unresolved ambiguity fired (GLM T02-NB-1).
        diagnostics.append(
            "the request text was AMBIGUOUS and was folded to NOT_APPLICABLE: "
            f"{raw_decision.reason}"
        )
    if decision.decision == "NOT_APPLICABLE":
        return AuditResult(
            case_id=request.case_id,
            deletion_status="NOT_APPLICABLE",
            steps_json="[]",
            authorization=decision,
            subject_user_id=None,
            authorization_method=decision.method,
            diagnostics=tuple(diagnostics),
        )

    # ---------------------------------------------------------------- identity resolution
    try:
        subject = participant_context.index.resolve_email(request.email, at=request.audit_at)
    except Exception as exc:  # UnknownSubjectError / AmbiguousSubjectError
        gap = EvidenceGap(
            kind="identity",
            detail=f"could not resolve {request.email!r} to one subject: {type(exc).__name__}: {exc}",
            blocking=True,
        )
        return AuditResult(
            case_id=request.case_id,
            deletion_status="INCOMPLETE",
            steps_json="[]",
            authorization=decision,
            subject_user_id=None,
            authorization_method=decision.method,
            gaps=(gap,),
            diagnostics=("identity could not be resolved; no plan can be built",),
        )

    # ------------------------------------------------------------------ evidence + state
    evidence = participant_context.library.resolve(
        subject, request.audit_at, strict=False, index=participant_context.index
    )
    supplementary = resource_scoped_matches(
        participant_context.library,
        subject,
        participant_context.index,
        at=request.audit_at,
        resource_ids=evidence.resource_ids,
        evidence=evidence,
    )
    state_report = reconstruct(
        evidence,
        subject,
        participant_context.index,
        at=request.audit_at,
        documents_text=participant_context.text_documents(),
        supplementary_matches=supplementary,
        library=participant_context.library,
    )
    policy_report = evaluate_state(state_report, participant_context.policy)

    for contradiction in state_report.contradictions:
        gaps.append(EvidenceGap(kind="contradiction", detail=contradiction))
    for name in state_report.unknown_records:
        gaps.append(EvidenceGap(kind="category", detail=f"no grounded category for {name}"))
    diagnostics.extend(state_report.diagnostics)
    diagnostics.extend(policy_report.diagnostics)
    if evidence.failures:
        diagnostics.append(
            f"{len(evidence.failures)} evidence extraction failure(s) were recorded"
        )

    # ----------------------------------------------------------------------------- plan
    status = decide_status(policy_report, state_report)

    if status == "COMPLETE":
        # A complete case must be evidence-backed. If nothing at all was grounded for the
        # subject, "complete" would be an unprovable assertion, so it is reported as an
        # explicit gap instead of a fabricated COMPLETE.
        if not policy_report.outcomes:
            gap = EvidenceGap(
                kind="evidence",
                detail=(
                    "no policy-relevant record was grounded to the subject at audit_at, so "
                    "completeness cannot be evidenced"
                ),
                blocking=True,
            )
            return AuditResult(
                case_id=request.case_id,
                deletion_status="INCOMPLETE",
                steps_json="[]",
                authorization=decision,
                subject_user_id=subject.user_id,
                authorization_method=decision.method,
                gaps=(gap,),
                diagnostics=tuple(diagnostics) + ("no grounded evidence for an authorized deletion",),
            )
        plan_result = plan_complete(policy_report, state_report, participant_context.policy)
    else:
        if policy_report.violations():
            plan_result = plan_incomplete(policy_report, state_report, participant_context.policy)
        else:
            # INCOMPLETE without a specific violation: the evidence does not decide the
            # resource state, observations disagree, or a copy duty is simply not covered.
            # No remediation is prescribed and no record is claimed to remain; the plan is
            # the set of checks that must pass once the evidence gap is closed.
            uncovered = coverage_gaps(policy_report, state_report)
            retention_gaps = missing_retention(policy_report, state_report)
            if uncovered or retention_gaps:
                diagnostics.append(
                    "deletion is INCOMPLETE because the evidence does not account for every "
                    "copy policy requires: "
                    + ", ".join(
                        gap.category for gap in (*uncovered, *retention_gaps)
                    )
                )
                for gap in (*uncovered, *retention_gaps):
                    gaps.append(
                        EvidenceGap(kind="coverage", detail=gap.reason, blocking=True)
                    )
            else:
                diagnostics.append(
                    "deletion is INCOMPLETE because at least one resource state could not be "
                    "decided from the available evidence"
                )
                gaps.append(
                    EvidenceGap(
                        kind="evidence",
                        detail="an undecided resource prevents a completeness claim",
                        blocking=True,
                    )
                )
            plan_result = _plan_from_unknowns(policy_report, state_report)

    problems = validate_steps_payload(_decode(plan_result.json))
    if problems:
        raise AuditError(
            f"{request.case_id}: produced steps_json that violates the contract: {problems[:5]}"
        )

    # Every emitted ``resource_id`` must have participant-visible grounding. A synthetic
    # ``<category>_copy``/``_absent`` placeholder, an evidence locator, or an empty id is a
    # fabrication and refuses the plan rather than shipping it (DS-R2-B3).
    provenance = emitted_resource_provenance(plan_result)
    if provenance:
        raise AuditError(
            f"{request.case_id}: emitted step resource id(s) have no participant grounding: "
            f"{provenance[:5]}"
        )

    diagnostics.extend(plan_result.diagnostics)
    return AuditResult(
        case_id=request.case_id,
        deletion_status=plan_result.status,
        steps_json=plan_result.json,
        authorization=decision,
        subject_user_id=subject.user_id,
        authorization_method=decision.method,
        gaps=tuple(gaps),
        diagnostics=tuple(diagnostics),
        model_usage=decision.model_usage,
        step_count=len(plan_result.steps),
    )


def _plan_from_unknowns(
    policy_report: PolicyReport,
    state_report: StateReport,
    policy: PolicyIndex | None = None,
) -> Plan:
    """Build the honest plan for a case that is incomplete without a specific violation.

    No record is reported as remaining (the evidence does not prove that) and no remediation
    is prescribed; the actions are the verification checks that must pass once the evidence
    gap is closed. The check is selected from the resource's *policy duty*, so a retained
    record gets a presence check, a flow gets a flow check and a backup gets a restore check
    (GLM T02-B1) — never a record-absence check against a process or a locator string.

    A coverage gap (a relevant copy neither decided nor covered) is expressed as the
    category's own verification duty, so an INCOMPLETE case always names the checks that
    would close it instead of returning an empty array (DS T02-NB-02).
    """

    steps: list[Step] = []
    unresolved: list[str] = []
    seen: set[tuple[str, str, str]] = set()

    # A catalogue link is an explicit identity bridge; an OCR read off a shared console page is
    # not. When a duty's only in-window observation is such an OCR artifact, the check names
    # the catalogue-linked resource instead of the OCR-noise id (GLM-R2-N5). The preference is
    # grounded: it only fires when a link names a resource of the same category.
    linked_by_category = _linked_resources_by_category(state_report)
    ocr_resources = _ocr_only_resources(state_report)

    for outcome in sorted(
        policy_report.outcomes,
        key=lambda item: (canonical_system_id(item.system, item.category), item.resource_id),
    ):
        if outcome.outcome != OUTCOME_UNKNOWN:
            continue
        resource_id = outcome.resource_id
        if resource_id in ocr_resources and outcome.category in linked_by_category:
            resource_id = linked_by_category[outcome.category]
        if not _is_real_resource_id(resource_id):
            # An evidence locator is not a resource. It cannot be named in a step.
            unresolved.append(f"{outcome.system}/{resource_id}")
            continue
        system_id = canonical_system_id(outcome.system, outcome.category)
        operation = _unknown_verification_operation(outcome)
        if operation is None:
            unresolved.append(f"{outcome.system}/{resource_id}")
            continue
        key = (operation, system_id, resource_id)
        if key in seen:
            continue
        seen.add(key)
        steps.append(
            Step(
                phase="VERIFICATION",
                system_id=system_id,
                resource_id=resource_id,
                operation=operation,
                evidence_id="",
            )
        )

    # A coverage gap is a duty whose evidence is missing. The check that would close it is
    # the category's required-final-state verification, and it must name a *real* grounded
    # resource: the subject's own recorded row, or a catalogue-linked resource whose id names
    # the category. A gap with no grounded resource stays a blocking diagnostic — it is never
    # serialized under a fabricated ``<category>_copy`` identity (DS-R2-B3).
    real_by_category = _real_resources_by_category(state_report)
    for gap in (*coverage_gaps(policy_report, state_report), *missing_retention(policy_report, state_report)):
        operation, system_hint = _duty_verification(gap.category)
        if operation is None:
            unresolved.append(f"coverage:{gap.category}")
            continue
        resource_id = real_by_category.get(gap.category) or linked_by_category.get(gap.category)
        if not resource_id:
            unresolved.append(f"coverage:{gap.category}")
            continue
        system_id = canonical_system_id(system_hint, gap.category)
        key = (operation, system_id, resource_id)
        if key in seen:
            continue
        seen.add(key)
        steps.append(
            Step(
                phase="VERIFICATION",
                system_id=system_id,
                resource_id=resource_id,
                operation=operation,
                evidence_id="",
            )
        )

    notes = [
        "no remediation is prescribed; evidence must be gathered first",
    ]
    if unresolved:
        notes.append(
            f"{len(unresolved)} resource(s) could not be resolved to a real resource id and "
            "are reported as a blocking evidence gap rather than serialized as a step: "
            + ", ".join(unresolved[:8])
            + (" ..." if len(unresolved) > 8 else "")
        )
    return Plan(
        status="INCOMPLETE",
        steps=tuple(steps),
        json=steps_json(steps),
        verification=len(steps),
        diagnostics=tuple(notes),
    )


#: ``category -> (verification operation, system)`` expressing what must be checked before a
#: copy duty can be certified. This is the *required final state* of the duty, not a claim
#: about the current state of a particular store.
_DUTY_VERIFICATION: Mapping[str, tuple[str, str]] = {
    "USER_PROFILE": ("VERIFY_RECORD_ABSENT", "account_service"),
    "SECONDARY_IDENTIFIER": ("VERIFY_RECORD_ABSENT", "identity_service"),
    "SEARCH_INDEX_ENTRY": ("VERIFY_RECORD_ABSENT", "search_service"),
    "ANALYTICS_PROFILE": ("VERIFY_RECORD_ANONYMIZED", "analytics_platform"),
    "PRODUCT_TELEMETRY": ("VERIFY_RECORD_ANONYMIZED", "analytics_platform"),
    "CACHE_ENTRY": ("VERIFY_RECORD_ABSENT", "cache_service"),
    "SUPPORT_MESSAGE": ("VERIFY_RECORD_REDACTED", "support_platform"),
    "SUPPORT_ATTACHMENT": ("VERIFY_RECORD_ABSENT", "support_platform"),
    "USER_EXPORT": ("VERIFY_RECORD_ABSENT", "export_service"),
    "MARKETING_PROFILE": ("VERIFY_RECORD_ABSENT", "marketing_platform"),
    "EMAIL_DELIVERY_LOG": ("VERIFY_RECORD_REDACTED", "email_delivery_service"),
    "SECURITY_AUDIT_LOG": (RETAIN_VERIFICATION, "security_service"),
    "LEGAL_HOLD_RECORD": (RETAIN_VERIFICATION, "legal_service"),
    # A tombstone is not deleted; policy redacts the prohibited direct identifiers while the
    # stable reference remains (rule_15). Its check is therefore a redaction check.
    "ACCOUNT_TOMBSTONE": ("VERIFY_RECORD_REDACTED", "identity_service"),
}


def _duty_verification(category: str) -> tuple[str | None, str]:
    found = _DUTY_VERIFICATION.get(category)
    if found is None:
        return None, "unknown"
    return found


def _real_resources_by_category(state_report: StateReport) -> dict[str, str]:
    """The subject's real resource id per category, where the evidence recorded one."""

    found: dict[str, str] = {}
    for record in sorted(state_report.records, key=lambda item: (item.system, item.resource_id)):
        if _is_real_resource_id(record.resource_id):
            found.setdefault(record.category, record.resource_id)
    for flow in sorted(state_report.flows, key=lambda item: (item.system, item.resource_id)):
        if _is_real_resource_id(flow.resource_id):
            found.setdefault("DATA_FLOW", flow.resource_id)
    for risk in sorted(state_report.restores, key=lambda item: (item.system, item.resource_id)):
        if _is_real_resource_id(risk.resource_id):
            found.setdefault("BACKUP_ARCHIVE", risk.resource_id)
    return found


def _linked_resources_by_category(state_report: StateReport) -> dict[str, str]:
    """Real resource ids the subject is linked to by a catalogue row, keyed by category.

    A ``LINK_RESOURCE_IDENTITY`` row names the resource, so its id is a grounded identity for
    the duty its prefix names — this is what lets a gap check name ``object_19`` or the
    subject's own ``tombstone_17`` instead of a fabricated placeholder (GLM-R2-B2).
    """

    found: dict[str, str] = {}
    for link in sorted(state_report.resource_links, key=lambda item: (item.at, item.resource_id)):
        if not _is_real_resource_id(link.resource_id):
            continue
        category = _category_for_resource_id(link.resource_id)
        if category is None:
            continue
        found.setdefault(category, link.resource_id)
    return found


def _ocr_only_resources(state_report: StateReport) -> frozenset[str]:
    """Resource ids whose only reconstructed evidence is an OCR/screenshot read.

    A resource id read off a shared console screenshot is OCR noise about *some* record on a
    page that also names other customers; it is a weaker identity than an explicit catalogue
    link (GLM-R2-N5). The set lets the planner prefer the linked identity for that duty.
    """

    values: set[str] = set()
    for record in state_report.records:
        if not _is_real_resource_id(record.resource_id):
            continue
        if record.observations and all(
            (observation.detail or "").startswith("ocr:") for observation in record.observations
        ):
            values.add(record.resource_id)
    for process in (*state_report.flows, *state_report.restores):
        if not _is_real_resource_id(process.resource_id):
            continue
        if process.observations and all(
            (observation.detail or "").startswith("ocr:") for observation in process.observations
        ):
            values.add(process.resource_id)
    return frozenset(values)


def _is_real_resource_id(resource_id: str) -> bool:
    """False for an evidence locator (``evidence_25:line:81``) or an empty value."""

    value = (resource_id or "").strip()
    if not value:
        return False
    if ":" in value:
        return False
    # A resource id names a store, so it carries the store's own prefix. A bare evidence id
    # or a line reference does not.
    return bool(re.match(r"[a-z][a-z0-9_]*$", value.casefold()))


#: Suffixes that mark a fabricated category-scoped placeholder rather than a real store id.
_SYNTHETIC_SUFFIXES: tuple[str, ...] = ("_copy", "_absent", "_placeholder", "_unknown")


def emitted_resource_provenance(plan: Plan) -> tuple[str, ...]:
    """Return emitted ``resource_id`` values that lack participant grounding.

    A step's ``resource_id`` must be a real store identity: it must be non-empty, not an
    evidence locator, and not a synthetic ``<category>_copy``/``<category>_absent``
    placeholder. An empty tuple means every emitted id is grounded. This is the invariant
    the T02 fix2 ticket requires across both the COMPLETE and INCOMPLETE paths (DS-R2-B3).
    """

    problems: list[str] = []
    for step in plan.steps:
        resource_id = (step.resource_id or "").strip()
        if not _is_real_resource_id(resource_id):
            problems.append(f"{step.operation}:{resource_id!r} is not a grounded resource id")
            continue
        if resource_id.casefold().endswith(_SYNTHETIC_SUFFIXES):
            problems.append(
                f"{step.operation}:{resource_id!r} is a synthetic category placeholder"
            )
    return tuple(problems)


def _unknown_verification_operation(outcome: PolicyOutcome) -> str | None:
    """The verification the *policy duty* requires for an undecided resource.

    RETAIN/PRESERVE_TOMBSTONE -> a presence check; DATA_FLOW -> a flow check;
    BACKUP_ARCHIVE -> a restore check; every deletion-duty record -> an absence check.
    """

    category = outcome.category
    if category == "DATA_FLOW":
        return "VERIFY_DATA_FLOW_DISABLED"
    if category == "BACKUP_ARCHIVE":
        return "VERIFY_RESTORE_BLOCKED"
    if outcome.required_action in {"RETAIN"} or category in RETAIN_DUTY_CATEGORIES:
        return RETAIN_VERIFICATION
    if outcome.required_action == "PRESERVE_TOMBSTONE":
        return "VERIFY_RECORD_REDACTED"
    if outcome.required_action == "REDACT":
        return "VERIFY_RECORD_REDACTED"
    if outcome.required_action == "ANONYMIZE":
        return "VERIFY_RECORD_ANONYMIZED"
    if outcome.required_action == "DELETE":
        return "VERIFY_RECORD_ABSENT"
    return None


def _decode(payload: str) -> object:
    import json as _json

    return _json.loads(payload)


def build_context(
    dataset: Dataset,
    *,
    classifier: SemanticClassifier | None = None,
) -> ParticipantContext:
    """Convenience constructor for the terminal runner and tests."""

    return ParticipantContext(dataset, classifier=classifier)
