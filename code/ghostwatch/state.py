"""Temporal, evidence-backed reconstruction of what each record *is* at ``audit_at``.

T01 answers "which records are grounded to this subject, and when were they captured or
observed". This module answers the follow-on question the deletion decision needs: for
each of those records, and for the systems that can copy or restore it, what state does
the evidence actually establish at ``audit_at``?

Three rules drive it, straight from the contract:

1. **A claim is not proof.** ``reported_status``, ``reported_result`` and a workflow log
   line are all *claims*. A record is ``PRESENT`` because evidence shows the record with
   identifiers in it, not because a job said it was deleted.
2. **Time is a filter, not a hint.** Only evidence captured at or before ``audit_at`` may
   be used, and a record's own ``observed_at`` is respected separately from the file's
   ``captured_at``.
3. **Absence is only proved by coverage.** A missing row in a snapshot does not prove a
   record is gone for two independent reasons: (a) the snapshot must *cover* the resource
   (the same kind of store or a lookup that names it), and (b) the lookup must be a real
   negative for *this* subject, not a different subject's ``NOT_FOUND``. Without coverage
   the record's state is ``UNKNOWN`` and is reported as such, never quietly treated as
   deleted.

The module also derives missing policy categories (T01 leaves ``record_type`` empty for
operational log lines, PDFs and screenshots) from the container, the collection, the
structured fields and the record's own business content, so a category is grounded in the
record rather than guessed from a case id.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import re
from typing import Iterable, Mapping, Sequence

from .evidence import EvidenceRecord, EvidenceMatch, SubjectEvidence
from .identity import IdentityIndex, Subject, normalise_identifier

UTC = _dt.timezone.utc

# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------

STATE_PRESENT = "PRESENT"          # the record exists and still carries identifiers
STATE_ABSENT = "ABSENT"            # evidence proves the record no longer exists
STATE_REDACTED = "REDACTED"        # the record exists with identifiers removed
STATE_ANONYMIZED = "ANONYMIZED"    # the record exists, no longer linkable
STATE_RETAINED = "RETAINED"        # policy-required retention, identifiers allowed
STATE_ACTIVE_FLOW = "ACTIVE"       # a live process can copy/recreate the data
STATE_BLOCKED = "BLOCKED"          # an unsafe restore path is already blocked
STATE_DISABLED = "DISABLED"        # a live process is already stopped
STATE_UNKNOWN = "UNKNOWN"          # evidence is insufficient or contradictory

#: Categories that describe a *process* rather than a stored record.
FLOW_CATEGORIES = frozenset({"DATA_FLOW", "SYNC_JOB", "INTEGRATION"})
RESTORE_CATEGORIES = frozenset({"BACKUP_ARCHIVE", "RESTORE_JOB", "BACKUP"})

#: Fields that assert a record's *state noun* rather than its existence. A value like
#: ``event=restore_authorization_completed``, ``event=message_scan_started`` or
#: ``event=deletion_reviewed`` names an operation; on its own it never proves a copy of the
#: subject still exists.
_OPERATION_EVENT_RE = re.compile(
    r"(?:^|_)(?:started|completed|denied|approved|reviewed|requested|received|failed|scanned|blocked|disabled|enabled|acquired|recovered|retry|miss|hit)(?:$|_)"
)

#: A ``|``-delimited structured log carries the operation token as its own column
#: (``... | tr-4612767 | audit_record_read_completed | ...``). T01's ``key=value`` tokeniser
#: does not turn it into an ``event`` field, so the state layer reads it from the raw text.
_PIPE_OPERATION_RE = re.compile(
    r"\|\s*(?P<op>[a-z][a-z0-9_]*_(?:started|completed|read|scan|query|lookup))\s*\|"
)


def _record_event_name(record: EvidenceRecord) -> str:
    """The record's operation name, from its ``event`` field or its ``|``-delimited text."""

    event = (record.field("event") or "").strip().casefold()
    if event:
        return event
    text = record.text or ""
    if text:
        match = _PIPE_OPERATION_RE.search(text)
        if match:
            return match.group("op").casefold()
    return ""


def _first_boolean(fields: Mapping[str, str], names: Iterable[str]) -> bool | None:
    """Return the first explicit boolean among ``names``, or ``None`` when none is stated.

    Only the record's *own* field values are read, so an absent field stays undecided rather
    than defaulting to a guessed polarity.
    """

    for name in names:
        raw = ""
        for key, value in fields.items():
            if key.rsplit(".", 1)[-1] == name:
                raw = value.strip().casefold()
                break
        if not raw:
            continue
        if raw in _TRUTHY:
            return True
        if raw in _FALSY:
            return False
    return None

#: Categories policy requires an organization to keep.
RETAIN_CATEGORIES = frozenset(
    {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE"}
)

#: Categories whose policy action is to remove directories/whole records.
DELETE_CATEGORIES = frozenset(
    {
        "USER_PROFILE",
        "SECONDARY_IDENTIFIER",
        "SEARCH_INDEX_ENTRY",
        "CACHE_ENTRY",
        "SUPPORT_ATTACHMENT",
        "USER_EXPORT",
        "MARKETING_PROFILE",
        "PRODUCT_TELEMETRY",
    }
)

#: The data categories a *complete* deletion must account for: every place a copy of the
#: subject's personal data can live on this platform. A completeness claim has to cover
#: them (with a decided compliant state or a covered absence), not merely avoid an observed
#: violation (DS-B3/GLM-B3). Flows and restores are process duties and are checked
#: separately, so they are not part of this set.
COPY_DUTY_CATEGORIES: tuple[str, ...] = (
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
    "CACHE_ENTRY",
    "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG",
)

#: Categories whose duty is to keep the record, so their presence is not a deletion gap but
#: their *missing* record would be a retention gap. Checked separately by the planner.
RETAIN_DUTY_CATEGORIES: tuple[str, ...] = (
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
)

#: ``collection_name`` values that name a *whole store* rather than one subject's row. A
#: snapshot containing such a section covers the collection for every subject, so the
#: subject's missing row is a covered absence rather than silence.
COVERING_COLLECTIONS: Mapping[str, tuple[str, str]] = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
}


# --------------------------------------------------------------------------------------
# Category derivation (T02-NB-G8 guard)
# --------------------------------------------------------------------------------------

#: resource-id prefix -> (system, data category). A record's own id names the store; the
#: prefix is stable across the supplied data and is grounded in the record, not a case.
_RESOURCE_PREFIX_CATEGORY: Mapping[str, tuple[str, str]] = {
    "account": ("account_service", "USER_PROFILE"),
    "search": ("search_service", "SEARCH_INDEX_ENTRY"),
    "analytics": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support": ("support_platform", "SUPPORT_MESSAGE"),
    "tombstone": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "backup": ("backup_service", "BACKUP_ARCHIVE"),
    "export": ("export_service", "USER_EXPORT"),
    "data_flow": ("integration_service", "DATA_FLOW"),
    "marketing": ("marketing_platform", "MARKETING_PROFILE"),
    "audit_record": ("security_service", "SECURITY_AUDIT_LOG"),
    "legal_hold": ("legal_service", "LEGAL_HOLD_RECORD"),
    "cache": ("cache_service", "CACHE_ENTRY"),
    "connector": ("integration_service", "DATA_FLOW"),
    "telemetry": ("analytics_platform", "PRODUCT_TELEMETRY"),
    "email_delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    # A support attachment held in object storage names its own role in the catalogue that
    # links it (``object_19`` -> ``delivery_confirmation_19.pdf`` in the attachment catalog).
    "object": ("support_platform", "SUPPORT_ATTACHMENT"),
}

#: collection / container name -> (system, data category).
_COLLECTION_CATEGORY: Mapping[str, tuple[str, str]] = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "profiles": ("account_service", "USER_PROFILE"),
    "profile_lookups": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "index_queries": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "tickets": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "connectors": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit": ("security_service", "SECURITY_AUDIT_LOG"),
    "audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "account_tombstones": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "customer_tombstones": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
    "marketing_audiences": ("marketing_platform", "MARKETING_PROFILE"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "retained_orders": ("legal_service", "LEGAL_HOLD_RECORD"),
    "email_delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "delivery_log": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
}


def _category_from_resource_id(resource_id: str | None) -> tuple[str, str] | None:
    if not resource_id:
        return None
    folded = resource_id.casefold()
    match = re.match(r"([a-z_]+?)_[0-9a-z]+$", folded)
    prefix = match.group(1) if match else folded
    return _RESOURCE_PREFIX_CATEGORY.get(prefix)


def derive_category(
    record: EvidenceRecord,
    *,
    subject_resource_ids: Iterable[str] = (),
) -> tuple[str, str] | None:
    """Return ``(system, data_category)`` for a record, grounded in the record itself.

    Resolution order, determinism first:

    1. the record's explicit ``record_type`` (T01 already derived it where the container
       named a collection);
    2. the collection name;
    3. a policy category token carried in a structured field (``record_type``,
       ``collection_name``, ``data_category``);
    4. the resource-id prefix;
    5. the record's own business content (a tombstone record names ``account_status``;
       a backup record names an archive path).

    Returns ``None`` when nothing grounds a category: an honest "unknown", never a guess.
    """

    explicit = (record.record_type or "").strip().upper()
    if explicit and explicit not in {"UNKNOWN", "SNAPSHOT", "OPERATIONAL_HISTORY"}:
        return (record.system or _system_for_category(explicit), explicit)

    for candidate in (
        record.collection,
        record.field("collection_name"),
        record.field("data_category"),
        record.container,
    ):
        if not candidate:
            continue
        found = _COLLECTION_CATEGORY.get(candidate.casefold())
        if found is not None:
            return found

    by_resource = _category_from_resource_id(record.resource_id)
    if by_resource is not None:
        return by_resource

    # Content-based: a record that literally carries a policy category token.
    token = record.field("record_type").strip().upper()
    if token and token not in {"UNKNOWN", "SNAPSHOT"}:
        return (record.system or _system_for_category(token), token)

    # Tombstone content: a deleted-account reference with a stable user id and no direct
    # identifiers is an ACCOUNT_TOMBSTONE wherever it is found.
    if record.field("account_status").upper() == "DELETED":
        return ("identity_service", "ACCOUNT_TOMBSTONE")

    if record.field("download_available") or record.field("file_name", "").endswith(".zip"):
        return ("export_service", "USER_EXPORT")

    if record.field("retention_until") or record.field("retain_until"):
        return ("legal_service", "LEGAL_HOLD_RECORD")

    if record.field("integrity_seal") or record.field("checksum_prefix") or record.field("journal_partition"):
        return ("security_service", "SECURITY_AUDIT_LOG")

    # Business-document content: the artifact names its own business role. These are the
    # kinds of documents §6.6 describes (invoices, statements, registers, exports,
    # backups, exports), and the role decides the policy category.
    content = " ".join(
        [record.text or ""]
        + [value for key, value in record.fields if key.startswith("text.")]
    ).casefold()
    if content:
        if "retention" in content or "retain until" in content or "legal hold" in content:
            return ("legal_service", "LEGAL_HOLD_RECORD")
        if (
            "compliance journal" in content
            or "security" in content
            or "audit record" in content
            or "integrity seal" in content
        ):
            return ("security_service", "SECURITY_AUDIT_LOG")
        if "backup" in content or "restore" in content or "archive" in content:
            return ("backup_service", "BACKUP_ARCHIVE")
        if "export" in content and ("download" in content or "archive" in content):
            return ("export_service", "USER_EXPORT")
        if "support" in content and ("ticket" in content or "attachment" in content):
            return ("support_platform", "SUPPORT_ATTACHMENT")
        if "marketing" in content or "audience" in content:
            return ("marketing_platform", "MARKETING_PROFILE")
        if "search index" in content or "index" in content and "document" in content:
            return ("search_service", "SEARCH_INDEX_ENTRY")

    return None


_SYSTEM_CATEGORY_HINTS: Mapping[str, str] = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "support_storage_service": "SUPPORT_ATTACHMENT",
    "export_service": "USER_EXPORT",
    "user_export_store": "USER_EXPORT",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "backup_restore_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "marketing_platform": "MARKETING_PROFILE",
    "legal_service": "LEGAL_HOLD_RECORD",
    "cache_service": "CACHE_ENTRY",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
}


def _system_for_category(category: str) -> str:
    for system, mapped in _SYSTEM_CATEGORY_HINTS.items():
        if mapped == category:
            return system
    return "unknown"


# --------------------------------------------------------------------------------------
# Observation
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Observation:
    """One state-bearing fact, with the evidence that proves it and when."""

    evidence_id: str
    system: str
    resource_id: str
    category: str | None
    state: str
    at: _dt.datetime
    source: str          # "record" | "activity"
    detail: str = ""
    identifiers_exposed: tuple[str, ...] = ()

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.evidence_id, self.resource_id, self.system, self.detail)


@dataclasses.dataclass(frozen=True, slots=True)
class ResourceState:
    """The reconciled state of one ``(system, resource_id)`` pair at ``audit_at``."""

    system: str
    resource_id: str
    category: str
    state: str
    observations: tuple[Observation, ...]
    contradictions: tuple[str, ...] = ()

    @property
    def evidence_id(self) -> str:
        return self.observations[0].evidence_id if self.observations else ""

    @property
    def identifiers_exposed(self) -> tuple[str, ...]:
        for observation in self.observations:
            if observation.identifiers_exposed:
                return observation.identifiers_exposed
        return ()

    @property
    def is_present(self) -> bool:
        return self.state in {STATE_PRESENT, STATE_RETAINED}


@dataclasses.dataclass(frozen=True, slots=True)
class DataFlowState:
    """A process (sync/export/integration) that can copy or recreate the data."""

    system: str
    resource_id: str
    state: str
    observations: tuple[Observation, ...]
    evidence_id: str = ""
    detail: str = ""

    @property
    def is_active(self) -> bool:
        return self.state == STATE_ACTIVE_FLOW


@dataclasses.dataclass(frozen=True, slots=True)
class RestoreRisk:
    """A backup/restore path that can bring the data back."""

    system: str
    resource_id: str
    state: str
    observations: tuple[Observation, ...]
    evidence_id: str = ""
    detail: str = ""

    @property
    def is_unsafe(self) -> bool:
        return self.state == STATE_ACTIVE_FLOW


@dataclasses.dataclass(frozen=True, slots=True)
class CoverageClaim:
    """Evidence that a store's collection was *covered* for the subject at ``at``.

    A missing row proves nothing on its own (rule 3 of the module docstring): the extract
    must cover the collection, and the subject must be otherwise evidenced in the same
    extract or by a covering readback. When both hold, the covered absence is provable and
    the planner may emit an evidence-backed ``VERIFY_RECORD_ABSENT`` for it (GLM T02-B3).
    """

    evidence_id: str
    system: str
    category: str
    collection: str
    captured_at: _dt.datetime


@dataclasses.dataclass(frozen=True, slots=True)
class StateReport:
    """Everything the state layer can prove, plus everything it cannot."""

    subject_user_id: str
    at: _dt.datetime
    records: tuple[ResourceState, ...]
    flows: tuple[DataFlowState, ...]
    restores: tuple[RestoreRisk, ...]
    unknown_records: tuple[str, ...] = ()
    evidence_artifacts: tuple[str, ...] = ()
    ungrounded_records: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    coverage: tuple[CoverageClaim, ...] = ()
    resource_links: tuple[ResourceLink, ...] = ()

    def record_for(self, resource_id: str) -> ResourceState | None:
        for record in self.records:
            if record.resource_id == resource_id:
                return record
        return None

    def present_records(self) -> tuple[ResourceState, ...]:
        return tuple(record for record in self.records if record.is_present)

    def active_flows(self) -> tuple[DataFlowState, ...]:
        return tuple(flow for flow in self.flows if flow.is_active)

    def unsafe_restores(self) -> tuple[RestoreRisk, ...]:
        return tuple(risk for risk in self.restores if risk.is_unsafe)

    def covered_categories(self) -> frozenset[str]:
        return frozenset(claim.category for claim in self.coverage)

    def decoded_categories(self) -> frozenset[str]:
        """Categories with at least one decided resource outcome.

        ``COPY_DUTY_CATEGORIES`` is what a completeness claim must cover; this is what the
        evidence actually decided, so the planner can name the gap rather than hide it.
        """

        from .state import FLOW_CATEGORIES as _FLOW
        from .state import RESTORE_CATEGORIES as _RESTORE

        decided: set[str] = set()
        for record in self.records:
            if record.state != STATE_UNKNOWN and record.category not in (
                _FLOW | _RESTORE | {"UNKNOWN"}
            ):
                decided.add(record.category)
        for flow in self.flows:
            if flow.state != STATE_UNKNOWN:
                decided.add("DATA_FLOW")
        for risk in self.restores:
            if risk.state != STATE_UNKNOWN:
                decided.add("BACKUP_ARCHIVE")
        return frozenset(decided)


# --------------------------------------------------------------------------------------
# State tokens
# --------------------------------------------------------------------------------------

#: Tokens found in evidence values that assert a state. Keys are matched case-folded.
_STATE_TOKENS: Mapping[str, str] = {
    "deleted": STATE_ABSENT,
    "not_found": STATE_ABSENT,
    "notfound": STATE_ABSENT,
    "absent": STATE_ABSENT,
    "purged": STATE_ABSENT,
    "erased": STATE_ABSENT,
    "removed": STATE_ABSENT,
    "redacted": STATE_REDACTED,
    "anonymized": STATE_ANONYMIZED,
    "anonymised": STATE_ANONYMIZED,
    "identifiable": STATE_PRESENT,
    "found": STATE_PRESENT,
    "present": STATE_PRESENT,
    "active": STATE_ACTIVE_FLOW,
    "enabled": STATE_ACTIVE_FLOW,
    "blocked": STATE_BLOCKED,
    "disabled": STATE_DISABLED,
    "inactive": STATE_DISABLED,
    "retained": STATE_RETAINED,
}

#: Fields whose value is a state claim about the record.
_STATE_FIELDS: tuple[str, ...] = (
    "account_status",
    "status",
    "result",
    "state",
    "record_state",
    "deletion_status",
    "outcome",
)

#: Fields that assert a *disabled* capability (a stopped flow, a blocked restore).
_DISABLED_FIELDS: tuple[str, ...] = (
    "enabled",
    "restore_allowed",
    "download_available",
    "active",
    "delivery_enabled",
)

#: Fields that assert an *active* capability.
_ACTIVE_FIELDS: tuple[str, ...] = (
    "archive_present",
    "sync_enabled",
    "indexing_enabled",
)

#: Fields that carry an explicit *authorization verdict* on a completed operation (a
#: restore/flow decision). The verdict is a state fact with its own polarity: a completed
#: ``restore_authorization_completed decision=deny`` proves the restore is stopped, and an
#: ``allow`` proves the path is still live. It is read only on a *process* category, so a
#: denial word anywhere in a record's text is never mapped onto a record absence
#: (DS-R2-B4).
_VERDICT_FIELDS: tuple[str, ...] = (
    "decision",
    "authorization_decision",
    "restore_decision",
    "verdict",
)

#: Values that mean the requested capability was refused / the process is stopped.
_VERDICT_DENIED: frozenset[str] = frozenset(
    {"deny", "denied", "reject", "rejected", "refuse", "refused", "blocked", "not_allowed"}
)

#: Values that mean the requested capability was granted / the process is live.
_VERDICT_ALLOWED: frozenset[str] = frozenset(
    {"allow", "allowed", "approve", "approved", "grant", "granted", "permit", "permitted"}
)

#: A completed *restore-candidate evaluation* carries its own polarity rather than a
#: ``decision`` verdict: ``eligible=true`` admits the candidate and ``deletion_block=false``
#: records that no deletion block is in force, so an admitted, unblocked candidate at
#: ``audit_at`` is a live restore path (GLM-R3-B1). ``deletion_block=true`` means removal of
#: the subject's data from that backup is already blocked, which is the ``BLOCKED`` end state.
#: These fields are read **only** on a process category and never synthesize a verdict from a
#: bare word on a record row, mirroring the DS-R2-B4 scoping.
_RESTORE_ELIGIBLE_FIELDS: tuple[str, ...] = ("eligible", "restore_eligible", "restore_candidate")
_RESTORE_BLOCK_FIELDS: tuple[str, ...] = ("deletion_block", "delete_block", "deletion_blocked")

#: Fields that mean "the record still exists".
_PRESENCE_FIELDS: tuple[str, ...] = (
    "retention_until",
    "event_code",
    "integrity_seal",
    "record_version",
    "journal_partition",
)

#: Free-text fields whose content can expose an identifier even when no structured
#: identifier column does (a support message quoting an address, a note mentioning a phone).
_FREETEXT_FIELDS: frozenset[str] = frozenset(
    {
        "message_text",
        "message_excerpt",
        "body",
        "text",
        "summary",
        "comment",
        "description",
        "note",
        "content",
        "subject_line",
    }
)

_TRUTHY: frozenset[str] = frozenset({"true", "1", "yes", "on"})
_FALSY: frozenset[str] = frozenset({"false", "0", "no", "off"})

#: Fields that expose a direct identifier and therefore are exactly what REDACT removes.
_DIRECT_IDENTIFIER_FIELDS: tuple[str, ...] = (
    "name",
    "full_name",
    "display_name",
    "customer_name",
    "email",
    "phone",
    "email_hash",
)


#: Direct identifier field names whose explicit null value marks an in-place redaction.
_REDACTION_FIELD_NAMES: tuple[str, ...] = (
    "email",
    "customer_email",
    "requester_email",
    "owner_email",
    "phone",
    "requester_phone",
    "owner_phone",
    "email_hash",
    "name",
    "full_name",
    "display_name",
    "customer_name",
    "requester_name",
)

_NULLISH: frozenset[str] = frozenset({"null", "none", "", "nil", "redacted", "[redacted]", "removed"})


def _is_redacted_in_place(record: EvidenceRecord) -> bool:
    """True when a *reachable* record explicitly nulls its identifier fields.

    Evidence such as ``requester_name=null requester_email=null requester_phone=null``
    on a completed support read means the row still exists with its identifiers removed —
    a redaction, not an absence. At least one identifier field must be present-and-null,
    and nothing may be exposed, so an unrelated record cannot be misread this way.
    """

    fields = record.field_map()
    seen_null = False
    for name in _REDACTION_FIELD_NAMES:
        for key, value in fields.items():
            if key.rsplit(".", 1)[-1] != name:
                continue
            if value.strip().casefold() in _NULLISH:
                seen_null = True
            elif value.strip():
                # A non-null direct identifier would already have been caught by
                # attribution; treat it as not-redacted.
                return False
    # The read must have been a *successful* reach of an existing row.
    event = fields.get("event", "")
    if "completed" not in event.casefold() and "found" not in event.casefold():
        return False
    return seen_null


def read_state_token(record: EvidenceRecord) -> str | None:
    """Return the record's own state assertion, if it makes one.

    State is read from the record's structured fields, in a fixed order, using only
    assertions the record actually makes. This is what lets a ``readback`` log line such
    as ``event=profile_lookup_completed rows=0 http_status=404`` be read as *absent* and
    ``event=connector_config_read_completed enabled=false`` be read as *disabled* — the
    facts are in the field values, not in a single verdict column.

    Presence is read the same way: a *completed* lookup/read whose result proves the row
    exists (``rows>=1``, ``http_status=200``, ``result=hit``, ``integrity_check=passed``)
    is a positive existence fact and is returned as PRESENT (T02-B1). The proof is scoped
    to the record's own operation, so a ``http_status=200`` on a deletion acknowledgement
    (``event`` naming a ``*_completed`` deletion) never proves the copy still exists, and
    a bare capability flag on a *record* category (an account ``active`` column) is not
    turned into an active data flow (T02-NB-4).
    """

    fields = record.field_map()

    # 1. An explicit state word in a status-ish field.
    for field in _STATE_FIELDS:
        value = fields.get(field, "").strip().casefold()
        if not value:
            continue
        # ``account_status=DELETED`` on an account-tombstone record says the *account* is
        # gone, while the tombstone row itself is present with its identifiers removed.
        # ``READ_STATE_FIELDS`` therefore defers that one token to the caller.
        if field == "account_status" and value == "deleted":
            continue
        if value in _STATE_TOKENS:
            return _STATE_TOKENS[value]
        for token, state in _STATE_TOKENS.items():
            if field == "account_status" and token == "deleted":
                continue
            if re.search(rf"\b{re.escape(token)}\b", value):
                return state

    # 2. A row count / HTTP status / result / integrity check on a *completed* operation.
    #    The positive direction is what T02-B1 was missing: a completed read that returns
    #    rows or a 200 is evidence the record exists.
    event = _record_event_name(record)
    completed = "completed" in event or event.endswith("_read") or event == "message_read"
    deletion_operation = any(
        marker in event for marker in ("delet", "purge", "erasure", "erased", "removed")
    )

    for field in ("http_status", "status_code"):
        value = fields.get(field, "").strip()
        if not value.isdigit():
            continue
        code = int(value)
        if code in {404, 410, 451}:
            return STATE_ABSENT
        if code == 200 and completed and not deletion_operation:
            return STATE_PRESENT

    rows = fields.get("rows", "").strip()
    if rows.isdigit():
        if int(rows) == 0:
            # ``rows=0`` only proves absence inside a completed reach of the resource; a
            # bare ``rows=0`` may just be a batch summary.
            return STATE_ABSENT
        if completed and not deletion_operation:
            return STATE_PRESENT

    result = fields.get("result", "").strip().casefold()
    if result == "hit" and completed:
        return STATE_PRESENT
    integrity = fields.get("integrity_check", "").strip().casefold()
    if integrity in {"passed", "pass", "ok"} and completed:
        return STATE_PRESENT

    # 2b. An explicit authorization verdict on a *completed* process operation. A restore
    #     authorization that was denied at ``audit_at`` proves the restore is already blocked;
    #     an allowed one proves the path is still live. The verdict is only meaningful for a
    #     process category — a ``decision`` word on a record row is not a record absence — and
    #     only on a completed line (DS-R2-B4).
    derived = derive_category(record)
    category_name = derived[1] if derived else None
    process_category = category_name in FLOW_CATEGORIES or category_name in RESTORE_CATEGORIES
    if process_category:
        for field in _VERDICT_FIELDS:
            value = fields.get(field, "").strip().casefold()
            if not value:
                continue
            # ``deny``/``allow`` is itself the outcome of the authorization decision, so it
            # does not need a ``*_completed`` event token to be a state fact. A ``*_started``
            # line, however, is only the request: its verdict is not yet decided.
            if _OPERATION_EVENT_RE.search(event) and event.endswith("_started"):
                continue
            if value in _VERDICT_DENIED:
                return STATE_BLOCKED if category_name in RESTORE_CATEGORIES else STATE_DISABLED
            if value in _VERDICT_ALLOWED:
                return STATE_ACTIVE_FLOW

        # 2c. A completed *restore-candidate evaluation* states its own polarity through the
        #     candidate fields. ``eligible=true`` with ``deletion_block=false`` admits the
        #     candidate and records that no deletion block is in force, so the archive is a
        #     live restore path; ``deletion_block=true`` means the subject's data is already
        #     blocked from that restore. The read is scoped to *restore* categories so an
        #     ``eligible`` word on a record row or a flow row never becomes a restore fact.
        if category_name in RESTORE_CATEGORIES and not event.endswith("_started"):
            block = _first_boolean(fields, _RESTORE_BLOCK_FIELDS)
            if block is True:
                return STATE_BLOCKED
            eligible = _first_boolean(fields, _RESTORE_ELIGIBLE_FIELDS)
            if eligible is True and block is not True:
                # An admitted candidate with no stated block is an unblocked restore path.
                return STATE_ACTIVE_FLOW

    # 3. A capability flag. A *record* category keeps the row-existence reading; only a
    #    process category turns a capability flag into ACTIVE/DISABLED. Whether the record
    #    is a process is decided from the record itself, never from a caller's guess.
    for field in _DISABLED_FIELDS:
        value = fields.get(field, "").strip().casefold()
        if value not in _FALSY and value not in _TRUTHY:
            continue
        if field == "restore_allowed":
            # A blocked restore is its own state: policy remediates it with BLOCK_RESTORE,
            # not DISABLE_DATA_FLOW, so the field decides which.
            return STATE_BLOCKED if value in _FALSY else STATE_ACTIVE_FLOW
        if process_category:
            return STATE_DISABLED if value in _FALSY else STATE_ACTIVE_FLOW
        # A record category: a false capability flag means the row is still there but the
        # capability is off; a true flag proves the row exists. Neither is a data flow.
        return STATE_RETAINED if category_name in RETAIN_CATEGORIES else STATE_PRESENT
    for field in _ACTIVE_FIELDS:
        value = fields.get(field, "").strip().casefold()
        if value in _TRUTHY:
            return STATE_ACTIVE_FLOW if process_category else STATE_PRESENT
        if value in _FALSY:
            return STATE_ABSENT

    # 4. A retention/presence field proves the record still exists — but only for a
    #    *record* category. ``event_code`` on a support/audit/deletion event names an
    #    operation, and a capability config names a process; neither is a stored copy of
    #    the subject, so presence is not asserted for a process row or an operation event.
    if any(fields.get(field, "").strip() for field in _PRESENCE_FIELDS):
        if process_category:
            return None
        if _OPERATION_EVENT_RE.search(event):
            return None
        return STATE_PRESENT

    return None


#: Field names that hold a *query input* rather than a stored identifier. A lookup that
#: targeted the subject's address does not mean the record still holds it; only the
#: result of the lookup does.
_QUERY_INPUT_FIELDS: frozenset[str] = frozenset(
    {"lookup_key", "lookup_value", "match_key", "matched_value", "subject_selector", "query"}
)

#: Field names that hold a *stable* reference which policy permits a retained record to
#: keep. Their presence is never treated as prohibited exposure on its own.
_STABLE_REFERENCE_FIELDS: frozenset[str] = frozenset(
    {"subject_reference", "subject_ref", "subject_key", "customer_reference", "user_id"}
)


def direct_identifiers_present(
    record: EvidenceRecord,
    subject: Subject,
    index: IdentityIndex,
    at: _dt.datetime,
) -> tuple[str, ...]:
    """Return the subject's direct identifiers that this record still exposes.

    A record "exposes" an identifier when a field carries one of the subject's *own*
    values (current or historical at ``at``). T01's identifier pairs already encode this,
    so the check is a set intersection against the normalised identifier sets — no raw
    tuple counting (T01-NB-01 guard).

    Query-input fields (``lookup_key`` and friends) are excluded: a lookup that *asked*
    about the subject's address is not a stored copy of it.
    """

    subject_sets = subject.identifier_sets(at)
    exposed: set[str] = set()
    query_only = _query_input_values(record)
    for kind, value in record.identifiers:
        if kind in {"email", "phone", "email_hash"} and value in subject_sets.get(kind, frozenset()):
            if (kind, value) in query_only and not _value_appears_elsewhere(record, kind, value):
                continue
            exposed.add(f"{kind}={value}")
    # A visible name is a direct identifier too, and a name is not an identity claim, so
    # it is checked against the snapshot directly.
    identity = index.identity(subject.user_id)
    for field in _DIRECT_IDENTIFIER_FIELDS:
        value = record.field(field)
        if not value:
            continue
        if field in {"name", "full_name", "display_name", "customer_name"}:
            if value.strip().casefold() == (identity.name or "").strip().casefold():
                exposed.add(f"name={value.strip().casefold()}")
        else:
            classified_kind = {"email": "email", "phone": "phone", "email_hash": "email_hash"}.get(field)
            if classified_kind and normalise_identifier(classified_kind, value) in subject_sets.get(
                classified_kind, frozenset()
            ):
                exposed.add(f"{classified_kind}={normalise_identifier(classified_kind, value)}")
    # Free text is not exempt: a support message that still quotes the subject's address
    # exposes it just as plainly as a structured column would. Mentions are matched at
    # token boundaries so a neighbouring user's address cannot be misread as this one.
    for field_name, value in record.fields:
        leaf = field_name.rsplit(".", 1)[-1]
        if leaf not in _FREETEXT_FIELDS or not value:
            continue
        for kind, values in subject_sets.items():
            for candidate in values:
                if mentions_identifier(value, kind, candidate):
                    exposed.add(f"{kind}={candidate}")
    # Identifier claims that came from a query-input field only must be dropped: they prove
    # the lookup ran, not that the record holds the value.
    return tuple(sorted(exposed))


#: Text that a system writes in place of a value it removed.
_REDACTION_SENTINELS: tuple[str, ...] = (
    "[redacted]",
    "<redacted>",
    "redacted",
    "[removed]",
    "***",
)


def free_text_is_redacted(record: EvidenceRecord) -> bool:
    """True when a record's free text has been replaced by an explicit redaction marker."""

    for field_name, value in record.fields:
        if field_name.rsplit(".", 1)[-1] not in _FREETEXT_FIELDS:
            continue
        folded = value.strip().casefold()
        if folded and any(sentinel in folded for sentinel in _REDACTION_SENTINELS):
            return True
    return False


# --------------------------------------------------------------------------------------
# Contradictory stable-user guard (T01-NB-02)
# --------------------------------------------------------------------------------------


def foreign_stable_reference(
    record: EvidenceRecord,
    subject: Subject,
    index: IdentityIndex,
) -> str | None:
    """Return a foreign ``user_id`` this record asserts, or ``None``.

    T01's ``owners_of`` does not index ``user_id``, so a *resource-linked* record whose
    only identity claim is another known subject's stable ``user_id`` can slip past the
    contamination filter. T02 must not trust such a record. The check is deliberately
    independent of T01's internals: scan the record's own ``user_id``-kind claims and
    reject any that names a known subject other than this one.
    """

    subject_user_id = subject.user_id.casefold()
    for kind, value in record.identifiers:
        if kind != "user_id":
            continue
        folded = value.casefold()
        if folded == subject_user_id:
            continue
        if folded in index_user_ids(index):
            return value
    # Structured link fields can carry a user id even when it was not classified.
    for key, value in record.fields:
        if key.rsplit(".", 1)[-1] not in {"subject_reference", "subject_ref", "subject_key", "user_id", "customer_reference"}:
            continue
        folded = value.strip().casefold()
        if folded.startswith("user_") and folded != subject_user_id and folded in index_user_ids(index):
            return value
    return None


def index_user_ids(index: IdentityIndex) -> frozenset[str]:
    """The known subject ids, folded, as a frozenset (cached on the index object)."""

    cached = getattr(index, "_ghostwatch_user_ids", None)
    if cached is None:
        cached = frozenset(user_id.casefold() for user_id in index.user_ids)
        try:
            object.__setattr__(index, "_ghostwatch_user_ids", cached)
        except (AttributeError, TypeError):  # pragma: no cover - defensive
            pass
    return cached


def index_identifier_tokens(index: IdentityIndex, kind: str) -> frozenset[str]:
    """Every normalised value of ``kind`` across the whole identity snapshot.

    Used only as a *foreign-conflict* guard: a capability row that names any known subject's
    identifier other than this subject's is refused rather than propagated (DS T02R3-B1). The
    values come from the reviewed :class:`IdentityIndex` public API, so no T01 file changes.
    """

    cache_key = f"_ghostwatch_tokens_{kind}"
    cached = getattr(index, cache_key, None)
    if cached is None:
        # A far-future ``at`` returns every identifier each subject ever used, which is exactly
        # the "any known subject" set the conflict guard needs.
        horizon = _dt.datetime.max.replace(tzinfo=UTC)
        values: set[str] = set()
        for user_id in index.user_ids:
            for value in index.identifier_sets(user_id, horizon).get(kind, frozenset()):
                if value:
                    values.add(value)
        cached = frozenset(values)
        try:
            object.__setattr__(index, cache_key, cached)
        except (AttributeError, TypeError):  # pragma: no cover - defensive
            pass
    return cached


# --------------------------------------------------------------------------------------
# Token-bounded mention matching (T01-NB-G3)
# --------------------------------------------------------------------------------------


def _query_input_values(record: EvidenceRecord) -> frozenset[tuple[str, str]]:
    """Identifier claims that came only from a query-input field."""

    values: set[tuple[str, str]] = set()
    for name, value in record.fields:
        if name.rsplit(".", 1)[-1] not in _QUERY_INPUT_FIELDS:
            continue
        classified = _classify_for_query(value)
        if classified is not None:
            values.add(classified)
    return frozenset(values)


def _classify_for_query(value: str) -> tuple[str, str] | None:
    from .evidence import classify_value

    classified = classify_value(value)
    if classified is None:
        return None
    kind, normalised = classified
    return (kind, normalised) if kind in {"email", "phone", "email_hash", "user_id"} else None


def _value_appears_elsewhere(record: EvidenceRecord, kind: str, value: str) -> bool:
    """True when ``value`` also appears in a non-query, non-link field of the record."""

    for name, raw in record.fields:
        leaf = name.rsplit(".", 1)[-1]
        if leaf in _QUERY_INPUT_FIELDS or leaf in _STABLE_REFERENCE_FIELDS:
            continue
        classified = _classify_for_query(raw)
        if classified == (kind, value):
            return True
    return False


def mentions_identifier(text: str, kind: str, value: str) -> bool:
    """True when ``text`` mentions ``value`` as a whole token of ``kind``.

    Raw substring matching is unsafe: ``user_10`` is a substring of ``user_100``. Emails
    must match as exact tokens, phones on a digit run with a boundary, and user ids on a
    word boundary that is not followed by another identifier character.
    """

    if not text or not value:
        return False
    folded = text.casefold()
    target = value.casefold()
    if kind == "user_id":
        return re.search(rf"(?<![0-9a-z_]){re.escape(target)}(?![0-9a-z_])", folded) is not None
    if kind == "email":
        # The address may legitimately be followed by sentence punctuation, so a trailing
        # ``.``/``,``/``)`` ends the token. A ``.`` that continues into another label
        # (``ada@example.com.evil``) extends the address and is not this value.
        pattern = rf"(?<![0-9a-z._%+-]){re.escape(target)}(?![0-9a-z_%+-])(?!\.[0-9a-z])"
        return re.search(pattern, folded) is not None
    if kind == "email_hash":
        return re.search(rf"(?<![0-9a-f]){re.escape(target)}(?![0-9a-f])", folded) is not None
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        if not digits:
            return False
        haystack_digits = re.sub(r"\D", "", text)
        for match in re.finditer(re.escape(digits), haystack_digits):
            before = haystack_digits[match.start() - 1 : match.start()]
            after = haystack_digits[match.end() : match.end() + 1]
            # Meaningful boundary: a phone is not part of a longer digit run. Compare
            # single characters explicitly: ``"" in "0123456789"`` is true in Python, so an
            # ``in`` test would wrongly reject a phone at the start or end of the text.
            if not before.isdigit() and not after.isdigit():
                return True
        return False
    if kind == "resource_id":
        return re.search(rf"(?<![0-9a-z_]){re.escape(target)}(?![0-9a-z_])", folded) is not None
    return target in folded


# --------------------------------------------------------------------------------------
# Handover-style state tables (T01 leaves these as 0 records)
# --------------------------------------------------------------------------------------

#: ``<ts> | <system> | <resource> | <record_type> | <STATE> | <subject>``. The handover
#: ``.txt`` export writes a seven-column row (the subject may itself contain ``|``), and
#: T01's text extractor only recognises the six-column variant, so the state layer reads
#: the shape directly rather than depending on a reviewed extractor being widened.
_HANDOVER_ROW_RE = re.compile(
    r"^\s*[-*]?\s*"
    r"(?P<observed>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}Z)\s*\|\s*"
    r"(?P<system>[^|]+?)\s*\|\s*"
    r"(?P<resource>[^|]+?)\s*\|\s*"
    r"(?P<type>[^|]+?)\s*\|\s*"
    r"(?P<state>[A-Za-z_ ]+?)\s*\|\s*"
    r"(?P<subject>.+?)\s*$"
)

_HANDOVER_SNAPSHOT_RE = re.compile(r"^Snapshot:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)

_RESOURCE_TOKEN_RE = re.compile(
    r"\b(?:account|search|analytics|support|export|backup|audit_record|tombstone|"
    r"marketing|cache|connector|telemetry|data_flow|legal_hold|email_delivery)_[0-9A-Za-z]{1,10}\b"
)


@dataclasses.dataclass(frozen=True, slots=True)
class HandoverRow:
    """One ``system | resource | type | state | subject`` row from a handover export."""

    observed_at: _dt.datetime
    system: str
    resource_id: str
    record_type: str
    state: str
    subject_text: str
    evidence_id: str


def parse_handover_rows(
    text: str,
    *,
    evidence_id: str,
    snapshot_at: _dt.datetime | None,
) -> tuple[HandoverRow, ...]:
    """Parse state rows out of a handover/diagnostic text export.

    Rows whose subject column is ``no direct identifier`` are kept: they prove that a
    resource exists without exposing the subject, which is exactly the anonymized state.
    """

    rows: list[HandoverRow] = []
    for line in text.splitlines():
        match = _HANDOVER_ROW_RE.match(line)
        if match is None:
            continue
        try:
            observed = _parse_state_timestamp(match.group("observed"))
        except ValueError:
            observed = snapshot_at
        if observed is None:
            continue
        rows.append(
            HandoverRow(
                observed_at=observed,
                system=match.group("system").strip(),
                resource_id=match.group("resource").strip(),
                record_type=match.group("type").strip().upper(),
                state=match.group("state").strip().upper(),
                subject_text=match.group("subject").strip(),
                evidence_id=evidence_id,
            )
        )
    return tuple(rows)


def _parse_state_timestamp(raw: str) -> _dt.datetime:
    text = raw.strip().replace(" ", "T", 1) if " " in raw.strip() else raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    stamp = _dt.datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        raise ValueError(f"naive timestamp in evidence: {raw!r}")
    return stamp.astimezone(UTC)


def _row_observes_subject(row: HandoverRow, subject: Subject, index: IdentityIndex, at: _dt.datetime) -> bool:
    """True when the row's subject column names this subject (email, phone, hash, user id).

    ``no direct identifier`` rows are handled by the caller: they are only attributable to
    the subject through the resource id, never through the text.
    """

    text = row.subject_text
    if not text or "no direct identifier" in text.casefold():
        return False
    folded = text.casefold().replace(" ", "")
    sets = subject.identifier_sets(at)
    if folded in sets.get("email", frozenset()):
        return True
    digits = re.sub(r"\D", "", text)
    if digits and digits in sets.get("phone", frozenset()):
        return True
    if folded in sets.get("email_hash", frozenset()):
        return True
    if folded == subject.user_id.casefold():
        return True
    # OCR-style variant: allow a case/space-insensitive email match.
    for email in sets.get("email", frozenset()):
        if email.replace(" ", "") == folded:
            return True
    return False


# --------------------------------------------------------------------------------------
# Reconstruction
# --------------------------------------------------------------------------------------


def _records_for_subject(
    evidence: SubjectEvidence,
    subject: Subject,
    index: IdentityIndex,
) -> tuple[EvidenceMatch, ...]:
    """Drop links whose only claim is another known subject's stable id (T01-NB-02)."""

    kept: list[EvidenceMatch] = []
    for match in evidence.matches:
        if match.match_kind == "resource_link" and foreign_stable_reference(
            match.record, subject, index
        ):
            continue
        kept.append(match)
    return tuple(kept)


def resource_scoped_matches(
    library,
    subject: Subject,
    index: IdentityIndex,
    *,
    at: _dt.datetime,
    resource_ids: Iterable[str],
    evidence: SubjectEvidence | None = None,
) -> tuple[EvidenceMatch, ...]:
    """Retrieve records that name one of the subject's resources but carry no identity claim.

    A readback log pair writes ``…_started`` with the subject's ``lookup_key`` and
    ``…_completed`` with only ``resource_id``. T01's identity-based retrieval attributes the
    first line and never the second, so the state layer fetches the completion lines itself
    — filtered by ``at`` and refused when they name another known subject.

    JSON-lines logs that T01's ``key=value`` extractor produced no records for are parsed
    here too, so a diagnostic export is not invisible to the audit. When ``evidence`` is
    supplied, resource discovery is additionally seeded from the subject's
    ``LINK_RESOURCE_IDENTITY`` catalogue rows and from the trace siblings of lines that name
    the subject.
    """

    wanted = {value.casefold() for value in resource_ids if value}
    matches: list[EvidenceMatch] = []
    subject_sets = subject.identifier_sets(at)
    subject_user_key = subject.user_id.casefold()

    def names_subject(record: EvidenceRecord) -> bool:
        for kind, value in record.identifiers:
            if kind == "user_id" and value.casefold() == subject_user_key:
                return True
            if kind in {"email", "phone", "email_hash"} and value in subject_sets.get(kind, frozenset()):
                return True
        for name, value in record.fields:
            if name.rsplit(".", 1)[-1] not in _QUERY_INPUT_FIELDS:
                continue
            classified = _classify_for_query(value)
            if classified is None:
                continue
            kind, normalised = classified
            if kind == "user_id" and normalised == subject_user_key:
                return True
            if kind in {"email", "phone", "email_hash"} and normalised in subject_sets.get(kind, frozenset()):
                return True
        return False

    def resource_values(record: EvidenceRecord) -> set[str]:
        values = {value for kind, value in record.identifiers if kind == "resource_id"}
        if record.resource_id:
            classified = _classify_resource(record.resource_id)
            if classified:
                values.add(classified)
        return values

    # A JSON-lines diagnostic names the subject with a *lookup key* on one line and the
    # resource on its completion line. Discovery therefore runs in two passes: first collect
    # the resources the subject is named beside, then attribute the records that name those
    # resources. Everything is still filtered by ``at`` and the foreign-reference guard.
    # Collect every candidate record once: T01's extracted records plus the JSON-lines
    # diagnostic lines T01's ``key=value`` extractor cannot see. Discovery then runs in three
    # passes over one pool: seed the subject's resources, follow trace identifiers, then
    # attribute.
    candidates: list[EvidenceRecord] = []
    seen_records: set[tuple[str, str]] = set()
    for document in library.documents(strict=False):
        if document is None or document.evidence.captured_at > at:
            continue
        for record in document.records:
            key = (record.evidence_id, record.locator)
            if key in seen_records:
                continue
            seen_records.add(key)
            candidates.append(record)
    for record in json_log_records(library, at=at):
        key = (record.evidence_id, record.locator)
        if key in seen_records:
            continue
        seen_records.add(key)
        candidates.append(record)

    def usable(record: EvidenceRecord) -> bool:
        if record.captured_at > at:
            return False
        if record.observed_at is not None and record.observed_at > at:
            return False
        return not foreign_stable_reference(record, subject, index)

    def seed(records):
        for record in records:
            if usable(record) and names_subject(record):
                wanted.update(resource_values(record))

    seed(candidates)

    # A ``*_started`` line names the subject with its lookup key, and its ``*_completed``
    # sibling names the resource but carries no identity claim, so the two are joined by the
    # shared operation name (``index_query_`` -> ``search_1``). The join is scoped to a
    # same-service started/completed pair inside the window and never crosses subjects.
    for record in _operation_pair_completions(
        candidates, wanted, names_subject, at=at, subject=subject, index=index
    ):
        if usable(record):
            wanted.update(resource_values(record))

    # A ``LINK_RESOURCE_IDENTITY`` catalogue row names a resource that belongs to the
    # subject even when no record carries both. Seeding discovery from it is what makes a
    # screenshot-only or archive-only resource reachable at all (GLM T02-B2).
    if evidence is not None:
        for link in linked_resource_identities(evidence, subject, index, at):
            classified = _classify_resource(link.resource_id)
            if classified:
                wanted.add(classified)

    # Follow the shared ``requestId``/``trace_id`` from any line naming the subject (or a
    # resource already known to be the subject's) to its sibling lines, so a completion line
    # that carries the real resource id and state is reached instead of being left as an
    # unresolved ``*_started`` locator (T02-NB-03). The join is scoped to one trace id and to
    # in-window lines, and is never a global join across unrelated requests.
    candidates = _expand_by_trace(candidates, wanted, names_subject, at=at)
    seed(candidates)
    # A trace sibling that names the subject's request carries the real resource identity, so
    # its resource id joins the wanted set even though the line itself is not an identity
    # claim (evidence_25: ``tr-7098227`` -> ``backup_3250``).
    for record in _trace_siblings(candidates, wanted, names_subject, at=at):
        if usable(record):
            wanted.update(resource_values(record))

    def consider(record: EvidenceRecord) -> None:
        if not usable(record):
            return
        shared = resource_values(record) & wanted
        if shared or names_subject(record):
            matches.append(
                EvidenceMatch(
                    record=record,
                    match_kind="resource_link" if shared else "email",
                    matched_fields=("resource_id",) if shared else ("lookup_key",),
                    matched_values=tuple(sorted(shared)) or tuple(sorted(record.identifier_values("email"))),
                )
            )

    for record in candidates:
        consider(record)

    matches.sort(key=lambda item: (item.record.evidence_id, item.record.locator))
    return tuple(matches)


def _classify_resource(value: str) -> str | None:
    from .evidence import classify_value

    classified = classify_value(value)
    if classified is None or classified[0] != "resource_id":
        return None
    return classified[1]


#: Recover a store identity that a nested wrapper carries as a sibling of the subject's
#: sub-object, e.g. ``{"resource_id": "account_5375", "profile": {...}}``. The extraction
#: path itself is not a resource, so it is never used as one (DS T02-B2).
_STORE_IDENTITY_RE = re.compile(
    r"\bresource_id\b[\"'\s:=]+("
    r"(?:account|search|analytics|support|export|backup|audit_record|tombstone|"
    r"marketing|cache|connector|telemetry|data_flow)_[0-9A-Za-z]{1,10})"
)


def resolve_resource_identity(
    record: EvidenceRecord,
    *,
    ancestry: Mapping[str, str] | None = None,
) -> str:
    """Return the record's real ``resource_id``, never an extraction locator.

    Some exports nest a subject's data under a wrapper that carries the store identity as a
    sibling (``{"resource_id": "account_5375", "profile": {...}}``). T01 emits the nested
    object as its own record, so the store identity has to be recovered from grounded data:

    1. the classified value of a ``resource_id``/``source_resource_id``-shaped field;
    2. the record's own declared ``resource_id``;
    3. a ``resource_id`` visible in the record's own text (the wrapper's sibling);
    4. **grounded JSON ancestry** — the nearest ancestor object in the same document that
       declares a ``resource_id`` (``ancestry`` maps an extraction path to the store identity
       its nearest ``resource_id``-bearing ancestor carries). A nested ``profile``/``document``
       sub-object resolves to the *same* store row as its wrapper, so the copy is deduplicated
       instead of duplicated (DS-R2-B1).

    When nothing grounds a store identity the function returns ``""``: an ungrounded nested
    object is a diagnostic, never a fabricated ``<category>_copy`` resource (DS-R2-B1/B3).
    """

    from .evidence import classify_value

    # 1. A classified resource id carried in any resource-shaped field.
    for name, value in record.fields:
        if name.rsplit(".", 1)[-1] not in {"resource_id", "source_resource_id", "archive_key", "object_key"}:
            continue
        classified = classify_value(value)
        if classified is not None and classified[0] == "resource_id":
            return classified[1]

    # 2. The record's own declared resource id.
    if record.resource_id:
        classified = classify_value(record.resource_id)
        if classified is not None and classified[0] == "resource_id":
            return classified[1]

    # 3. A store identity visible in the record's own text (the nested wrapper's sibling).
    text = record.text or ""
    if text:
        match = _STORE_IDENTITY_RE.search(text)
        if match:
            return match.group(1).casefold()

    # 4. Grounded JSON ancestry: the nearest enclosing object that declares a resource id.
    if ancestry:
        inherited = ancestry.get(_locator_key(record))
        if inherited:
            return inherited

    # 5. No grounded store identity. Returning an empty string lets the caller report the
    #    record as a blocking diagnostic instead of inventing a ``<category>_copy`` resource.
    return ""


def _locator_key(record: EvidenceRecord) -> str:
    return f"{record.evidence_id}|{record.locator}"


#: Extraction-path separators used by T01's JSON walker: ``$/a/b[3]/c``.
_JSON_PATH_INDEX_RE = re.compile(r"\[(\d+)\]$")


def build_ancestry_map(library, *, at: _dt.datetime) -> Mapping[str, str]:
    """Map every JSON record's extraction path to its nearest ``resource_id`` ancestor.

    The map is built by walking each in-window JSON document the same way T01 does, so a
    nested sub-object (``.../profile_lookups[1]/profile``) inherits the store identity its
    wrapper (``.../profile_lookups[1]``) declares. It is grounded in the document's own bytes
    and holds no case ids, so it adds no fabrication risk (DS-R2-B1).
    """

    import json as _json

    ancestry: dict[str, str] = {}
    if library is None:
        return ancestry
    for document in library.documents(strict=False):
        if document is None or document.kind != "json":
            continue
        if document.evidence.captured_at > at:
            continue
        try:
            payload = _json.loads(document.text)
        except _json.JSONDecodeError:  # pragma: no cover - extraction already validated it
            continue
        file_id = document.evidence.file_id
        stack: list[str | None] = []

        def walk(node, path: str) -> None:
            inherited = next((value for value in reversed(stack) if value), None)
            own = None
            if isinstance(node, dict):
                candidate = node.get("resource_id")
                if isinstance(candidate, str) and candidate.strip():
                    classified = _classify_resource(candidate.strip())
                    if classified:
                        own = classified
            if own or inherited:
                resolved = own or inherited
                if resolved:
                    ancestry[f"{file_id}|json:{path}"] = resolved
            stack.append(own)
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, (dict, list)):
                        walk(value, f"{path}/{key}")
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    walk(item, f"{path}[{index}]")
            stack.pop()

        walk(payload, "$")
    return ancestry


def derive_coverage(
    library,
    subject: Subject,
    index: IdentityIndex,
    *,
    at: _dt.datetime,
    matches: Sequence[EvidenceMatch],
) -> tuple[CoverageClaim, ...]:
    """Find the stores a snapshot *provably* covers for the subject at ``at``.

    A store is covered only when the evidence establishes that the section is a **complete
    listing of the collection for the audited population**. Merely containing a collection
    section — and naming the subject somewhere in the export — does not establish a complete
    scoped listing: the supplied multi-subject extracts are samples (a 1-row
    ``customer_profiles`` section next to 20-row ``security_audit_events``), so a missing
    subject row proves nothing and must not be turned into an absence claim (DS-R2-B2).

    Two sources can establish completeness, both explicit and inspectable:

    * an exporter-declared completeness marker on the section (``complete``/``is_complete``
      true, or ``truncated``/``partial`` false) — no supplied file carries one, so this path
      is exercised by fixtures; and
    * a per-subject successful **zero-hit lookup**, which proves that lookup's resource
      absence. Those are read as ``ABSENT`` observations by :func:`read_state_token`, not
      re-derived here, so a covered claim is never minted from a partial extract.

    The disagreement between the r1 reviewers is resolved by the participant metadata itself:
    the ``snapshot_scope`` table lists only ``origin_system``/``captured_at`` and declares no
    complete population, and no export carries a completeness marker, so partial extracts are
    not treated as proof of absence.
    """

    _ = index  # kept for call-site symmetry; coverage is derived from the snapshot itself
    subject_email_tokens = {
        value for _kind, values in subject.identifier_sets(at).items() for value in values
    }
    subject_user_key = subject.user_id.casefold()

    # Files in scope: those already attributed to the subject at ``at``.
    files_in_scope = {match.record.evidence_id for match in matches if match.record.captured_at <= at}
    if not files_in_scope:
        return ()

    claims: list[CoverageClaim] = []
    for document in library.documents(strict=False):
        file_id = document.evidence.file_id
        if file_id not in files_in_scope:
            continue
        captured = document.evidence.captured_at
        if captured > at:
            continue
        # Only sections the document declares complete are coverage. The declaration must name
        # the collection it covers, so a complete listing of one collection never becomes
        # coverage for a sibling collection in the same file (DS-R2-NB-2).
        declared = _declared_complete_collections(document)
        if not declared:
            continue
        names_subject = False
        for record in document.records:
            for kind, value in record.identifiers:
                if kind == "user_id" and value.casefold() == subject_user_key:
                    names_subject = True
                elif kind in {"email", "phone", "email_hash"} and value in subject_email_tokens:
                    names_subject = True
        if not names_subject:
            continue
        for collection in sorted(declared):
            mapped = COVERING_COLLECTIONS.get(collection)
            if mapped is None:
                continue
            system, category = mapped
            claims.append(
                CoverageClaim(
                    evidence_id=file_id,
                    system=system,
                    category=category,
                    collection=collection,
                    captured_at=captured,
                )
            )
    claims.sort(key=lambda item: (item.evidence_id, item.category, item.collection))
    return tuple(claims)


#: Keys an exporter uses to declare a section is a complete listing of its collection.
_COMPLETENESS_TRUE_KEYS: tuple[str, ...] = (
    "complete",
    "is_complete",
    "completeness_verified",
    "full_extract",
    "all_records_included",
)
#: Keys an exporter uses to declare a section is *partial* (truncated / a sample).
_PARTIAL_KEYS: tuple[str, ...] = ("truncated", "partial", "sample", "sampled", "is_partial")


def _declared_complete_collections(document) -> frozenset[str]:
    """The collections this document explicitly declares as a complete listing.

    A marker is honoured only when it is present, truthy (or a ``partial`` flag that is
    falsey) and co-located with the collection it describes, so a convenient row count or a
    sibling section can never be promoted to completeness. Returns an empty set when the
    document makes no declaration — which is the case for every supplied snapshot.
    """

    import json as _json

    if document.kind != "json":
        return frozenset()
    try:
        payload = _json.loads(document.text)
    except _json.JSONDecodeError:  # pragma: no cover - extraction already validated it
        return frozenset()

    complete: set[str] = set()

    def is_truthy(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().casefold() in _TRUTHY

    def is_falsey(value) -> bool:
        if isinstance(value, bool):
            return not value
        return str(value).strip().casefold() in _FALSY

    def scan(node) -> None:
        if isinstance(node, dict):
            collection = node.get("collection") or node.get("collection_name")
            if isinstance(collection, str) and collection.strip():
                name = collection.strip().casefold()
                declared = False
                for key in _COMPLETENESS_TRUE_KEYS:
                    if key in node and is_truthy(node[key]):
                        declared = True
                for key in _PARTIAL_KEYS:
                    if key in node and is_falsey(node[key]):
                        declared = True
                if declared:
                    complete.add(name)
            for value in node.values():
                scan(value)
        elif isinstance(node, list):
            for item in node:
                scan(item)

    scan(payload)
    return frozenset(complete)


#: A JSON-lines log line: ``<ISO timestamp> {json object}``. Several supplied diagnostic
#: logs use this shape, and T01's ``key=value`` log extractor produces no records for them.
_JSON_LINE_RE = re.compile(r"^(?P<ts>\S+)\s+(?P<body>\{.*\})\s*$")

#: JSON-lines fields that name the emitting component rather than the subject's data. Their
#: values can look like identifiers (``search_service`` matches the resource-id pattern), so
#: they must never become resource claims.
_NON_IDENTITY_LOG_FIELDS: frozenset[str] = frozenset(
    {"service", "logger", "pod", "instance", "region", "severity", "cache", "index", "pool", "route"}
)

#: Component names that are *not* subject resources even though they match an id pattern.
_NAMED_COMPONENTS: frozenset[str] = frozenset(
    {
        "search_service",
        "account_service",
        "analytics_platform",
        "support_platform",
        "backup_service",
        "integration_service",
        "security_service",
        "export_service",
        "identity_service",
        "marketing_platform",
        "legal_service",
        "cache_service",
        "email_delivery_service",
        "connection_acquired",
        "dependency_retry",
        "dependency_recovered",
        "connector_heartbeat",
        "restore_policy_check",
        "profile_lookup",
        "index_query",
        "message_scan",
        "audit_record_query",
        "connector_config_read",
    }
)


def json_log_records(library, *, at: _dt.datetime):
    """Yield ``EvidenceRecord`` objects parsed from JSON-lines log files.

    Only files that T01 could not turn into records are parsed, so the reviewed extraction
    is never duplicated or overridden. Each line becomes one record whose ``fields`` are the
    JSON keys, which is what lets the state reader see ``rows``/``http_status``/``enabled``
    facts that the ``key=value`` extractor misses.

    A file T01 *did* extract is deliberately left to T01: re-parsing it here would add the
    operation/telemetry lines the reviewed extractor intentionally did not attribute as
    records, which would widen record state beyond the accepted extraction. A lone
    ``*_completed`` line that T01 extracted but could not pair is instead reached through
    :func:`resource_scoped_matches`' trace/operation pairing over T01's own records (DS NB-2).
    """

    from .evidence import (
        EvidenceError,
        EvidenceRecord,
        classify_value,
        extract_identifiers,
    )
    from .ingest import clean_text, parse_timestamp

    for entry in library.manifest:
        if not entry.file_path.lower().endswith(".log"):
            continue
        if entry.captured_at > at:
            continue
        document = library.document(entry.file_id, strict=False)
        if document is None or document.records:
            continue
        for line_no, line in enumerate(document.text.splitlines(), start=1):
            match = _JSON_LINE_RE.match(line.strip())
            if match is None:
                continue
            try:
                payload = json.loads(match.group("body"))
            except json.JSONDecodeError:  # pragma: no cover - defensive
                continue
            if not isinstance(payload, dict):
                continue
            observed: _dt.datetime | None = None
            try:
                observed = parse_timestamp(
                    match.group("ts"), field="observed_at", source=f"{entry.file_id}:{line_no}"
                )
            except EvidenceError:
                observed = None
            if observed is not None and observed > at:
                continue
            fields = tuple(
                sorted(
                    (str(key), clean_text(str(value)))
                    for key, value in payload.items()
                    if value is not None and str(value).strip()
                )
            )
            identifiers: set[tuple[str, str]] = set()
            for key, value in fields:
                leaf = key.rsplit(".", 1)[-1]
                if leaf in _NON_IDENTITY_LOG_FIELDS:
                    # ``service``/``logger``/``pod``/``instance`` values look like identifiers
                    # (``search_service``) but name the emitting component, not a resource the
                    # subject owns. Classifying them would seed discovery with a bogus
                    # resource and merge unrelated requests.
                    continue
                classified = classify_value(value)
                if classified is not None:
                    identifiers.add(classified)
                elif leaf in {"subject_key", "lookup_key", "match_key", "subject_ref", "customer_reference"}:
                    for kind, normalised in extract_identifiers(value):
                        identifiers.add((kind, normalised))
            resource_id = clean_text(str(payload.get("resource_id") or "")) or None
            if resource_id:
                classified = classify_value(resource_id)
                if classified is not None:
                    identifiers.add(classified)
            identifiers = {
                (kind, value)
                for kind, value in identifiers
                if not (kind == "resource_id" and value in _NAMED_COMPONENTS)
            }
            if not identifiers and resource_id is None:
                continue
            yield EvidenceRecord(
                evidence_id=entry.file_id,
                dataset_path=entry.file_path,
                origin=entry.origin,
                captured_at=entry.captured_at,
                observed_at=observed,
                system=clean_text(str(payload.get("service") or payload.get("logger") or "")) or None,
                collection=None,
                container="log",
                record_type=clean_text(str(payload.get("record_type") or "")) or None,
                resource_id=resource_id,
                fields=fields,
                identifiers=tuple(
                    sorted(identifiers, key=lambda item: (item[0], item[1]))
                ),
                locator=f"line:{line_no}",
            )


_TRACE_FIELDS = ("requestId", "trace_id", "traceId", "request_id")

#: Trace ids that appear as their own ``|``-delimited column in a structured log line, e.g.
#: ``2026-02-03T05:51:23Z | DEBUG | security_service | tr-4612767 | audit_record_query_started
#: | ...``. T01's ``key=value`` tokeniser does not capture them, so the state layer reads the
#: trace column itself rather than positional-joining interleaved requests (DS-R2-NB-3).
_BARE_TRACE_RE = re.compile(r"\btr-[A-Za-z0-9]+(-\d+)?\b")


def _record_trace_ids(record: EvidenceRecord) -> set[str]:
    values: set[str] = set()
    for name, value in record.fields:
        if name.rsplit(".", 1)[-1] in _TRACE_FIELDS and value.strip():
            values.add(value.strip())
    if not values and record.text:
        values |= {match.group(0) for match in _BARE_TRACE_RE.finditer(record.text)}
    return values


def _seed_trace_ids(records, wanted, names_subject, at) -> set[str]:
    seeds: set[str] = set()
    for record in records:
        if record.observed_at is not None and record.observed_at > at:
            continue
        resource_values_here = {value for kind, value in record.identifiers if kind == "resource_id"}
        if record.resource_id:
            classified = _classify_resource(record.resource_id)
            if classified:
                resource_values_here.add(classified)
        if names_subject(record) or (resource_values_here & wanted):
            seeds |= _record_trace_ids(record)
    return seeds


def _trace_siblings(records, wanted, names_subject, *, at):
    """Yield records that share a trace id with a line naming the subject or its resources."""

    seeds = _seed_trace_ids(records, wanted, names_subject, at)
    if not seeds:
        return []
    return [
        record
        for record in records
        if (record.observed_at is None or record.observed_at <= at)
        and (_record_trace_ids(record) & seeds)
    ]


#: Operation-name suffix that starts a read/lookup and the suffix that completes it. The
#: pair shares the same ``<operation>_`` prefix, which is what lets a completion line that
#: carries only a resource id be joined back to the line that names the subject.
_OPERATION_PREFIX_RE = re.compile(r"^(?P<prefix>[a-z_]+?)_(?:started|completed|read|scan|query)$")


def _operation_name(record: EvidenceRecord) -> str:
    return _record_event_name(record)


def _operation_pair_completions(records, wanted, names_subject, *, at, subject=None, index=None):
    """Yield completion lines whose ``<operation>_`` prefix is named by a subject line.

    A readback pair writes ``..._started`` with the subject's lookup key and ``..._completed``
    with only the resource. The operation name is the shared key, and the join is scoped so
    that an unrelated request in the same export is not merged:

    * one export only, and one operation prefix only;
    * the completion must be the **earliest** completion of that prefix after the subject's
      own started line (a diagnostic export interleaves requests, so the next completion of
      the same operation *is* this request's completion);
    * a completion that names a different known subject is refused.
    """

    ordered = [
        (position, record)
        for position, record in enumerate(records)
        if record.observed_at is None or record.observed_at <= at
    ]
    pairs: list[EvidenceRecord] = []
    by_operation: dict[tuple[str, str], list[tuple[int, EvidenceRecord]]] = {}
    for position, record in ordered:
        event = _operation_name(record)
        match = _OPERATION_PREFIX_RE.match(event)
        if match is None:
            continue
        by_operation.setdefault((record.evidence_id, match.group("prefix")), []).append(
            (position, record)
        )

    for (_evidence_id, _prefix), group in by_operation.items():
        for position, record in group:
            if not names_subject(record):
                continue
            started_traces = _record_trace_ids(record)
            # The completion must be the *same operation instance*. When the export stamps
            # trace ids, that means an identical trace id; a shared diagnostic log otherwise
            # merges unrelated requests. A started line with no trace and a completion with no
            # trace still pair (the original files' shape), but a trace on one side must match.
            for later_position, later in group:
                if later_position <= position:
                    continue
                event = _operation_name(later)
                if not event.endswith(("_completed", "_read")):
                    continue
                later_traces = _record_trace_ids(later)
                if started_traces or later_traces:
                    if not (started_traces & later_traces):
                        continue
                if subject is not None and index is not None:
                    if foreign_stable_reference(later, subject, index):
                        continue
                    if _names_other_subject(later, subject, index):
                        continue
                pairs.append(later)
                break
    return pairs


def _names_other_subject(record: EvidenceRecord, subject: Subject, index: IdentityIndex) -> bool:
    subject_user = subject.user_id.casefold()
    for kind, value in record.identifiers:
        if kind != "user_id":
            continue
        folded = value.casefold()
        if folded != subject_user and folded in index_user_ids(index):
            return True
    return False


def _expand_by_trace(
    records: Sequence[EvidenceRecord],
    wanted: set[str],
    names_subject,
    *,
    at: _dt.datetime,
) -> list[EvidenceRecord]:
    """Add the trace siblings of lines that name the subject or a known resource.

    A diagnostic export interleaves several requests; the line that names the subject carries
    a ``requestId``/``trace_id`` and the line that carries the resource id and its state
    shares it. Following that identifier — scoped to lines already in the export and inside
    the audit window — reaches the completion line without ever joining unrelated requests
    (T02-NB-03). The join is transitive only within one trace id.
    """

    seeds = _seed_trace_ids(records, wanted, names_subject, at)
    if not seeds:
        return list(records)

    seen = {(record.evidence_id, record.locator) for record in records}
    expanded: list[EvidenceRecord] = list(records)
    for record in records:
        if record.observed_at is not None and record.observed_at > at:
            continue
        if not (_record_trace_ids(record) & seeds):
            continue
        key = (record.evidence_id, record.locator)
        if key in seen:
            continue
        seen.add(key)
        expanded.append(record)
    return expanded


def _stable_reference_present(record: EvidenceRecord) -> bool:
    """True when the record names the subject through a policy-permitted stable reference."""

    for name, value in record.fields:
        if name.rsplit(".", 1)[-1] in _STABLE_REFERENCE_FIELDS and value.strip():
            return True
    return any(kind == "user_id" for kind, _value in record.identifiers)


def reconstruct(
    evidence: SubjectEvidence,
    subject: Subject,
    index: IdentityIndex,
    *,
    at: _dt.datetime,
    documents_text: Mapping[str, str] | None = None,
    supplementary_matches: Sequence[EvidenceMatch] = (),
    library=None,
) -> StateReport:
    """Reconstruct the evidence-backed state of every relevant resource at ``at``.

    ``documents_text`` maps ``evidence_id -> raw text`` for text documents whose state rows
    T01 does not turn into records; the state layer parses them itself so the handover
    export is not lost. ``supplementary_matches`` carries records the state layer retrieved
    by resource id (a ``*_completed`` line that names only ``resource_id`` and no identity
    claim is not attributed by T01's identity-based retrieval, yet it is the line that
    states the resource's state). Everything else comes from T01's grounded, time-filtered
    matches.
    """

    diagnostics: list[str] = []
    matches = list(_records_for_subject(evidence, subject, index))
    seen_keys = {
        (match.record.evidence_id, match.record.locator) for match in matches
    }
    for match in supplementary_matches:
        key = (match.record.evidence_id, match.record.locator)
        if key in seen_keys:
            continue
        if match.record.captured_at > at:
            continue
        if match.record.observed_at is not None and match.record.observed_at > at:
            continue
        if match.match_kind == "resource_link" and foreign_stable_reference(
            match.record, subject, index
        ):
            continue
        seen_keys.add(key)
        matches.append(match)

    # ---------------------------------------------------------------- per-record state
    observations: dict[tuple[str, str], list[Observation]] = {}
    category_by_resource: dict[tuple[str, str], str] = {}
    contradictions: list[str] = []
    unknown_records: list[str] = []
    evidence_artifacts: list[str] = []
    ungrounded_records: list[str] = []
    record_by_resource_id: dict[str, EvidenceRecord] = {}
    ancestry = build_ancestry_map(library, at=at) if library is not None else {}

    for match in matches:
        record = match.record
        derived = derive_category(record)
        is_artifact = False
        if derived is None:
            key = f"{record.evidence_id}:{record.locator}"
            # A record whose container names no policy category is only a business artifact
            # when it also asserts no state. A log line carrying ``rows``/``http_status``/
            # ``enabled`` facts is state evidence for the resource it names.
            if record.container in {"pdf", "screenshot", "log", "text_export"} and read_state_token(record) is None:
                evidence_artifacts.append(key)
                is_artifact = True
            else:
                unknown_records.append(key)
            system = record.system or "unknown"
            category = "UNKNOWN"
        else:
            system, category = derived
        system = record.system or system
        resource_id = resolve_resource_identity(record, ancestry=ancestry)
        if not resource_id:
            # A nested sub-object whose store identity is nowhere grounded is a diagnostic,
            # never a fabricated ``<category>_copy`` resource (DS-R2-B1/B3). Its evidence is
            # still attributed to the subject, so it is reported, not silently dropped. A bare
            # ``*_started`` operation line names no resource by nature, so it is not reported
            # as an ungrounded *record* — its completion line carries the identity.
            event_name = _record_event_name(record)
            is_operation_event = bool(_OPERATION_EVENT_RE.search(event_name))
            if derived is not None and not is_operation_event:
                ungrounded_records.append(f"{record.evidence_id}:{record.locator}")
            continue
        state = classify_record_state(record, subject, index, at)
        exposed = direct_identifiers_present(record, subject, index, at)
        if state == STATE_PRESENT and not exposed:
            # A record that exists but exposes no direct identifier is present-with-clean
            # data only if policy allows retention; otherwise it is still present.
            pass
        observations.setdefault((system, resource_id), []).append(
            Observation(
                evidence_id=record.evidence_id,
                system=system,
                resource_id=resource_id,
                category=category,
                state=state,
                at=record.observed_at or record.captured_at,
                source="record",
                detail=record.locator,
                identifiers_exposed=exposed,
            )
        )
        category_by_resource[(system, resource_id)] = category
        record_by_resource_id.setdefault(resource_id, record)
        if is_artifact:
            # A business artifact whose role does not map to a policy category is evidence
            # about the subject, not a platform record the policy deletes. It is recorded
            # for the report but never turned into a policy outcome.
            observations.pop((system, resource_id), None)
            category_by_resource.pop((system, resource_id), None)

    # ------------------------------------------------- handover/text state rows (own parse)
    for evidence_id, text in sorted((documents_text or {}).items()):
        snapshot_at = None
        snapshot_match = _HANDOVER_SNAPSHOT_RE.search(text)
        if snapshot_match is not None:
            try:
                snapshot_at = _parse_state_timestamp(snapshot_match.group(1))
            except ValueError:
                snapshot_at = None
        for row in parse_handover_rows(text, evidence_id=evidence_id, snapshot_at=snapshot_at):
            if row.observed_at > at:
                continue
            row_state = _STATE_TOKENS.get(row.state.casefold(), STATE_UNKNOWN)
            observed_subject = _row_observes_subject(row, subject, index, at)
            anonymous_row = "no direct identifier" in row.subject_text.casefold()
            if not observed_subject and not anonymous_row:
                continue
            system = row.system or "unknown"
            category = row.record_type or "UNKNOWN"
            if anonymous_row:
                # The resource exists; the state column says whether it can be linked.
                state = row_state if row_state != STATE_UNKNOWN else STATE_UNKNOWN
                exposed: tuple[str, ...] = ()
            else:
                state = row_state
                exposed = () if row_state in {STATE_ABSENT, STATE_REDACTED, STATE_ANONYMIZED} else (
                    f"handover-subject={row.subject_text}",
                )
            observations.setdefault((system, row.resource_id), []).append(
                Observation(
                    evidence_id=evidence_id,
                    system=system,
                    resource_id=row.resource_id,
                    category=category,
                    state=state,
                    at=row.observed_at,
                    source="record",
                    detail=f"handover:{row.state}",
                    identifiers_exposed=exposed,
                )
            )
            category_by_resource.setdefault((system, row.resource_id), category)

    # ------------------------------------------------------------------- reconciliation
    record_states: list[ResourceState] = []
    for (system, resource_id), obs in sorted(observations.items()):
        category = category_by_resource.get((system, resource_id), "UNKNOWN")
        ordered = tuple(sorted(obs, key=lambda item: (item.at, item.evidence_id, item.detail)))
        state, notes = reconcile(ordered, category)
        contradictions.extend(notes)
        record_states.append(
            ResourceState(
                system=system,
                resource_id=resource_id,
                category=category,
                state=state,
                observations=ordered,
                contradictions=tuple(notes),
            )
        )

    # --------------------------------------------------------------- flows and restores
    # A flow/restore is a *process*: observations of the same resource are folded
    # newest-wins, so a stale ACTIVE event cannot survive a later DISABLED/BLOCKED one
    # (GLM T02-NB-3). Stored records keep the facet-aware record reconciliation above.
    #
    # A process resource is keyed by its *resource id*, not by whichever system happened to
    # emit the observation: an export can name ``search_index_service`` for ``data_flow_9927``
    # while the activity row names ``integration_service``, and both describe one store. The
    # owning system is derived from the resource id's own category, so the two views fold into
    # one process instead of emitting two steps for one resource (DS T02R3-B1 dedup).
    flow_observations: dict[str, list[Observation]] = {}
    restore_observations: dict[str, list[Observation]] = {}
    flow_category: dict[str, str] = {}
    flow_system: dict[str, str] = {}
    for record_state in record_states:
        owner_system = _owner_system_for_resource(record_state.resource_id, record_state.system)
        if record_state.category in FLOW_CATEGORIES:
            flow_observations.setdefault(record_state.resource_id, []).extend(
                record_state.observations
            )
            flow_category.setdefault(record_state.resource_id, record_state.category)
            flow_system.setdefault(record_state.resource_id, owner_system)
        elif record_state.category in RESTORE_CATEGORIES:
            restore_observations.setdefault(record_state.resource_id, []).extend(
                record_state.observations
            )
            flow_category.setdefault(record_state.resource_id, record_state.category)
            flow_system.setdefault(record_state.resource_id, owner_system)

    flows: list[DataFlowState] = []
    restores: list[RestoreRisk] = []
    for resource_id, obs in sorted(flow_observations.items()):
        system = flow_system.get(resource_id, "unknown")
        category = flow_category.get(resource_id, "DATA_FLOW")
        ordered = tuple(sorted(obs, key=lambda item: (item.at, item.evidence_id, item.detail)))
        state, notes = reconcile_process(ordered, category)
        contradictions.extend(notes)
        flows.append(
            DataFlowState(
                system=system,
                resource_id=resource_id,
                state=state,
                observations=ordered,
                evidence_id=ordered[0].evidence_id if ordered else "",
                detail=category,
            )
        )
    for resource_id, obs in sorted(restore_observations.items()):
        system = flow_system.get(resource_id, "unknown")
        category = flow_category.get(resource_id, "BACKUP_ARCHIVE")
        ordered = tuple(sorted(obs, key=lambda item: (item.at, item.evidence_id, item.detail)))
        state, notes = reconcile_process(ordered, category)
        contradictions.extend(notes)
        restores.append(
            RestoreRisk(
                system=system,
                resource_id=resource_id,
                state=state,
                observations=ordered,
                evidence_id=ordered[0].evidence_id if ordered else "",
                detail=category,
            )
        )

    # ----------------------------------------------------------- activity-derived state
    # A capability row that names only a resource (``CHECK_RESTORE_ACCESS backup_7253``) is
    # attributed through the subject's own resource provenance: the records already grounded
    # in-window plus the catalogue-linked resources observed at or before ``audit_at``. The
    # set is time-valid (built from in-window matches and cutoff-filtered links) and the
    # attribution refuses any row naming a different known subject, so a shared resource never
    # propagates one subject's capability onto another (DS T02R3-B1).
    resource_links = linked_resource_identities(evidence, subject, index, at)
    owned_resource_ids = {
        record_state.resource_id
        for record_state in record_states
        if record_state.resource_id
    } | {link.resource_id for link in resource_links if link.resource_id}
    # ``evidence.activity`` holds the rows T01 attributed by identifier; a *resource-only*
    # capability row (no identifier in its text) is missing from it, so the full activity
    # stream is offered as well. ``activity_state_events`` accepts a row through either the
    # identifier path or the time-valid owned-resource path, and the foreign-conflict guard
    # still refuses a row naming another subject (DS T02R3-B1).
    activity_stream = _activity_stream(evidence, library)
    attributed_ids = {event.activity_id for event in evidence.activity}
    flow_events, restore_events = activity_state_events(
        evidence,
        subject,
        index,
        at,
        owned_resource_ids=owned_resource_ids,
        activity_stream=activity_stream,
        attributed_ids=attributed_ids,
    )
    flows = _merge_process_states(flows, flow_events, as_flow=True)
    restores = _merge_process_states(restores, restore_events, as_flow=False)

    if unknown_records:
        diagnostics.append(
            f"{len(unknown_records)} matched record(s) have no grounded policy category: "
            + ", ".join(unknown_records[:8])
            + (" ..." if len(unknown_records) > 8 else "")
        )
    if evidence_artifacts:
        diagnostics.append(
            f"{len(evidence_artifacts)} business artifact(s) carry no policy category and are "
            "treated as evidence, not remediable records: "
            + ", ".join(evidence_artifacts[:8])
            + (" ..." if len(evidence_artifacts) > 8 else "")
        )
    if ungrounded_records:
        diagnostics.append(
            f"{len(ungrounded_records)} record(s) carry a policy category but no grounded store "
            "identity; they are reported as a blocking diagnostic rather than serialized under an "
            "invented resource id: "
            + ", ".join(ungrounded_records[:8])
            + (" ..." if len(ungrounded_records) > 8 else "")
        )

    # A catalogue link whose linked resource's own artifact exposes a different person is a real
    # contradiction between two participant artifacts. It is surfaced as a runtime diagnostic so
    # the mismatch is not silent, and the duty stays undecided rather than being refuted
    # (GLM-R3-N2). No fuzzy merge is performed and the fail-closed INCOMPLETE is unchanged.
    mismatches = linked_resource_mismatches(
        [
            (link, record_by_resource_id[link.resource_id])
            for link in resource_links
            if link.resource_id in record_by_resource_id
        ],
        subject,
        index,
    )
    for note in mismatches:
        contradictions.append(note)
    if mismatches:
        diagnostics.append(
            f"{len(mismatches)} linked resource(s) contradict their catalogue claim; the duty is "
            "left undecided rather than refuted: "
            + " | ".join(mismatches[:4])
            + (" ..." if len(mismatches) > 4 else "")
        )

    return StateReport(
        subject_user_id=subject.user_id,
        at=at,
        records=tuple(record_states),
        flows=tuple(sorted(flows, key=lambda item: (item.system, item.resource_id))),
        restores=tuple(sorted(restores, key=lambda item: (item.system, item.resource_id))),
        unknown_records=tuple(unknown_records),
        evidence_artifacts=tuple(evidence_artifacts),
        ungrounded_records=tuple(ungrounded_records),
        contradictions=tuple(contradictions),
        diagnostics=tuple(diagnostics),
        coverage=(
            derive_coverage(library, subject, index, at=at, matches=matches)
            if library is not None
            else ()
        ),
        resource_links=resource_links,
    )


def classify_record_state(
    record: EvidenceRecord,
    subject: Subject,
    index: IdentityIndex,
    at: _dt.datetime,
) -> str:
    """Classify one record's state from its own content, never from a reported status."""

    token = read_state_token(record)
    exposed = direct_identifiers_present(record, subject, index, at)
    category = derive_category(record)
    category_name = category[1] if category else None
    if token is None:
        # A ``*_started`` line records that a lookup ran; it carries no state of its own and
        # must not be read as a redacted record just because it holds no identifiers.
        event = record.field("event")
        if event.casefold().endswith("_started") and not exposed:
            return STATE_UNKNOWN
        # No explicit token: presence is proven by the record carrying the subject's data.
        if exposed:
            return STATE_PRESENT
        # A record whose free text was replaced by an explicit redaction marker has had its
        # identifiers removed in place: the row remains, the identifiers do not.
        if free_text_is_redacted(record):
            if category_name in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                return STATE_ANONYMIZED
            return STATE_REDACTED
        # A stored record that is *reached* (a completed lookup or read of an existing row)
        # but whose identifier fields are all explicitly null has been redacted in place:
        # the row remains, the identifiers do not.
        if _is_redacted_in_place(record):
            if category_name in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                return STATE_ANONYMIZED
            return STATE_REDACTED
        # A support message is grounded through its stable ``user_id`` reference because a
        # conversation may have to be retained for the shared context it carries. When the
        # record exposes none of the subject's direct identifiers and its free text carries
        # none either, the message is present with its identifiers removed — the retained,
        # redacted state rule_05 describes — not an uncertain one.
        if category_name == "SUPPORT_MESSAGE" and not exposed:
            return STATE_REDACTED
        # A tombstone record: its presence is proven by the row existing with an
        # ``account_status`` that marks the account deleted while only the stable reference
        # policy permits remains.
        if category_name == "ACCOUNT_TOMBSTONE" and record.field("account_status"):
            return STATE_REDACTED
        # An analytics/telemetry row reached through its stable reference whose direct
        # identifier columns are all null is the anonymized state rule_07/rule_08 describe.
        if (
            category_name in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
            and _stable_reference_present(record)
        ):
            return STATE_ANONYMIZED
        # A support conversation grounded only by its stable reference, with no direct
        # identifier in any field, is the retained/redacted state rule_05 describes.
        if category_name == "SUPPORT_MESSAGE" and _stable_reference_present(record):
            return STATE_REDACTED
        # A record grounded only through a resource link and exposing nothing is uncertain:
        # it might be a neighbouring row in the same conversation. Reported as UNKNOWN.
        return STATE_UNKNOWN
    if token in {STATE_ABSENT, STATE_DISABLED, STATE_BLOCKED}:
        return token
    if token in {STATE_REDACTED, STATE_ANONYMIZED}:
        return token
    if token == STATE_PRESENT:
        if exposed:
            return STATE_PRESENT
        # The record is present but carries none of the subject's identifiers. Whether that
        # is compliant depends on the category: an ANALYTICS_PROFILE with no direct
        # identifier is anonymized; a tombstone with null direct fields is redacted; an
        # audit record that never held identifiers is simply retained.
        if category_name == "ANALYTICS_PROFILE" or category_name == "PRODUCT_TELEMETRY":
            return STATE_ANONYMIZED
        if category_name in {"ACCOUNT_TOMBSTONE", "SUPPORT_MESSAGE"}:
            return STATE_REDACTED
        if category_name in RETAIN_CATEGORIES:
            return STATE_RETAINED
        return STATE_PRESENT
    return token


#: Resolved state -> preference weight. A capability/absence/redaction fact is more
#: specific than a plain "the row exists" fact, so it wins when both describe the same
#: resource at the same instant (a ``*_completed`` line carries the capability config; the
#: ``*_started`` line only proves a lookup ran).
_STATE_WEIGHT: Mapping[str, int] = {
    STATE_ACTIVE_FLOW: 5,
    STATE_BLOCKED: 5,
    STATE_DISABLED: 5,
    STATE_ABSENT: 4,
    STATE_REDACTED: 4,
    STATE_ANONYMIZED: 4,
    STATE_RETAINED: 3,
    STATE_PRESENT: 2,
    STATE_UNKNOWN: 0,
}


#: States grouped by the facet they describe. Two observations only *contradict* when they
#: describe the same facet differently; a "the row exists" fact and a "the capability is
#: off" fact are complementary, not contradictory.
_STATE_FACET: Mapping[str, str] = {
    STATE_PRESENT: "existence",
    STATE_RETAINED: "existence",
    STATE_ABSENT: "existence",
    STATE_REDACTED: "existence",
    STATE_ANONYMIZED: "existence",
    STATE_ACTIVE_FLOW: "capability",
    STATE_DISABLED: "capability",
    STATE_BLOCKED: "capability",
    STATE_UNKNOWN: "unknown",
}


def reconcile(observations: Sequence[Observation], category: str) -> tuple[str, list[str]]:
    """Fold multiple observations of one resource into a single state.

    The most specific observation at the latest instant wins: a ``*_completed`` line that
    states a capability is preferred over the ``*_started`` line that only proves a lookup
    ran. A genuine disagreement *within one facet* (two snapshots that disagree about
    whether the row exists) is recorded rather than hidden — replica drift is exactly the
    failure mode this challenge models.
    """

    if not observations:
        return STATE_UNKNOWN, []
    decisive = [item for item in observations if item.state != STATE_UNKNOWN]
    pool = decisive or list(observations)
    newest = max(
        pool,
        key=lambda item: (
            item.at,
            _STATE_WEIGHT.get(item.state, 1),
            item.evidence_id,
            item.detail,
        ),
    )
    notes: list[str] = []
    for facet in ("existence", "capability"):
        facet_observations = [item for item in pool if _STATE_FACET.get(item.state) == facet]
        # A disagreement is only a contradiction when it concerns the *same instant*: two
        # snapshots taken at different times legitimately differ because the data changed
        # in between. Concurrent replicas that disagree at one captured moment are the
        # drift this challenge models, and they are reported.
        for _instant, group in _group_by_instant(facet_observations).items():
            states = sorted({item.state for item in group})
            if len(states) > 1:
                newest_instant = max(group, key=lambda item: (item.at, item.evidence_id))
                notes.append(
                    f"{newest_instant.system}/{newest_instant.resource_id}: concurrent "
                    f"{facet} observations disagree ({', '.join(states)}) at "
                    f"{newest_instant.at.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                    f"({newest_instant.evidence_id}); replica drift"
                )
    return newest.state, notes


def reconcile_process(
    observations: Sequence[Observation],
    category: str,
) -> tuple[str, list[str]]:
    """Fold every observation of one process resource (a flow or a restore path).

    Process state is *newest-wins across all observations*, not "the row exists": a stale
    ``ACTIVE`` event that a later ``DISABLED``/``BLOCKED`` outcome supersedes must not
    survive (GLM T02-NB-3). Observations are ordered by the instant they were observed and
    the newest one decides, which is exactly how a capability changes over time.
    """

    if not observations:
        return STATE_UNKNOWN, []
    decisive = [item for item in observations if item.state != STATE_UNKNOWN]
    pool = decisive or list(observations)
    newest = max(
        pool,
        key=lambda item: (item.at, _STATE_WEIGHT.get(item.state, 1), item.evidence_id, item.detail),
    )
    notes: list[str] = []
    states = sorted({item.state for item in pool})
    if len(states) > 1:
        # Only a same-instant disagreement is drift; a change over time is just a change.
        drifted = False
        for _instant, group in _group_by_instant(pool).items():
            if len({item.state for item in group}) > 1:
                drifted = True
        if drifted:
            notes.append(
                f"{newest.system}/{newest.resource_id}: concurrent process observations "
                f"disagree ({', '.join(states)}) at "
                f"{newest.at.strftime('%Y-%m-%dT%H:%M:%SZ')} ({newest.evidence_id})"
            )
    return newest.state, notes


def _group_by_instant(
    observations: Sequence[Observation],
) -> dict[_dt.datetime, list[Observation]]:
    groups: dict[_dt.datetime, list[Observation]] = {}
    for observation in observations:
        groups.setdefault(observation.at, []).append(observation)
    return groups


def _merge_process_states(
    record_derived: Sequence[object],
    activity_derived: Sequence[object],
    *,
    as_flow: bool,
):
    """Merge record-derived and activity-derived observations of the same process resource.

    A flow can be observed both in a configuration snapshot and in the activity stream. The
    two views are folded per **resource id** with the same newest-wins rule used for records,
    so a stale ``ACTIVE`` record observation cannot override a newer ``DISABLED``/``BLOCKED``
    activity outcome, and vice versa. Keying on the resource id (not the emitting system) is
    what keeps one store from being emitted twice when its record and its activity row name
    different systems (DS T02R3-B1 dedup); the emitted ``system`` is the canonical owner
    derived from the resource id.
    """

    merged: dict[str, list[Observation]] = {}
    detail_by_key: dict[str, str] = {}
    system_by_key: dict[str, str] = {}
    for item in list(record_derived) + list(activity_derived):
        resource_id = item.resource_id  # type: ignore[attr-defined]
        merged.setdefault(resource_id, []).extend(item.observations)  # type: ignore[attr-defined]
        detail_by_key.setdefault(resource_id, getattr(item, "detail", "") or "")
        system_by_key.setdefault(
            resource_id,
            _owner_system_for_resource(resource_id, item.system),  # type: ignore[attr-defined]
        )

    result: list[object] = []
    for resource_id, obs in sorted(merged.items()):
        system = system_by_key.get(resource_id, "unknown")
        ordered = tuple(sorted(obs, key=lambda item: (item.at, item.evidence_id, item.detail)))
        state, _notes = reconcile_process(ordered, detail_by_key.get(resource_id, ""))
        if as_flow:
            result.append(
                DataFlowState(
                    system=system,
                    resource_id=resource_id,
                    state=state,
                    observations=ordered,
                    evidence_id=ordered[0].evidence_id if ordered else "",
                    detail=detail_by_key.get(resource_id, ""),
                )
            )
        else:
            result.append(
                RestoreRisk(
                    system=system,
                    resource_id=resource_id,
                    state=state,
                    observations=ordered,
                    evidence_id=ordered[0].evidence_id if ordered else "",
                    detail=detail_by_key.get(resource_id, ""),
                )
            )
    return result


def _owner_system_for_resource(resource_id: str, fallback: str | None) -> str:
    """The canonical owning system of a process/record store, from its resource id.

    ``data_flow_9927`` -> ``integration_service``, ``backup_5237`` -> ``backup_service``,
    regardless of which system emitted the observation. Falls back to the supplied system when
    the resource id grounds no category, so an unknown store keeps its own provenance.
    """

    derived = _category_from_resource_id(resource_id)
    if derived is not None:
        system, _category = derived
        if system:
            return system
    return fallback or "unknown"


def activity_state_events(
    evidence: SubjectEvidence,
    subject: Subject,
    index: IdentityIndex,
    at: _dt.datetime,
    *,
    owned_resource_ids: Iterable[str] = (),
    activity_stream: Sequence[object] | None = None,
    attributed_ids: frozenset[str] = frozenset(),
) -> tuple[list[DataFlowState], list[RestoreRisk]]:
    """Turn token-bounded activity around the subject into flow/restore state.

    Only activity that mentions the subject's *own* identifiers (or one of its resources)
    at token boundaries is considered, and ``reported_result`` is never used as proof: a
    ``SYNC_RECORD`` that reported SUCCESS tells us a sync ran, not that the resulting copy
    is gone. What matters is whether a flow/restore capability is active at ``audit_at``.

    A capability row that names only a *resource* — ``CHECK_RESTORE_ACCESS`` on
    ``backup_7253``, ``CHECK_DATA_FLOW`` on ``data_flow_1`` — is attributed through the
    subject's time-valid resource ownership/link provenance, not only through a direct
    identifier in the row's own text (DS T02R3-B1). ``activity_stream`` carries the full
    activity stream so a row T01's identifier-based selection dropped is still reachable;
    ``owned_resource_ids`` carries the resources the evidence grounds as the subject's
    (records, links); ``attributed_ids`` names the rows T01 already selected. The attribution
    is refused whenever the row names a different known subject, so a shared or conflicting
    resource never propagates one subject's capability onto another (no global propagation).

    The polarity of a ``CHECK_*`` row is read from its detail sentence, not from its event
    type: a check that confirmed the capability is *still enabled* is active, while a check
    that confirmed it is *disabled/blocked* is the stopped state (GLM T02-NB-5). A row with
    no positive marker is left UNKNOWN rather than asserted active.
    """

    sets = subject.identifier_sets(at)
    owned = frozenset(value.casefold() for value in owned_resource_ids if value)
    flow_events: list[DataFlowState] = []
    restore_events: list[RestoreRisk] = []
    seen_ids: set[str] = set()
    for event in _iter_activity(evidence, activity_stream):
        activity_id = getattr(event, "activity_id", "")
        if activity_id in seen_ids:
            continue
        seen_ids.add(activity_id)
        if event.event_time > at:
            continue
        # A row T01 already attributed is trusted as-is; a row reached through the wider stream
        # is accepted only through the identifier-or-owned-resource path (DS T02R3-B1).
        if activity_id in attributed_ids:
            attributed = True
        else:
            attributed = _activity_attributed_to_subject(event, subject, sets, index, owned)
        if not attributed:
            continue
        kind = event.event_type.upper()
        # A *re-creation* event (``SYNC_RECORD``/``INDEX_RECORD``/…) is only a capability
        # observation when the resource it names is itself a process store. T01 attributes a row
        # by resource join, so a ``SYNC_RECORD account_6345`` reaches here on a *profile* id;
        # turning that into an active data flow on ``account_6345`` would be a phantom process
        # on a record's identity (DS T02R3-B1 scoping).
        if kind in {"SYNC_RECORD", "CREATE_EXPORT", "INDEX_RECORD", "REFRESH_CACHE"}:
            if not _is_process_capability_row(event):
                continue
        elif kind not in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE", "CHECK_DATA_FLOW",
                          "CHECK_RESTORE_ACCESS", "RESTORE_BACKUP"}:
            continue
        if kind in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}:
            state = STATE_DISABLED if kind == "DISABLE_DATA_FLOW" else STATE_BLOCKED
        elif kind in {"ANONYMIZE_RECORD", "DELETE_RECORD", "REDACT_RECORD", "RETAIN_RECORD"}:
            # A deletion/retention *operation* is bookkeeping, not a capability: its result
            # is a claim and is never read as state proof.
            continue
        elif kind in {"CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"}:
            state = _check_polarity(event.details)
            if state is None:
                continue
        elif kind in {"SYNC_RECORD", "CREATE_EXPORT", "INDEX_RECORD", "REFRESH_CACHE", "RESTORE_BACKUP"}:
            state = STATE_ACTIVE_FLOW
        else:
            continue
        observation = Observation(
            evidence_id=event.activity_id,
            system=_process_owner_system(event, kind),
            resource_id=event.resource_id or event.activity_id,
            category="DATA_FLOW" if kind != "RESTORE_BACKUP" else "RESTORE_JOB",
            state=state,
            at=event.event_time,
            source="activity",
            detail=event.event_type,
        )
        target = (
            restore_events if kind in {"CHECK_RESTORE_ACCESS", "RESTORE_BACKUP", "BLOCK_RESTORE"} else flow_events
        )
        if target is restore_events:
            restore_events.append(
                RestoreRisk(
                    system=observation.system,
                    resource_id=observation.resource_id,
                    state=state,
                    observations=(observation,),
                    evidence_id=event.activity_id,
                    detail=event.event_type,
                )
            )
        else:
            flow_events.append(
                DataFlowState(
                    system=observation.system,
                    resource_id=observation.resource_id,
                    state=state,
                    observations=(observation,),
                    evidence_id=event.activity_id,
                    detail=event.event_type,
                )
            )
    return flow_events, restore_events


def _process_owner_system(event, kind: str) -> str:
    """The canonical *owning* system of the process resource an activity row names.

    An activity row records the *emitting* system (``deletion_worker`` that ran the check),
    while a configuration record for the same resource names its owning system
    (``integration_service``, ``backup_service``). Folding the two views requires one key per
    resource, so the system is derived from the resource id's own category when it grounds
    one; otherwise the row's own system is kept. This is a property of the resource, not of
    the case, and it is what stops the same ``data_flow_5127`` being emitted twice under two
    ``system_id`` values (DS T02R3-B1 dedup).
    """

    del kind  # the owning system is a property of the resource, not the operation
    return _owner_system_for_resource(
        (event.resource_id or "").strip(),
        event.source_system or event.target_system,
    )


def _iter_activity(evidence: SubjectEvidence, activity_stream: Sequence[object] | None):
    """Yield the candidate activity rows: T01's selection first, then the wider stream.

    A resource-only capability row is absent from ``evidence.activity`` because T01 attributes
    by identifier; the wider stream is offered so the state layer can reach it through the
    owned-resource path. Order is deterministic (the stream is already time-sorted by the
    loader), and de-duplication happens in the caller by ``activity_id``.
    """

    for event in evidence.activity:
        yield event
    for event in activity_stream or ():
        yield event


def _activity_stream(evidence: SubjectEvidence, library) -> Sequence[object]:
    """The full activity stream when the library exposes one, else T01's selected rows."""

    dataset = getattr(library, "dataset", None)
    activity = getattr(dataset, "activity", None)
    if activity is None:
        return ()
    return tuple(activity)


#: Detail phrases that positively confirm a capability is stopped, and phrases that confirm
#: it is still live. A ``CHECK_*`` row carries no state field, so the sentence decides.
_INACTIVE_CHECK_RE = re.compile(
    r"\b(?:no longer|not|isn'?t|is not|denied|deny|blocked|disabled|revoked|"
    r"can(?:not|'?t) (?:still )?be restored|unable to)\b",
    re.IGNORECASE,
)
_ACTIVE_CHECK_RE = re.compile(
    r"\b(?:remains enabled|still enabled|is enabled|remains active|still active|"
    r"can still be restored|still restorable|remains restorable|restore (?:is|remains) (?:allowed|possible))\b",
    re.IGNORECASE,
)


def _check_polarity(details: str) -> str | None:
    """Read a ``CHECK_*`` row's outcome from its detail sentence.

    Returns ``ACTIVE``/``DISABLED``/``BLOCKED`` when the sentence states the capability, or
    ``None`` when the sentence carries no positive marker (the state is simply not proven).
    """

    text = (details or "").strip()
    if not text:
        return None
    if _INACTIVE_CHECK_RE.search(text):
        return STATE_DISABLED
    if _ACTIVE_CHECK_RE.search(text):
        return STATE_ACTIVE_FLOW
    return None


#: ``LINK_RESOURCE_IDENTITY`` rows prove a resource belongs to the subject. They are an
#: identity *bridge*, never state proof: the linked resource's own evidence decides its
#: state. The catalogue phrase for a sole-owner attachment is the supplied policy condition
#: for ``rule_06`` and is preserved as such, not read as presence or absence.
_SOLE_OWNER_RE = re.compile(
    r"\bbelongs only to\b|\bno other subject is linked\b|\bsole(?:ly)? owner\b",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True, slots=True)
class ResourceLink:
    """One ``LINK_RESOURCE_IDENTITY`` row attributed to the subject."""

    activity_id: str
    at: _dt.datetime
    resource_id: str
    system: str
    sole_owner: bool
    subject_email: str | None
    detail: str = ""


def linked_resource_identities(
    evidence: SubjectEvidence,
    subject: Subject,
    index: IdentityIndex,
    at: _dt.datetime,
) -> tuple[ResourceLink, ...]:
    """Return the resource identities the subject is linked to by catalogue activity.

    A ``LINK_RESOURCE_IDENTITY`` row names the resource and the subject together, so it is a
    grounded bridge even when no record names both. It is *not* a state fact: the caller
    uses the returned resource ids to seed discovery and then inspects the linked evidence.
    Attribution honours the cutoff, the foreign-reference guard and identifier token
    boundaries (GLM T02-B2).
    """

    sets = subject.identifier_sets(at)
    links: list[ResourceLink] = []
    for event in evidence.activity:
        if event.event_type.upper() != "LINK_RESOURCE_IDENTITY":
            continue
        if event.event_time > at:
            continue
        if not _activity_mentions_subject(event, subject, sets):
            continue
        resource_id = (event.resource_id or "").strip()
        if not resource_id:
            continue
        if not _resource_belongs_to_subject(event.details, subject, index):
            continue
        email = _first_subject_email(event.details, sets)
        links.append(
            ResourceLink(
                activity_id=event.activity_id,
                at=event.event_time,
                resource_id=resource_id,
                system=(event.target_system or event.source_system or "unknown").strip(),
                sole_owner=bool(_SOLE_OWNER_RE.search(event.details or "")),
                subject_email=email,
                detail=event.details or "",
            )
        )
    links.sort(key=lambda item: (item.at, item.activity_id, item.resource_id))
    return tuple(links)


def _resource_belongs_to_subject(
    details: str,
    subject: Subject,
    index: IdentityIndex,
) -> bool:
    """Refuse a link row that names a *different* known subject (foreign-reference guard)."""

    if not details:
        return True
    folded = details.casefold()
    subject_user = subject.user_id.casefold()
    for user_id in index_user_ids(index):
        if user_id == subject_user:
            continue
        if mentions_identifier(folded, "user_id", user_id):
            return False
    return True


def _first_subject_email(details: str, sets: Mapping[str, frozenset[str]]) -> str | None:
    for email in sorted(sets.get("email", frozenset())):
        if mentions_identifier(details, "email", email):
            return email
    return None


def linked_resource_mismatches(
    linked_resource_records: Sequence[tuple["ResourceLink", EvidenceRecord]],
    subject: Subject,
    index: IdentityIndex,
) -> tuple[str, ...]:
    """Report linked resources whose reachable record exposes a *different* person.

    A ``LINK_RESOURCE_IDENTITY`` row is a catalogue *claim*: it names a resource and the
    subject together. When the resource's own reachable record exposes direct identifiers
    that match neither this subject nor any registered subject — **and exposes none of the
    subject's own identifiers** — the two artifacts genuinely contradict, and the mismatch is
    recorded as a runtime diagnostic rather than left implicit (GLM-R3-N2, DS-R2-NB-5). The
    ``exposes none of the subject's own`` condition is what keeps a shared store that carries
    the subject's row *and* a neighbour's row from being misreported as a mismatch. The
    fail-closed INCOMPLETE decision is unchanged: a contradiction never becomes subject proof,
    and no fuzzy identity merge is performed.
    """

    subject_sets = subject.identifier_sets(subject_at_max())
    subject_values: set[str] = set()
    for values in subject_sets.values():
        subject_values |= set(values)
    notes: list[str] = []
    for link, record in linked_resource_records:
        claims = _record_identifier_claims(record)
        if any(value in subject_values for _kind, value in claims):
            # The artifact evidences the subject, so the link is not contradicted.
            continue
        foreign = {
            f"{kind}={value}"
            for kind, value in claims
            if kind in {"email", "phone", "email_hash"}
            and (kind == "email" or value in index_identifier_tokens(index, kind))
        }
        if foreign:
            notes.append(
                f"{link.resource_id}: the catalogue link ({link.activity_id}) claims this "
                "resource for the subject, but its reachable evidence exposes only identifiers "
                f"matching no subject record ({', '.join(sorted(foreign))}) and none of the "
                "subject's own; the link and the artifact contradict, so the duty stays "
                "undecided rather than being refuted"
            )
    return tuple(notes)


def _record_identifier_claims(record: EvidenceRecord) -> tuple[tuple[str, str], ...]:
    """Every direct-identifier claim the record itself makes, normalised.

    Both classified identifier values and free-text ``email``/``phone`` fields are read, so an
    OCR'd screenshot that carries an address only in ``text.email`` is still visible to the
    mismatch check (GLM-R3-N2).
    """

    claims: set[tuple[str, str]] = set()
    for kind, value in record.identifiers:
        if kind in {"email", "phone", "email_hash"}:
            claims.add((kind, value))
    for name, value in record.fields:
        if name.rsplit(".", 1)[-1] not in {"email", "phone"}:
            continue
        classified = _classify_for_query(value)
        if classified is None:
            continue
        kind, normalised = classified
        if kind in {"email", "phone"}:
            claims.add((kind, normalised))
    return tuple(sorted(claims))


def subject_at_max() -> _dt.datetime:
    return _dt.datetime.max.replace(tzinfo=UTC)


def _activity_mentions_subject(
    event,
    subject: Subject,
    sets: Mapping[str, frozenset[str]],
) -> bool:
    details = event.details or ""
    if event.resource_id and event.resource_id.casefold() == subject.user_id.casefold():
        return True
    if mentions_identifier(details, "user_id", subject.user_id):
        return True
    for email in sets.get("email", frozenset()):
        if mentions_identifier(details, "email", email):
            return True
    for value in sets.get("email_hash", frozenset()):
        if mentions_identifier(details, "email_hash", value):
            return True
    for phone in sets.get("phone", frozenset()):
        if mentions_identifier(details, "phone", phone):
            return True
    return False


def _activity_names_foreign_subject(
    event,
    subject: Subject,
    index: IdentityIndex,
) -> bool:
    """True when the row names a *different* known subject (foreign-conflict guard).

    A capability row about a shared or conflicting resource must never carry one subject's
    state onto another. The check is deliberately broader than :func:`_activity_mentions_subject`:
    it looks for any known ``user_id`` or any registered email/hash/phone that is not this
    subject's, so a row that names a decoy person is refused even when it also names a
    resource the subject happens to be linked to (DS T02R3-B1 conflict guard).
    """

    details = event.details or ""
    if not details:
        return False
    folded = details.casefold()
    subject_user = subject.user_id.casefold()
    for user_id in index_user_ids(index):
        if user_id == subject_user:
            continue
        if mentions_identifier(folded, "user_id", user_id):
            return True
    for value in index_identifier_tokens(index, "email"):
        if mentions_identifier(folded, "email", value):
            return True
    for value in index_identifier_tokens(index, "phone"):
        if mentions_identifier(folded, "phone", value):
            return True
    for value in index_identifier_tokens(index, "email_hash"):
        if mentions_identifier(folded, "email_hash", value):
            return True
    return False


def _activity_attributed_to_subject(
    event,
    subject: Subject,
    sets: Mapping[str, frozenset[str]],
    index: IdentityIndex,
    owned_resource_ids: frozenset[str],
) -> bool:
    """Attribute a capability row to the subject through identifiers *or* owned resources.

    A direct identifier in the row's own text always attributes it. When the text names no
    identifier, the row is still the subject's if it is a *capability* observation about a
    resource the evidence already grounds as the subject's own (a record or a catalogue link
    observed at or before ``audit_at``) — this is what reaches
    ``CHECK_RESTORE_ACCESS backup_7253`` for case_363. The attribution is refused whenever the
    row names a different known subject, so a shared or conflicting resource never propagates
    one subject's capability onto another and no global resource-id propagation occurs
    (DS T02R3-B1).

    The resource-scoped path is deliberately limited to *process-capability* rows — a
    ``CHECK_*`` probe, or a row whose resource id names a ``data_flow``/``backup`` store (a
    ``SYNC_RECORD``/``RESTORE_BACKUP`` against the flow it copies). A re-creation event on a
    *record* resource (a ``SYNC_RECORD account_6345``) is not a capability observation about a
    process, so it is left to the record path rather than turned into a phantom flow on a
    profile's id.
    """

    if _activity_mentions_subject(event, subject, sets):
        return True
    resource_id = (event.resource_id or "").strip().casefold()
    if not resource_id or resource_id not in owned_resource_ids:
        return False
    if not _is_process_capability_row(event):
        return False
    return not _activity_names_foreign_subject(event, subject, index)


def _is_process_capability_row(event) -> bool:
    """True when an activity row observes a *process* capability rather than a record copy.

    ``CHECK_DATA_FLOW``/``CHECK_RESTORE_ACCESS`` are capability probes by definition. A
    ``SYNC_RECORD``/``RESTORE_BACKUP``/``CREATE_EXPORT``/``INDEX_RECORD``/``REFRESH_CACHE``
    row is a re-creation event, so it is only a capability observation when the resource it
    names is itself a process store (``data_flow_*``, ``connector_*``, ``backup_*``).
    """

    kind = event.event_type.upper()
    if kind in {"CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS", "RESTORE_BACKUP"}:
        return True
    if kind in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}:
        return True
    if kind in {"SYNC_RECORD", "CREATE_EXPORT", "INDEX_RECORD", "REFRESH_CACHE"}:
        derived = _category_from_resource_id(event.resource_id or "")
        if derived is None:
            return False
        return derived[1] in FLOW_CATEGORIES or derived[1] in RESTORE_CATEGORIES
    return False
