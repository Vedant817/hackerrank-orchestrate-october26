"""Authored evaluation cases for Ghost Data Still Exists (T03).

These are **additional evaluation cases created by the participant**, as the submission
contract requires. Each one is a self-contained fixture with its own tiny dataset built in a
temporary directory, an explicit expected behaviour, and an assertion, so the case is
executable rather than prose-only.

Coverage of the contract-required behaviours:

* ``historical_identifier`` - a request that arrives under a *historical* email (an address
  the subject changed away from) must resolve to the same subject and still prove the
  deletion of the account record.
* ``temporal_recreation`` - a synchronisation job that ran *after* the primary deletion but
  *before* ``audit_at`` recreates the record; the audit must report the active flow and the
  remaining record rather than trusting the workflow's ``COMPLETE`` claim.
* ``tombstone_retention`` - a retained tombstone must keep the stable ``user_id`` while the
  direct identifiers are redacted, and a retained security record must still be proven
  present.
* ``late_evidence_ignored`` - evidence captured after ``audit_at`` must never change the
  decision (cutoff rule).

The fixtures never touch the real ``dataset/`` and never read ``dataset/sample_output.csv``.
The rule ``condition`` strings are the exact participant phrasings (``deletion_rules.csv``),
because the policy layer classifies a condition by its wording.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_CODE_DIR = _HERE.parent
if str(_CODE_DIR) not in sys.path:
    sys.path.insert(0, str(_CODE_DIR))

REQUEST_HEADER = "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text"
IDENTITY_HEADER = "user_id,name,email,phone,email_hash,updated_at"
AUDIT_HEADER = "audit_id,user_id,event_time,field_name,old_value,new_value"
ACTIVITY_HEADER = (
    "activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details"
)
RULE_HEADER = "rule_id,data_category,condition,required_action"
EVIDENCE_HEADER = "file_id,file_path,origin,captured_at"

#: The exact participant rule phrasings, so the policy layer grounds each condition.
RULE_PROFILE = "rule_01,USER_PROFILE,Always,DELETE"
RULE_SEARCH = "rule_03,SEARCH_INDEX_ENTRY,Always,DELETE"
RULE_SECURITY = (
    "rule_12,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN"
)
RULE_TOMBSTONE = (
    "rule_15,ACCOUNT_TOMBSTONE,"
    "Account is deleted and only a stable internal user_id is needed to preserve "
    "references to retained records,REDACT"
)


def _write_csv(path: Path, header: str, rows: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


@dataclass(slots=True)
class CustomCase:
    """One authored evaluation case."""

    name: str
    focus: str
    expected_status: str
    expected_behaviour: str
    build: "object" = field(repr=False, default=None)


# --------------------------------------------------------------------------------------
# Case fixtures
# --------------------------------------------------------------------------------------


def _build_historical_identifier(root: Path) -> tuple[Path, str]:
    """Deletion arrives under the subject's *old* email; the account record is gone."""

    dataset = root / "dataset"
    (dataset / "evidence").mkdir(parents=True, exist_ok=True)

    _write_csv(
        dataset / "deletion_requests.csv",
        REQUEST_HEADER,
        [
            "case_hist,old.address@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-10T00:00:00Z,Please delete my account.",
        ],
    )
    _write_csv(
        dataset / "user_identities.csv",
        IDENTITY_HEADER,
        [
            "user_hist,Ada Lovelace,new.address@example.com,+44 20 7946 0001,"
            "aa11bb22,2026-02-01T00:00:00Z",
        ],
    )
    _write_csv(
        dataset / "user_audit_log.csv",
        AUDIT_HEADER,
        [
            "audit_hist,user_hist,2026-01-15T00:00:00Z,email,"
            "old.address@example.com,new.address@example.com",
        ],
    )
    _write_csv(dataset / "system_activity.csv", ACTIVITY_HEADER, [])
    _write_csv(dataset / "deletion_rules.csv", RULE_HEADER, [RULE_PROFILE, RULE_SECURITY])
    _write_csv(
        dataset / "evidence_files.csv",
        EVIDENCE_HEADER,
        ["evidence_hist,evidence/records/snap.json,records_assurance_service,2026-03-05T00:00:00Z"],
    )
    _write_json(
        dataset / "evidence" / "records" / "snap.json",
        {
            "exported_at": "2026-03-05T00:00:00Z",
            "snapshots": [
                # The account store is a complete listing and holds no row for the subject.
                {"data_store": "account_service", "collection": "customer_profiles",
                 "complete": True, "records": []},
                # The retained security store still holds the subject's audit record, keyed
                # only by the stable reference (no prohibited direct identifier).
                {"data_store": "security_service", "collection": "security_audit_events",
                 "records": [
                     {"resource_id": "audit_record_hist", "subject_reference": "user_hist",
                      "event_name": "account_deletion_reviewed",
                      "integrity_seal": "sha256:" + "ab" * 32}
                 ]},
            ],
        },
    )
    return dataset, "case_hist"


def _build_temporal_recreation(root: Path) -> tuple[Path, str]:
    """A sync job recreates the profile after the "successful" deletion."""

    dataset = root / "dataset"
    (dataset / "evidence").mkdir(parents=True, exist_ok=True)

    _write_csv(
        dataset / "deletion_requests.csv",
        REQUEST_HEADER,
        [
            "case_sync,recreated@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-09T00:00:00Z,Please delete my account.",
        ],
    )
    _write_csv(
        dataset / "user_identities.csv",
        IDENTITY_HEADER,
        ["user_sync,Alan Turing,recreated@example.com,+44 20 7946 0002,cc33dd44,2026-02-01T00:00:00Z"],
    )
    _write_csv(dataset / "user_audit_log.csv", AUDIT_HEADER, [])
    _write_csv(
        dataset / "system_activity.csv",
        ACTIVITY_HEADER,
        [
            # In-window sync that recreates the profile downstream.
            "activity_sync,2026-03-06T02:00:00Z,SYNC_RECORD,account_service,search_service,"
            "search_sync,SUCCESS,Active connector repopulated downstream resource with the profile.",
            # A check confirming the flow is still enabled.
            "activity_flow,2026-03-06T03:00:00Z,CHECK_DATA_FLOW,account_service,search_service,"
            "search_sync,SUCCESS,Sync remains enabled and can copy the profile again.",
        ],
    )
    _write_csv(dataset / "deletion_rules.csv", RULE_HEADER, [RULE_PROFILE, RULE_SEARCH])
    _write_csv(
        dataset / "evidence_files.csv",
        EVIDENCE_HEADER,
        ["evidence_sync,evidence/records/search_sync.json,search_service,2026-03-06T04:00:00Z"],
    )
    _write_json(
        dataset / "evidence" / "records" / "search_sync.json",
        {
            "exported_at": "2026-03-06T04:00:00Z",
            "snapshots": [
                # The account store is complete and empty for the subject (deleted)...
                {"data_store": "account_service", "collection": "customer_profiles",
                 "complete": True, "records": []},
                # ...but the search store holds the recreated copy.
                {"data_store": "search_service", "collection": "customer_search_documents",
                 "records": [
                     {"resource_id": "search_sync", "email": "recreated@example.com",
                      "user_id": "user_sync"}
                 ]},
            ],
        },
    )
    return dataset, "case_sync"


def _build_tombstone_retention(root: Path) -> tuple[Path, str]:
    """A tombstone keeps the stable ``user_id`` while direct identifiers are redacted."""

    dataset = root / "dataset"
    (dataset / "evidence").mkdir(parents=True, exist_ok=True)

    _write_csv(
        dataset / "deletion_requests.csv",
        REQUEST_HEADER,
        [
            "case_tomb,retained@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-11T00:00:00Z,Please delete my account.",
        ],
    )
    _write_csv(
        dataset / "user_identities.csv",
        IDENTITY_HEADER,
        ["user_tomb,Grace Hopper,retained@example.com,+44 20 7946 0003,ee55ff66,2026-02-01T00:00:00Z"],
    )
    _write_csv(dataset / "user_audit_log.csv", AUDIT_HEADER, [])
    _write_csv(dataset / "system_activity.csv", ACTIVITY_HEADER, [])
    _write_csv(dataset / "deletion_rules.csv", RULE_HEADER, [RULE_SECURITY, RULE_TOMBSTONE])
    _write_csv(
        dataset / "evidence_files.csv",
        EVIDENCE_HEADER,
        ["evidence_tomb,evidence/records/tomb.json,identity_service,2026-03-05T00:00:00Z"],
    )
    _write_json(
        dataset / "evidence" / "records" / "tomb.json",
        {
            "exported_at": "2026-03-05T00:00:00Z",
            "snapshots": [
                {
                    "data_store": "identity_service",
                    "collection": "account_tombstones",
                    "complete": True,
                    "records": [
                        # Redacted in place: stable reference remains, direct ids are null.
                        {"resource_id": "tombstone_tomb", "subject_reference": "user_tomb",
                         "email": "null", "phone": "null", "email_hash": "null",
                         "account_status": "DELETED"}
                    ],
                },
                {
                    "data_store": "security_service",
                    "collection": "security_audit_events",
                    "complete": True,
                    "records": [
                        {"resource_id": "audit_record_tomb", "subject_reference": "user_tomb",
                         "event_name": "account_deletion_reviewed",
                         "integrity_seal": "sha256:" + "ef" * 32}
                    ],
                },
            ],
        },
    )
    return dataset, "case_tomb"


def _build_late_evidence_ignored(root: Path) -> tuple[Path, str]:
    """Evidence captured after ``audit_at`` must not change the decision."""

    dataset = root / "dataset"
    (dataset / "evidence").mkdir(parents=True, exist_ok=True)

    _write_csv(
        dataset / "deletion_requests.csv",
        REQUEST_HEADER,
        [
            "case_late,late@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-10T00:00:00Z,Please delete my account.",
        ],
    )
    _write_csv(
        dataset / "user_identities.csv",
        IDENTITY_HEADER,
        ["user_late,Marie Curie,late@example.com,+44 20 7946 0004,gg77hh88,2026-02-01T00:00:00Z"],
    )
    _write_csv(dataset / "user_audit_log.csv", AUDIT_HEADER, [])
    _write_csv(dataset / "system_activity.csv", ACTIVITY_HEADER, [])
    _write_csv(dataset / "deletion_rules.csv", RULE_HEADER, [RULE_PROFILE, RULE_SECURITY])
    _write_csv(
        dataset / "evidence_files.csv",
        EVIDENCE_HEADER,
        [
            "evidence_inwin,evidence/records/inwin.json,records_assurance_service,2026-03-05T00:00:00Z",
            "evidence_late,evidence/records/late.json,records_assurance_service,2026-03-25T00:00:00Z",
        ],
    )
    # The in-window read names the subject (so the file is attributed) but the complete
    # account listing holds no row for them.
    _write_json(
        dataset / "evidence" / "records" / "inwin.json",
        {
            "exported_at": "2026-03-05T00:00:00Z",
            "snapshots": [
                {"data_store": "account_service", "collection": "customer_profiles",
                 "complete": True, "records": []},
                {"data_store": "security_service", "collection": "security_audit_events",
                 "records": [
                     {"resource_id": "audit_record_late", "subject_reference": "user_late",
                      "event_name": "account_deletion_reviewed",
                      "integrity_seal": "sha256:" + "cd" * 32}
                 ]},
            ],
        },
    )
    # A late read (captured after audit_at) shows a profile reappearing; it must be ignored.
    _write_json(
        dataset / "evidence" / "records" / "late.json",
        {
            "exported_at": "2026-03-25T00:00:00Z",
            "snapshots": [
                {"data_store": "account_service", "collection": "customer_profiles",
                 "records": [
                     {"resource_id": "account_late", "email": "late@example.com",
                      "user_id": "user_late"}
                 ]},
            ],
        },
    )
    return dataset, "case_late"


CASES: tuple[CustomCase, ...] = (
    CustomCase(
        name="historical_identifier",
        focus="historical identifier resolution",
        expected_status="COMPLETE",
        expected_behaviour=(
            "The request arrives under the subject's historical email. The audit must resolve "
            "the same subject, prove the account record absent from the declared-complete "
            "snapshot, and prove the retained security record present — never a delete against "
            "the retained store."
        ),
        build=_build_historical_identifier,
    ),
    CustomCase(
        name="temporal_recreation",
        focus="temporal recreation by an active flow",
        expected_status="INCOMPLETE",
        expected_behaviour=(
            "A sync job recreated the profile inside the window. The audit must report the "
            "active flow and the remaining record and never trust the workflow's COMPLETE claim."
        ),
        build=_build_temporal_recreation,
    ),
    CustomCase(
        name="tombstone_retention",
        focus="tombstone redaction and retention",
        expected_status="COMPLETE",
        expected_behaviour=(
            "The tombstone keeps the stable user_id; the audit must emit a redaction check "
            "(not a delete) against the tombstone and a presence check for the retained legal "
            "record."
        ),
        build=_build_tombstone_retention,
    ),
    CustomCase(
        name="late_evidence_ignored",
        focus="audit_at cutoff",
        expected_status="COMPLETE",
        expected_behaviour=(
            "A file captured after audit_at shows the record reappearing. The audit must "
            "answer from the in-window declared-complete snapshot and never cite the late file."
        ),
        build=_build_late_evidence_ignored,
    ),
)


# --------------------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------------------


def run_case(case: CustomCase, workdir: Path | None = None) -> dict:
    """Run one authored case and return a structured result (prediction + pass/fail)."""

    from ghostwatch.ingest import load_dataset
    from ghostwatch.planner import ParticipantContext, audit

    base = Path(tempfile.mkdtemp(prefix=f"gwcase_{case.name}_", dir=str(workdir) if workdir else None))
    try:
        dataset_dir, case_id = case.build(base)
        dataset = load_dataset(dataset_dir)
        context = ParticipantContext(dataset)
        request = dataset.request(case_id)
        result = audit(request, context)
        steps = json.loads(result.steps_json)
        operations = [step["operation"] for step in steps]
        resource_ids = {step["resource_id"] for step in steps}
        evidence_ids = {step["evidence_id"] for step in steps if step["evidence_id"]}
        passed, note = _check(case, result, operations, resource_ids, evidence_ids)
        return {
            "name": case.name,
            "focus": case.focus,
            "case_id": case_id,
            "expected_status": case.expected_status,
            "predicted_status": result.deletion_status,
            "operations": operations,
            "resource_ids": sorted(resource_ids),
            "evidence_ids": sorted(evidence_ids),
            "steps": steps,
            "passed": passed,
            "note": note,
            "gaps": [{"kind": gap.kind, "blocking": gap.blocking} for gap in result.gaps],
        }
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _check(
    case: CustomCase,
    result,
    operations: list[str],
    resource_ids: set[str],
    evidence_ids: set[str],
) -> tuple[bool, str]:
    problems: list[str] = []
    if result.deletion_status != case.expected_status:
        problems.append(f"status {result.deletion_status!r} != expected {case.expected_status!r}")

    if case.name == "historical_identifier":
        if "VERIFY_RECORD_ABSENT" not in operations:
            problems.append("missing VERIFY_RECORD_ABSENT for the deleted account")
        if "VERIFY_RECORD_PRESENT" not in operations:
            problems.append("missing VERIFY_RECORD_PRESENT for the retained security record")
        if "DELETE_RECORD" in operations:
            problems.append("a delete remediation was issued on a completed deletion")
    elif case.name == "temporal_recreation":
        if "REPORT_ACTIVE_DATA_FLOW" not in operations:
            problems.append("missing REPORT_ACTIVE_DATA_FLOW for the recreating sync")
        if "DISABLE_DATA_FLOW" not in operations:
            problems.append("missing DISABLE_DATA_FLOW remediation")
        if "REPORT_REMAINING_RECORD" not in operations:
            problems.append("missing REPORT_REMAINING_RECORD for the recreated copy")
        # Order: a flow must be disabled before a dependent record is deleted.
        if "DISABLE_DATA_FLOW" in operations and "DELETE_RECORD" in operations:
            if operations.index("DISABLE_DATA_FLOW") > operations.index("DELETE_RECORD"):
                problems.append("DELETE_RECORD ordered before DISABLE_DATA_FLOW")
    elif case.name == "tombstone_retention":
        if "VERIFY_RECORD_REDACTED" not in operations:
            problems.append("missing VERIFY_RECORD_REDACTED for the tombstone")
        if "DELETE_RECORD" in operations or "VERIFY_RECORD_ABSENT" in operations:
            problems.append("an absence treatment was issued against a retained record")
        if "VERIFY_RECORD_PRESENT" not in operations:
            problems.append("retained security record not verified present")
    elif case.name == "late_evidence_ignored":
        if "evidence_late" in evidence_ids:
            problems.append("cited evidence captured after audit_at")
        if "evidence_inwin" not in evidence_ids:
            problems.append("did not cite the in-window evidence")

    note = "ok" if not problems else "; ".join(problems)
    return not problems, note


def run_all(workdir: Path | None = None) -> list[dict]:
    return [run_case(case, workdir) for case in CASES]


def format_report(results: list[dict]) -> str:
    """Render the authored-case results as a Markdown section."""

    lines = ["### Authored evaluation cases", ""]
    lines.append("| Case | Focus | Expected status | Predicted status | Result |")
    lines.append("| --- | --- | --- | --- | --- |")
    for record in results:
        flag = "PASS" if record["passed"] else "FAIL"
        lines.append(
            f"| `{record['name']}` | {record['focus']} | {record['expected_status']} | "
            f"{record['predicted_status']} | {flag} |"
        )
    lines.append("")
    for record in results:
        lines.append(f"**`{record['name']}`** — {record['focus']}")
        lines.append("")
        lines.append(f"- operations: {', '.join(record['operations']) or '(none)'}")
        lines.append(f"- resources: {', '.join(record['resource_ids']) or '(none)'}")
        lines.append(f"- check: {record['note']}")
        lines.append("")
    return "\n".join(lines)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Argument parser for the authored-case runner.

    The fixtures are self-contained: they build their own tiny datasets in a temporary
    directory and never read the participant ``dataset/`` directory (or its labels). There
    is therefore no ``--dataset`` option — passing one is rejected rather than silently
    ignored, so a caller cannot believe a supplied dataset influenced the fixtures.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Run the participant-authored evaluation cases. These fixtures are self-contained "
            "and take no dataset; unknown arguments (including --dataset) are rejected."
        )
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _build_arg_parser().parse_args(argv)
    results = run_all()
    print(format_report(results))
    return 0 if all(record["passed"] for record in results) else 1


if __name__ == "__main__":  # pragma: no cover - manual run
    raise SystemExit(main())
