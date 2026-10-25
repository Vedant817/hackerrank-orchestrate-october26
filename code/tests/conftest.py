"""Shared test configuration for the T01 ingestion layer.

The delivered module lives in ``code/ghostwatch``. It is imported here by putting the
``code`` directory on ``sys.path`` so the tests run from a clean checkout without an
installed package and without depending on the ignored starter ``ghostwatch/`` tree.

Fixtures build small, self-contained datasets under ``tmp_path``. Public sample requests
(``dataset/sample_deletion_requests.csv``) may be loaded through the explicit
``include_samples`` switch; ``sample_output.csv`` is never read by the package or by these
tests because it holds evaluation labels.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
DATASET_DIR = REPO_ROOT / "dataset"

if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def dataset_dir() -> Path:
    return DATASET_DIR


@pytest.fixture(scope="session")
def real_dataset():
    """The participant dataset, loaded once for smoke coverage."""

    from ghostwatch.ingest import load_dataset

    return load_dataset(DATASET_DIR)


REQUEST_HEADER = "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text"
IDENTITY_HEADER = "user_id,name,email,phone,email_hash,updated_at"
AUDIT_HEADER = "audit_id,user_id,event_time,field_name,old_value,new_value"
ACTIVITY_HEADER = (
    "activity_id,event_time,event_type,source_system,target_system,resource_id,"
    "reported_result,details"
)
RULE_HEADER = "rule_id,data_category,condition,required_action"
EVIDENCE_HEADER = "file_id,file_path,origin,captured_at"


def write_csv(path: Path, header: str, rows: list[str]) -> Path:
    """Write a small CSV fixture with the given header and raw rows."""

    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join([header, *rows])
    path.write_text(body + "\n", encoding="utf-8")
    return path


@pytest.fixture
def mini_dataset(tmp_path: Path):
    """Build a minimal, internally consistent participant dataset.

    Two subjects are created. ``user_a`` changes its email half-way through its history so
    historical-identifier resolution can be exercised; ``user_b`` is an unrelated person
    used to prove decoy exclusion. Evidence is added per test through the returned helper.
    """

    from ghostwatch.ingest import load_dataset

    dataset_root = tmp_path / "dataset"
    (dataset_root / "evidence").mkdir(parents=True)

    write_csv(
        dataset_root / "deletion_requests.csv",
        REQUEST_HEADER,
        [
            "case_a,old.address@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-05T00:00:00Z,Please delete my account.",
        ],
    )
    write_csv(
        dataset_root / "user_identities.csv",
        IDENTITY_HEADER,
        [
            "user_a,Ada Lovelace,new.address@example.com,+44 20 7946 0001,"
            "aa11,2026-02-01T00:00:00Z",
            "user_b,Grace Hopper,g.hopper@example.com,+1 202 555 0100,"
            "bb22,2026-01-01T00:00:00Z",
        ],
    )
    write_csv(
        dataset_root / "user_audit_log.csv",
        AUDIT_HEADER,
        [
            "audit_01,user_a,2026-01-15T00:00:00Z,email,"
            "old.address@example.com,new.address@example.com",
        ],
    )
    write_csv(
        dataset_root / "system_activity.csv",
        ACTIVITY_HEADER,
        [
            "activity_01,2026-03-01T12:00:00Z,SYNC_RECORD,account_service,"
            "search_service,search_a,SUCCESS,Synced search_a.",
        ],
    )
    write_csv(
        dataset_root / "deletion_rules.csv",
        RULE_HEADER,
        [
            "rule_01,USER_PROFILE,Always,DELETE",
            "rule_02,ACCOUNT_TOMBSTONE,Stable reference needed,REDACT",
        ],
    )
    write_csv(
        dataset_root / "evidence_files.csv",
        EVIDENCE_HEADER,
        [],
    )

    def add_evidence(file_id: str, relative: str, origin: str, captured_at: str) -> Path:
        write_csv(
            dataset_root / "evidence_files.csv",
            EVIDENCE_HEADER,
            [
                *[
                    line
                    for line in (dataset_root / "evidence_files.csv")
                    .read_text(encoding="utf-8")
                    .splitlines()[1:]
                    if line.strip()
                ],
                f"{file_id},{relative},{origin},{captured_at}",
            ],
        )
        target = dataset_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    return {
        "root": dataset_root,
        "load": lambda **kwargs: load_dataset(dataset_root, **kwargs),
        "add_evidence": add_evidence,
    }
