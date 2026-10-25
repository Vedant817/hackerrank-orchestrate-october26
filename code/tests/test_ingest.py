"""T01 acceptance tests for participant CSV ingestion."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from conftest import (
    ACTIVITY_HEADER,
    AUDIT_HEADER,
    EVIDENCE_HEADER,
    IDENTITY_HEADER,
    REQUEST_HEADER,
    RULE_HEADER,
    write_csv,
)

from ghostwatch.ingest import (
    ACTIVITY_COLUMNS,
    AUDIT_COLUMNS,
    EVIDENCE_COLUMNS,
    IDENTITY_COLUMNS,
    REQUEST_COLUMNS,
    RULE_COLUMNS,
    DatasetNotFoundError,
    DuplicateRecordId,
    SchemaError,
    TimestampFormatError,
    default_dataset_root,
    format_timestamp,
    load_dataset,
    normalise_email,
    parse_timestamp,
    project_root,
)

UTC = dt.timezone.utc

AUDIT_HEADER_FIXTURE = AUDIT_HEADER
ACTIVITY_HEADER_FIXTURE = ACTIVITY_HEADER
RULE_HEADER_FIXTURE = RULE_HEADER


# --------------------------------------------------------------------------------------
# Schema, identifiers and duplicates
# --------------------------------------------------------------------------------------


def test_csv_schema_and_duplicate_ids(mini_dataset, tmp_path: Path) -> None:
    """The loader accepts the documented schema and rejects a duplicate identifier."""

    dataset = mini_dataset["load"]()
    assert dataset.case_ids == ("case_a",)
    assert dataset.describe()["requests"] == 1

    # Every participant file declares the schema the package expects; the contract in the
    # problem statement fixes those column names, so a silent change must fail loudly.
    assert REQUEST_COLUMNS == (
        "case_id",
        "email",
        "requested_at",
        "reported_status",
        "reported_at",
        "audit_at",
        "request_text",
    )
    assert IDENTITY_COLUMNS == ("user_id", "name", "email", "phone", "email_hash", "updated_at")
    assert AUDIT_COLUMNS == ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value")
    assert ACTIVITY_COLUMNS[0] == "activity_id"
    assert EVIDENCE_COLUMNS == ("file_id", "file_path", "origin", "captured_at")
    assert RULE_COLUMNS == ("rule_id", "data_category", "condition", "required_action")

    # A wrong header is a schema error naming the file.
    bad_root = tmp_path / "bad"
    (bad_root / "evidence").mkdir(parents=True)
    write_csv(bad_root / "deletion_requests.csv", "case_id,email\n", ["case_x,a@b.com"])
    with pytest.raises(SchemaError) as excinfo:
        load_dataset(bad_root)
    assert "deletion_requests.csv" in str(excinfo.value)

    # Two rows sharing a case_id must be rejected, not silently collapsed.
    dup_root = tmp_path / "dup"
    (dup_root / "evidence").mkdir(parents=True)
    write_csv(
        dup_root / "deletion_requests.csv",
        REQUEST_HEADER,
        [
            "case_a,a@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-05T00:00:00Z,delete",
            "case_a,a@example.com,2026-03-01T00:00:00Z,COMPLETE,"
            "2026-03-02T00:00:00Z,2026-03-05T00:00:00Z,delete",
        ],
    )
    write_csv(dup_root / "user_identities.csv", IDENTITY_HEADER, [])
    write_csv(dup_root / "user_audit_log.csv", AUDIT_HEADER_FIXTURE, [])
    write_csv(dup_root / "system_activity.csv", ACTIVITY_HEADER_FIXTURE, [])
    write_csv(dup_root / "deletion_rules.csv", RULE_HEADER_FIXTURE, ["rule_01,USER_PROFILE,Always,DELETE"])
    write_csv(dup_root / "evidence_files.csv", EVIDENCE_HEADER, [])
    with pytest.raises(DuplicateRecordId) as excinfo:
        load_dataset(dup_root)
    assert "case_a" in str(excinfo.value)


def test_duplicate_identity_and_evidence_ids_rejected(tmp_path: Path) -> None:
    """Identity and evidence identifiers are unique per the contract."""

    root = tmp_path / "dup2"
    (root / "evidence").mkdir(parents=True)
    write_csv(
        root / "deletion_requests.csv",
        REQUEST_HEADER,
        ["case_a,a@example.com,2026-03-01T00:00:00Z,COMPLETE,"
         "2026-03-02T00:00:00Z,2026-03-05T00:00:00Z,delete"],
    )
    write_csv(
        root / "user_identities.csv",
        IDENTITY_HEADER,
        [
            "user_a,Ada,ada@example.com,+44 1,aa,2026-01-01T00:00:00Z",
            "user_a,Ada,ada@example.com,+44 1,aa,2026-01-01T00:00:00Z",
        ],
    )
    write_csv(root / "user_audit_log.csv", AUDIT_HEADER_FIXTURE, [])
    write_csv(root / "system_activity.csv", ACTIVITY_HEADER_FIXTURE, [])
    write_csv(root / "deletion_rules.csv", RULE_HEADER_FIXTURE, ["rule_01,USER_PROFILE,Always,DELETE"])
    write_csv(root / "evidence_files.csv", EVIDENCE_HEADER, [])
    with pytest.raises(DuplicateRecordId):
        load_dataset(root)


def test_missing_dataset_reports_the_path(tmp_path: Path) -> None:
    with pytest.raises(DatasetNotFoundError) as excinfo:
        load_dataset(tmp_path / "nope")
    assert "nope" in str(excinfo.value)


# --------------------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------------------


def test_timestamp_parsing_requires_a_timezone() -> None:
    parsed = parse_timestamp("2026-03-01T12:30:45Z")
    assert parsed == dt.datetime(2026, 3, 1, 12, 30, 45, tzinfo=UTC)
    assert format_timestamp(parsed) == "2026-03-01T12:30:45Z"

    # An offset is normalised to UTC so comparisons across zones are exact.
    assert parse_timestamp("2026-03-01T14:30:45+02:00") == parsed

    # A naive stamp is refused: guessing a zone would move evidence across audit_at.
    with pytest.raises(TimestampFormatError):
        parse_timestamp("2026-03-01T12:30:45")


def test_timestamp_errors_name_the_field_and_source() -> None:
    with pytest.raises(TimestampFormatError) as excinfo:
        parse_timestamp("not-a-time", field="audit_at", source="deletion_requests.csv:7")
    message = str(excinfo.value)
    assert "audit_at" in message and "deletion_requests.csv:7" in message


# --------------------------------------------------------------------------------------
# Paths and normalisation
# --------------------------------------------------------------------------------------


def test_dataset_root_defaults_to_repository_dataset() -> None:
    root = project_root()
    assert (root / "AGENTS.md").is_file()
    assert default_dataset_root() == root / "dataset"


def test_dataset_root_environment_override(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GHOSTWATCH_DATASET_DIR", str(tmp_path))
    assert default_dataset_root() == tmp_path.resolve()


def test_normalise_email_is_case_and_space_insensitive() -> None:
    assert normalise_email("  Ada.Lovelace@Example.COM ") == "ada.lovelace@example.com"


def test_bom_and_blank_lines_are_tolerated(tmp_path: Path) -> None:
    """A UTF-8 BOM and trailing blank lines must not break the loader."""

    root = tmp_path / "bom"
    (root / "evidence").mkdir(parents=True)
    request = root / "deletion_requests.csv"
    request.write_text(
        "\ufeff" + REQUEST_HEADER + "\n"
        "case_a,a@example.com,2026-03-01T00:00:00Z,COMPLETE,"
        "2026-03-02T00:00:00Z,2026-03-05T00:00:00Z,delete\n\n",
        encoding="utf-8",
    )
    write_csv(root / "user_identities.csv", IDENTITY_HEADER, [])
    write_csv(root / "user_audit_log.csv", AUDIT_HEADER_FIXTURE, [])
    write_csv(root / "system_activity.csv", ACTIVITY_HEADER_FIXTURE, [])
    write_csv(root / "deletion_rules.csv", RULE_HEADER_FIXTURE, ["rule_01,USER_PROFILE,Always,DELETE"])
    write_csv(root / "evidence_files.csv", EVIDENCE_HEADER, [])
    dataset = load_dataset(root)
    assert dataset.case_ids == ("case_a",)


def test_sample_output_is_never_loaded(mini_dataset) -> None:
    """``sample_output.csv`` holds evaluation labels and must not be ingested."""

    dataset = mini_dataset["load"]()
    # Even when a sample_output.csv exists beside the dataset, nothing reads it.
    (mini_dataset["root"] / "sample_output.csv").write_text(
        "case_id,deletion_status,steps_json\ncase_a,COMPLETE,[]\n", encoding="utf-8"
    )
    reloaded = mini_dataset["load"]()
    assert reloaded.sample_requests == ()
    assert not hasattr(dataset, "sample_output")


def test_public_samples_load_only_with_the_explicit_switch(dataset_dir: Path) -> None:
    """Real sample requests load behind ``include_samples``; labels never do."""

    default = load_dataset(dataset_dir)
    assert default.sample_requests == ()

    with_samples = load_dataset(dataset_dir, include_samples=True)
    assert len(with_samples.sample_requests) == 32
    assert len(with_samples.requests) == 518
