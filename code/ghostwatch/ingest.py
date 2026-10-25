"""Ingestion of the participant-facing dataset.

The module is the only place that opens files under ``dataset/``. It validates the
documented schema, rejects duplicate identifiers, normalises timestamps to timezone
aware UTC datetimes, and exposes immutable records so later layers cannot mutate the
loaded snapshot.

Design notes:

* Paths are resolved from the repository layout, not from hard-coded user paths, so a
  clone, a rename or a worktree keeps working.
* ``sample_output.csv`` is never read here. Sample requests are public and may be
  loaded with the explicit ``include_samples=True`` switch for local fixtures only.
* Schema problems raise :class:`SchemaError` subclasses with the file, the column and
  the row number. Silently coercing a malformed row would produce a confident but
  wrong audit.
"""

from __future__ import annotations

import csv
import dataclasses
import datetime as _dt
import functools
import os
import re
from pathlib import Path
from typing import Iterator, Mapping, Sequence

UTC = _dt.timezone.utc

DATASET_DIRNAME = "dataset"
EVIDENCE_DIRNAME = "evidence"

#: Environment override used by tests and by the eventual runner. It is optional; the
#: documented default is ``<repository root>/dataset``.
DATASET_ENV_VAR = "GHOSTWATCH_DATASET_DIR"


class DatasetError(RuntimeError):
    """Base class for every ingestion problem."""


class DatasetNotFoundError(DatasetError):
    """The dataset directory or a required participant CSV is missing."""


class SchemaError(DatasetError):
    """A participant CSV does not match the documented schema."""


class DuplicateRecordId(SchemaError):
    """Two rows share an identifier that the contract requires to be unique."""


class TimestampFormatError(SchemaError):
    """A timestamp is missing, naive, or not in an accepted ISO-8601 form."""


# --------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------


def project_root(start: os.PathLike[str] | str | None = None) -> Path:
    """Return the repository root.

    ``start`` defaults to this file. Walking up from ``code/ghostwatch/ingest.py``
    yields ``code/ghostwatch`` -> ``code`` -> repository root.
    """

    if start is not None:
        return Path(start).resolve()
    return Path(__file__).resolve().parents[2]


def default_dataset_root() -> Path:
    """Return the dataset root: the environment override, else ``<repo root>/dataset``."""

    override = os.environ.get(DATASET_ENV_VAR, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return project_root() / DATASET_DIRNAME


# --------------------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})"
    r"[T ](?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d{1,9})?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


@functools.lru_cache(maxsize=200_000)
def _parse_timestamp(raw: str) -> _dt.datetime:
    text = raw.strip()
    if not text:
        raise TimestampFormatError("empty timestamp")
    match = _TIMESTAMP_RE.match(text)
    if match is None:
        raise TimestampFormatError(f"unsupported timestamp format: {raw!r}")
    zone = match.group("tz")
    if not zone:
        raise TimestampFormatError(f"timestamp without timezone offset: {raw!r}")
    if zone == "Z":
        offset = _dt.timedelta(0)
    else:
        sign = 1 if zone[0] == "+" else -1
        body = zone[1:].replace(":", "")
        offset = sign * _dt.timedelta(hours=int(body[:2]), minutes=int(body[2:]))
    fraction = match.group("frac") or ""
    microseconds = 0
    if fraction:
        microseconds = int(round(float(fraction) * 1_000_000))
        microseconds = min(microseconds, 999_999)
    stamp = _dt.datetime(
        *_parse_date_parts(match.group("date")),
        *_parse_time_parts(match.group("time")),
        microsecond=microseconds,
        tzinfo=_dt.timezone(offset),
    )
    return stamp.astimezone(UTC)


def _parse_date_parts(text: str) -> tuple[int, int, int]:
    year, month, day = text.split("-")
    return int(year), int(month), int(day)


def _parse_time_parts(text: str) -> tuple[int, int, int]:
    hour, minute, second = text.split(":")
    return int(hour), int(minute), int(second)


def parse_timestamp(raw: str, *, field: str = "timestamp", source: str = "input") -> _dt.datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Naive timestamps are rejected: the audit cutoff is meaningless without a zone, and
    guessing UTC would silently shift evidence across the ``audit_at`` boundary.
    """

    try:
        return _parse_timestamp(raw)
    except TimestampFormatError as exc:
        raise TimestampFormatError(f"{source}: field {field!r}: {exc}") from exc


def format_timestamp(value: _dt.datetime) -> str:
    """Render a datetime in the dataset's canonical ``...Z`` form."""

    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------
# Text normalisation helpers
# --------------------------------------------------------------------------------------

_WHITESPACE_RE = re.compile(r"\s+")


def clean_text(value: str | None) -> str:
    """Collapse whitespace and strip non-breaking spaces."""

    if value is None:
        return ""
    return _WHITESPACE_RE.sub(" ", str(value).replace("\u00a0", " ")).strip()


def normalise_email(value: str | None) -> str:
    """Case-fold and trim an email address for comparison."""

    return clean_text(value).casefold()


def digits_only(value: str | None) -> str:
    """Return only the decimal digits of a phone number."""

    return re.sub(r"\D", "", value or "")


def normalise_identifier(kind: str, value: str | None) -> str:
    """Normalise an identifier value according to its kind."""

    if kind == "email":
        return normalise_email(value)
    if kind == "email_hash":
        return clean_text(value).lower()
    if kind == "phone":
        return digits_only(value)
    if kind in {"user_id", "resource_id"}:
        return clean_text(value).casefold()
    return clean_text(value)


# --------------------------------------------------------------------------------------
# Schema definitions
# --------------------------------------------------------------------------------------

REQUEST_COLUMNS = (
    "case_id",
    "email",
    "requested_at",
    "reported_status",
    "reported_at",
    "audit_at",
    "request_text",
)
IDENTITY_COLUMNS = ("user_id", "name", "email", "phone", "email_hash", "updated_at")
AUDIT_COLUMNS = ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value")
ACTIVITY_COLUMNS = (
    "activity_id",
    "event_time",
    "event_type",
    "source_system",
    "target_system",
    "resource_id",
    "reported_result",
    "details",
)
RULE_COLUMNS = ("rule_id", "data_category", "condition", "required_action")
EVIDENCE_COLUMNS = ("file_id", "file_path", "origin", "captured_at")

SCHEMAS: Mapping[str, tuple[str, ...]] = {
    "deletion_requests.csv": REQUEST_COLUMNS,
    "sample_deletion_requests.csv": REQUEST_COLUMNS,
    "user_identities.csv": IDENTITY_COLUMNS,
    "user_audit_log.csv": AUDIT_COLUMNS,
    "system_activity.csv": ACTIVITY_COLUMNS,
    "deletion_rules.csv": RULE_COLUMNS,
    "evidence_files.csv": EVIDENCE_COLUMNS,
}

REPORTED_STATUSES = frozenset({"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"})
RULE_ACTIONS = frozenset(
    {"DELETE", "REDACT", "ANONYMIZE", "RETAIN", "PRESERVE_TOMBSTONE"}
)
IDENTITY_FIELDS = frozenset({"email", "phone", "email_hash"})


# --------------------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class DeletionRequest:
    """One audit case from ``deletion_requests.csv``."""

    case_id: str
    email: str
    requested_at: _dt.datetime
    reported_status: str
    reported_at: _dt.datetime
    audit_at: _dt.datetime
    request_text: str
    source_row: int = dataclasses.field(default=0, compare=False)

    @property
    def status_is_claim(self) -> bool:
        """The workflow status is a claim, never proof; kept for readability at call sites."""

        return True

    def as_dict(self) -> dict[str, str]:
        return {
            "case_id": self.case_id,
            "email": self.email,
            "requested_at": format_timestamp(self.requested_at),
            "reported_status": self.reported_status,
            "reported_at": format_timestamp(self.reported_at),
            "audit_at": format_timestamp(self.audit_at),
            "request_text": self.request_text,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class UserIdentity:
    """The current identity snapshot row for one subject."""

    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: _dt.datetime
    source_row: int = dataclasses.field(default=0, compare=False)

    def field_value(self, field: str) -> str:
        if field not in IDENTITY_FIELDS:
            raise KeyError(f"{field!r} is not a changing identity field")
        return getattr(self, field)


@dataclasses.dataclass(frozen=True, slots=True)
class IdentityAuditEntry:
    """One historical identity change."""

    audit_id: str
    user_id: str
    event_time: _dt.datetime
    field_name: str
    old_value: str
    new_value: str
    source_row: int = dataclasses.field(default=0, compare=False)


@dataclasses.dataclass(frozen=True, slots=True)
class ActivityEvent:
    """One row of the global ``system_activity.csv`` stream.

    ``reported_result`` is explicitly a claim made by the emitting system.
    """

    activity_id: str
    event_time: _dt.datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    source_row: int = dataclasses.field(default=0, compare=False)


@dataclasses.dataclass(frozen=True, slots=True)
class DeletionRule:
    """One policy row from ``deletion_rules.csv``."""

    rule_id: str
    data_category: str
    condition: str
    required_action: str
    source_row: int = dataclasses.field(default=0, compare=False)


@dataclasses.dataclass(frozen=True, slots=True)
class EvidenceFile:
    """One manifest entry pointing at a participant evidence file."""

    file_id: str
    file_path: str
    origin: str
    captured_at: _dt.datetime
    source_row: int = dataclasses.field(default=0, compare=False)


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def _open_csv(path: Path, columns: Sequence[str]) -> Iterator[tuple[int, dict[str, str]]]:
    if not path.is_file():
        raise DatasetNotFoundError(f"missing participant file: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration as exc:  # pragma: no cover - empty file
            raise SchemaError(f"{path.name}: file is empty") from exc
        header = [cell.strip() for cell in header]
        if tuple(header) != tuple(columns):
            raise SchemaError(
                f"{path.name}: unexpected header. expected {list(columns)} but found {header}"
            )
        for line_no, row in enumerate(reader, start=2):
            if not row or all(not cell.strip() for cell in row):
                continue
            if len(row) != len(columns):
                raise SchemaError(
                    f"{path.name}: row {line_no} has {len(row)} cells, expected {len(columns)}"
                )
            yield line_no, {name: cell for name, cell in zip(columns, row)}


def _require(row: Mapping[str, str], column: str, *, filename: str, line_no: int) -> str:
    value = row[column].strip()
    if not value:
        raise SchemaError(f"{filename}: row {line_no} has an empty {column!r}")
    return value


def _check_unique(seen: dict[str, int], value: str, *, column: str, filename: str, line_no: int) -> None:
    if value in seen:
        raise DuplicateRecordId(
            f"{filename}: duplicate {column} {value!r} at rows {seen[value]} and {line_no}"
        )
    seen[value] = line_no


def _load_rows(
    path: Path,
    columns: Sequence[str],
) -> list[tuple[int, dict[str, str]]]:
    return list(_open_csv(path, columns))


def _load_requests(path: Path, *, filename: str) -> tuple[DeletionRequest, ...]:
    seen: dict[str, int] = {}
    requests: list[DeletionRequest] = []
    for line_no, row in _load_rows(path, REQUEST_COLUMNS):
        case_id = _require(row, "case_id", filename=filename, line_no=line_no)
        _check_unique(seen, case_id, column="case_id", filename=filename, line_no=line_no)
        requests.append(
            DeletionRequest(
                case_id=case_id,
                email=_require(row, "email", filename=filename, line_no=line_no),
                requested_at=parse_timestamp(row["requested_at"], field="requested_at", source=f"{filename}:{line_no}"),
                reported_status=clean_text(row["reported_status"]).upper(),
                reported_at=parse_timestamp(row["reported_at"], field="reported_at", source=f"{filename}:{line_no}"),
                audit_at=parse_timestamp(row["audit_at"], field="audit_at", source=f"{filename}:{line_no}"),
                request_text=clean_text(row["request_text"]),
                source_row=line_no,
            )
        )
    if not requests:
        raise SchemaError(f"{filename}: no request rows found")
    return tuple(requests)


def _load_identities(path: Path) -> tuple[UserIdentity, ...]:
    filename = path.name
    seen: dict[str, int] = {}
    identities: list[UserIdentity] = []
    for line_no, row in _load_rows(path, IDENTITY_COLUMNS):
        user_id = _require(row, "user_id", filename=filename, line_no=line_no)
        _check_unique(seen, user_id, column="user_id", filename=filename, line_no=line_no)
        identities.append(
            UserIdentity(
                user_id=user_id,
                name=clean_text(row["name"]),
                email=clean_text(row["email"]),
                phone=clean_text(row["phone"]),
                email_hash=clean_text(row["email_hash"]),
                updated_at=parse_timestamp(row["updated_at"], field="updated_at", source=f"{filename}:{line_no}"),
                source_row=line_no,
            )
        )
    return tuple(identities)


def _load_audit_log(path: Path, *, known_users: set[str]) -> tuple[IdentityAuditEntry, ...]:
    filename = path.name
    seen: dict[str, int] = {}
    entries: list[IdentityAuditEntry] = []
    for line_no, row in _load_rows(path, AUDIT_COLUMNS):
        audit_id = _require(row, "audit_id", filename=filename, line_no=line_no)
        _check_unique(seen, audit_id, column="audit_id", filename=filename, line_no=line_no)
        user_id = _require(row, "user_id", filename=filename, line_no=line_no)
        if user_id not in known_users:
            raise SchemaError(
                f"{filename}: row {line_no} references unknown user_id {user_id!r}"
            )
        field_name = _require(row, "field_name", filename=filename, line_no=line_no).lower()
        if field_name not in IDENTITY_FIELDS:
            raise SchemaError(
                f"{filename}: row {line_no} has unsupported identity field {field_name!r}"
            )
        entries.append(
            IdentityAuditEntry(
                audit_id=audit_id,
                user_id=user_id,
                event_time=parse_timestamp(row["event_time"], field="event_time", source=f"{filename}:{line_no}"),
                field_name=field_name,
                old_value=clean_text(row["old_value"]),
                new_value=clean_text(row["new_value"]),
                source_row=line_no,
            )
        )
    return tuple(entries)


def _load_activity(path: Path) -> tuple[ActivityEvent, ...]:
    filename = path.name
    seen: dict[str, int] = {}
    events: list[ActivityEvent] = []
    for line_no, row in _load_rows(path, ACTIVITY_COLUMNS):
        activity_id = _require(row, "activity_id", filename=filename, line_no=line_no)
        _check_unique(seen, activity_id, column="activity_id", filename=filename, line_no=line_no)
        events.append(
            ActivityEvent(
                activity_id=activity_id,
                event_time=parse_timestamp(row["event_time"], field="event_time", source=f"{filename}:{line_no}"),
                event_type=clean_text(row["event_type"]).upper(),
                source_system=clean_text(row["source_system"]),
                target_system=clean_text(row["target_system"]),
                resource_id=clean_text(row["resource_id"]),
                reported_result=clean_text(row["reported_result"]).upper(),
                details=clean_text(row["details"]),
                source_row=line_no,
            )
        )
    return tuple(events)


def _load_rules(path: Path) -> tuple[DeletionRule, ...]:
    filename = path.name
    seen: dict[str, int] = {}
    rules: list[DeletionRule] = []
    for line_no, row in _load_rows(path, RULE_COLUMNS):
        rule_id = _require(row, "rule_id", filename=filename, line_no=line_no)
        _check_unique(seen, rule_id, column="rule_id", filename=filename, line_no=line_no)
        rules.append(
            DeletionRule(
                rule_id=rule_id,
                data_category=_require(row, "data_category", filename=filename, line_no=line_no).upper(),
                condition=clean_text(row["condition"]),
                required_action=_require(row, "required_action", filename=filename, line_no=line_no).upper(),
                source_row=line_no,
            )
        )
    if not rules:
        raise SchemaError(f"{filename}: no deletion rules found")
    return tuple(rules)


def _load_evidence_manifest(path: Path) -> tuple[EvidenceFile, ...]:
    filename = path.name
    seen: dict[str, int] = {}
    files: list[EvidenceFile] = []
    for line_no, row in _load_rows(path, EVIDENCE_COLUMNS):
        file_id = _require(row, "file_id", filename=filename, line_no=line_no)
        _check_unique(seen, file_id, column="file_id", filename=filename, line_no=line_no)
        files.append(
            EvidenceFile(
                file_id=file_id,
                file_path=_require(row, "file_path", filename=filename, line_no=line_no),
                origin=clean_text(row["origin"]),
                captured_at=parse_timestamp(row["captured_at"], field="captured_at", source=f"{filename}:{line_no}"),
                source_row=line_no,
            )
        )
    return tuple(files)


@dataclasses.dataclass(frozen=True)
class Dataset:
    """An immutable, validated view of the participant dataset."""

    root: Path
    requests: tuple[DeletionRequest, ...]
    identities: tuple[UserIdentity, ...]
    audit_log: tuple[IdentityAuditEntry, ...]
    activity: tuple[ActivityEvent, ...]
    rules: tuple[DeletionRule, ...]
    evidence_manifest: tuple[EvidenceFile, ...]
    sample_requests: tuple[DeletionRequest, ...] = ()
    warnings: tuple[str, ...] = ()

    # ------------------------------------------------------------------ indexing

    def request_by_case_id(self) -> dict[str, DeletionRequest]:
        return {request.case_id: request for request in self.requests}

    def request(self, case_id: str) -> DeletionRequest:
        try:
            return self.request_by_case_id()[case_id]
        except KeyError as exc:
            raise KeyError(f"unknown case_id {case_id!r}") from exc

    @property
    def case_ids(self) -> tuple[str, ...]:
        return tuple(sorted(request.case_id for request in self.requests))

    def rule_for_category(self, data_category: str) -> DeletionRule | None:
        wanted = data_category.strip().upper()
        for rule in self.rules:
            if rule.data_category == wanted:
                return rule
        return None

    @property
    def evidence_root(self) -> Path:
        return self.root / EVIDENCE_DIRNAME

    def describe(self) -> dict[str, int]:
        """Row counts per participant file, used by the smoke test and the README."""

        return {
            "requests": len(self.requests),
            "sample_requests": len(self.sample_requests),
            "identities": len(self.identities),
            "audit_log": len(self.audit_log),
            "activity": len(self.activity),
            "rules": len(self.rules),
            "evidence_manifest": len(self.evidence_manifest),
        }


def load_dataset(
    dataset_root: os.PathLike[str] | str | None = None,
    *,
    include_samples: bool = False,
) -> Dataset:
    """Load and validate the participant dataset.

    ``dataset_root`` defaults to :func:`default_dataset_root`. ``include_samples``
    loads ``sample_deletion_requests.csv`` (public format examples) into
    :attr:`Dataset.sample_requests`. ``sample_output.csv`` is never loaded by design.
    """

    root = Path(dataset_root).expanduser().resolve() if dataset_root is not None else default_dataset_root()
    if not root.is_dir():
        raise DatasetNotFoundError(f"dataset directory not found: {root}")
    evidence_root = root / EVIDENCE_DIRNAME
    if not evidence_root.is_dir():
        raise DatasetNotFoundError(f"dataset evidence directory not found: {evidence_root}")

    warnings: list[str] = []
    requests = _load_requests(root / "deletion_requests.csv", filename="deletion_requests.csv")
    for request in requests:
        if request.reported_status not in REPORTED_STATUSES:
            warnings.append(
                f"{request.case_id}: unrecognised reported_status {request.reported_status!r}"
            )

    identities = _load_identities(root / "user_identities.csv")
    known_users = {identity.user_id for identity in identities}
    audit_log = _load_audit_log(root / "user_audit_log.csv", known_users=known_users)
    activity = _load_activity(root / "system_activity.csv")
    rules = _load_rules(root / "deletion_rules.csv")
    for rule in rules:
        if rule.required_action not in RULE_ACTIONS:
            warnings.append(
                f"{rule.rule_id}: unrecognised required_action {rule.required_action!r}"
            )
    manifest = _load_evidence_manifest(root / "evidence_files.csv")

    sample_requests: tuple[DeletionRequest, ...] = ()
    if include_samples:
        sample_path = root / "sample_deletion_requests.csv"
        if sample_path.is_file():
            sample_requests = _load_requests(sample_path, filename="sample_deletion_requests.csv")
        else:  # pragma: no cover - defensive
            warnings.append("include_samples requested but sample_deletion_requests.csv is missing")

    return Dataset(
        root=root,
        requests=requests,
        identities=identities,
        audit_log=audit_log,
        activity=activity,
        rules=rules,
        evidence_manifest=manifest,
        sample_requests=sample_requests,
        warnings=tuple(warnings),
    )


def request_emails(dataset: Dataset) -> dict[str, str]:
    """Map ``case_id`` -> supplied email, handy for batch resolution."""

    return {request.case_id: request.email for request in dataset.requests}
