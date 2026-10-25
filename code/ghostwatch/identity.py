"""Identity resolution and historical identifier reconstruction.

The request supplies one email address. That address may be current or may have been
replaced before the request was filed, so resolution has to use both the current
snapshot (``user_identities.csv``) and the change history (``user_audit_log.csv``).

Two different questions matter downstream and they are deliberately kept apart:

``identifiers_at(at)``
    Which identifiers were *in force* at ``at``. Used when a check must reflect only
    the state that existed at that instant.
``identifiers_used_by(at)``
    Which identifiers the subject had *ever used* at or before ``at``. Evidence such
    as an invoice or support ticket legitimately contains an address the person has
    since changed, so retrieval must match on this wider set.

Identifiers whose validity only starts *after* ``at`` are excluded from both views.
That is the guard against an audit that leaks future identifiers into its own
reasoning.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Sequence

from .ingest import (
    IDENTITY_FIELDS,
    IdentityAuditEntry,
    UserIdentity,
    clean_text,
    normalise_identifier,
)

UTC = _dt.timezone.utc

CURRENT_SNAPSHOT_SOURCE = "identity_snapshot"


class IdentityResolutionError(RuntimeError):
    """Base class for identity problems."""


class UnknownSubjectError(IdentityResolutionError):
    """The supplied value does not belong to any known subject."""


class AmbiguousSubjectError(IdentityResolutionError):
    """The supplied value maps to more than one subject.

    The audit refuses to guess: attributing one person's records to another is worse
    than failing loudly.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class Identifier:
    """One identifier value with the interval over which it was in force."""

    kind: str
    value: str
    normalised: str
    valid_from: _dt.datetime | None
    valid_to: _dt.datetime | None
    source: str

    def covers(self, at: _dt.datetime) -> bool:
        """True when the identifier was in force at ``at``."""

        if self.valid_from is not None and self.valid_from > at:
            return False
        if self.valid_to is not None and self.valid_to <= at:
            return False
        return True

    def existed_by(self, at: _dt.datetime) -> bool:
        """True when the identifier had come into force at or before ``at``."""

        return self.valid_from is None or self.valid_from <= at


@dataclasses.dataclass(frozen=True, slots=True)
class Subject:
    """A resolved audit subject."""

    user_id: str
    identity: UserIdentity
    matched_kind: str
    matched_value: str
    matched_via: str
    _index: "IdentityIndex" = dataclasses.field(compare=False, repr=False)

    # ------------------------------------------------------------------ views

    def identifiers_at(self, at: _dt.datetime) -> tuple[Identifier, ...]:
        return self._index.identifiers_at(self.user_id, at)

    def identifiers_used_by(self, at: _dt.datetime) -> tuple[Identifier, ...]:
        return self._index.identifiers_used_by(self.user_id, at)

    def identifier_sets(self, at: _dt.datetime) -> dict[str, frozenset[str]]:
        """Normalised identifier sets keyed by kind, for evidence attribution."""

        return self._index.identifier_sets(self.user_id, at)

    def emails(self, at: _dt.datetime) -> tuple[str, ...]:
        return tuple(sorted({i.value for i in self.identifiers_used_by(at) if i.kind == "email"}))

    def phones(self, at: _dt.datetime) -> tuple[str, ...]:
        return tuple(sorted({i.value for i in self.identifiers_used_by(at) if i.kind == "phone"}))

    def email_hashes(self, at: _dt.datetime) -> tuple[str, ...]:
        return tuple(
            sorted({i.value for i in self.identifiers_used_by(at) if i.kind == "email_hash"})
        )


class IdentityIndex:
    """Index over the identity snapshot plus its change history."""

    def __init__(
        self,
        identities: Sequence[UserIdentity],
        audit_log: Sequence[IdentityAuditEntry] = (),
    ) -> None:
        self._identities: dict[str, UserIdentity] = {}
        for identity in identities:
            if identity.user_id in self._identities:
                raise IdentityResolutionError(
                    f"duplicate user_id in identity snapshot: {identity.user_id!r}"
                )
            self._identities[identity.user_id] = identity

        grouped: dict[str, list[IdentityAuditEntry]] = {user_id: [] for user_id in self._identities}
        for entry in audit_log:
            if entry.user_id not in self._identities:
                raise IdentityResolutionError(
                    f"audit entry {entry.audit_id!r} references unknown user_id {entry.user_id!r}"
                )
            grouped[entry.user_id].append(entry)
        for entries in grouped.values():
            entries.sort(key=lambda item: (item.event_time, item.audit_id))

        self._audit: dict[str, tuple[IdentityAuditEntry, ...]] = {
            user_id: tuple(entries) for user_id, entries in grouped.items()
        }
        self._intervals: dict[str, tuple[Identifier, ...]] = {
            user_id: self._build_intervals(self._identities[user_id], self._audit[user_id])
            for user_id in self._identities
        }
        self._value_index = self._build_value_index()

    # ------------------------------------------------------------------ construction

    @staticmethod
    def _build_intervals(
        identity: UserIdentity, entries: Sequence[IdentityAuditEntry]
    ) -> tuple[Identifier, ...]:
        intervals: list[Identifier] = []
        by_field: dict[str, list[IdentityAuditEntry]] = {field: [] for field in IDENTITY_FIELDS}
        for entry in entries:
            by_field[entry.field_name].append(entry)

        for field, field_entries in by_field.items():
            field_entries.sort(key=lambda item: (item.event_time, item.audit_id))
            for position, entry in enumerate(field_entries):
                previous_time = field_entries[position - 1].event_time if position else None
                following_time = (
                    field_entries[position + 1].event_time
                    if position + 1 < len(field_entries)
                    else None
                )
                intervals.extend(
                    _make_identifiers(field, entry.old_value, previous_time, entry.event_time, entry.audit_id)
                )
                intervals.extend(
                    _make_identifiers(field, entry.new_value, entry.event_time, following_time, entry.audit_id)
                )

            current_value = getattr(identity, field)
            current_from = field_entries[-1].event_time if field_entries else None
            if field_entries and normalise_identifier(
                field, field_entries[-1].new_value
            ) == normalise_identifier(field, current_value):
                # The last audited value is still the live value; the audit entry already
                # carries the provenance, so do not add a duplicate interval.
                continue
            intervals.extend(
                _make_identifiers(
                    field, current_value, current_from, None, CURRENT_SNAPSHOT_SOURCE
                )
            )

        # De-duplicate identical (kind, value, start, end, source) tuples while keeping
        # a deterministic order.
        unique: dict[tuple[str, str, object, object, str], Identifier] = {}
        for identifier in intervals:
            key = (
                identifier.kind,
                identifier.normalised,
                identifier.valid_from,
                identifier.valid_to,
                identifier.source,
            )
            unique.setdefault(key, identifier)
        return tuple(
            sorted(
                unique.values(),
                key=lambda item: (item.kind, item.normalised, _sort_time(item.valid_from), item.source),
            )
        )

    def _build_value_index(self) -> dict[tuple[str, str], frozenset[str]]:
        owners: dict[tuple[str, str], set[str]] = {}
        for user_id, intervals in self._intervals.items():
            for identifier in intervals:
                owners.setdefault((identifier.kind, identifier.normalised), set()).add(user_id)
        return {key: frozenset(value) for key, value in owners.items()}

    # ------------------------------------------------------------------ lookups

    def __contains__(self, user_id: object) -> bool:
        return user_id in self._identities

    @property
    def user_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._identities))

    def identity(self, user_id: str) -> UserIdentity:
        try:
            return self._identities[user_id]
        except KeyError as exc:
            raise UnknownSubjectError(f"unknown user_id {user_id!r}") from exc

    def audit_entries(self, user_id: str) -> tuple[IdentityAuditEntry, ...]:
        return self._audit.get(user_id, ())

    def owners_of(self, kind: str, value: str) -> frozenset[str]:
        return self._value_index.get((kind, normalise_identifier(kind, value)), frozenset())

    def identifiers_at(self, user_id: str, at: _dt.datetime) -> tuple[Identifier, ...]:
        return tuple(
            identifier for identifier in self._intervals_for(user_id) if identifier.covers(at)
        )

    def identifiers_used_by(self, user_id: str, at: _dt.datetime) -> tuple[Identifier, ...]:
        return tuple(
            identifier
            for identifier in self._intervals_for(user_id)
            if identifier.existed_by(at)
        )

    def identifier_sets(self, user_id: str, at: _dt.datetime) -> dict[str, frozenset[str]]:
        sets: dict[str, set[str]] = {field: set() for field in IDENTITY_FIELDS}
        for identifier in self.identifiers_used_by(user_id, at):
            sets.setdefault(identifier.kind, set()).add(identifier.normalised)
        return {kind: frozenset(values) for kind, values in sets.items()}

    def _intervals_for(self, user_id: str) -> tuple[Identifier, ...]:
        try:
            return self._intervals[user_id]
        except KeyError as exc:
            raise UnknownSubjectError(f"unknown user_id {user_id!r}") from exc

    # ------------------------------------------------------------------ resolution

    def resolve_email(self, email: str, *, at: _dt.datetime | None = None) -> Subject:
        """Resolve an email address to exactly one subject.

        ``at`` is accepted for call-site clarity and future policy checks; resolution
        itself uses the full history because the person's address at request time is
        not always the address on file.
        """

        raw = clean_text(email)
        if not raw:
            raise UnknownSubjectError("empty email address supplied with the request")
        normalised = normalise_identifier("email", raw)
        if "@" not in normalised:
            raise UnknownSubjectError(f"supplied value is not an email address: {raw!r}")

        owners = self.owners_of("email", normalised)
        if not owners:
            raise UnknownSubjectError(
                f"no subject matches the supplied email address {raw!r}"
            )
        if len(owners) > 1:
            raise AmbiguousSubjectError(
                "the supplied email address "
                f"{raw!r} matches several subjects: {sorted(owners)}; "
                "refusing to guess which person the request concerns"
            )
        user_id = next(iter(owners))
        identity = self._identities[user_id]
        current = normalise_identifier("email", identity.email)
        via = "current_email" if current == normalised else "historical_email"
        return Subject(
            user_id=user_id,
            identity=identity,
            matched_kind="email",
            matched_value=raw,
            matched_via=via,
            _index=self,
        )

    def resolve_identifier(self, kind: str, value: str) -> Subject:
        """Resolve any identity kind (email, phone, email_hash) to one subject."""

        if kind not in IDENTITY_FIELDS:
            raise IdentityResolutionError(f"cannot resolve identifiers of kind {kind!r}")
        owners = self.owners_of(kind, value)
        if not owners:
            raise UnknownSubjectError(f"no subject matches {kind} {value!r}")
        if len(owners) > 1:
            raise AmbiguousSubjectError(
                f"{kind} {value!r} matches several subjects: {sorted(owners)}"
            )
        user_id = next(iter(owners))
        identity = self._identities[user_id]
        normalised = normalise_identifier(kind, value)
        via = (
            "current"
            if normalise_identifier(kind, getattr(identity, kind)) == normalised
            else "historical"
        )
        return Subject(
            user_id=user_id,
            identity=identity,
            matched_kind=kind,
            matched_value=value,
            matched_via=via,
            _index=self,
        )


def _make_identifiers(
    kind: str,
    value: str,
    valid_from: _dt.datetime | None,
    valid_to: _dt.datetime | None,
    source: str,
) -> list[Identifier]:
    text = clean_text(value)
    if not text:
        return []
    return [
        Identifier(
            kind=kind,
            value=text,
            normalised=normalise_identifier(kind, text),
            valid_from=valid_from,
            valid_to=valid_to,
            source=source,
        )
    ]


def _sort_time(value: _dt.datetime | None) -> str:
    return "" if value is None else value.isoformat()


def build_index(
    identities: Sequence[UserIdentity],
    audit_log: Sequence[IdentityAuditEntry] = (),
) -> IdentityIndex:
    """Convenience constructor used by the CLI and tests."""

    return IdentityIndex(identities, audit_log)


def audit_verbatim_consistency(index: IdentityIndex) -> tuple[str, ...]:
    """Report subjects whose change history does not chain into the current snapshot.

    The participant data is expected to be consistent; this helper lets a test prove
    it instead of assuming it, and gives the runner a diagnostic if a future dataset
    revision breaks the assumption.
    """

    problems: list[str] = []
    for user_id in index.user_ids:
        identity = index.identity(user_id)
        entries = index.audit_entries(user_id)
        last_by_field: dict[str, IdentityAuditEntry] = {}
        for entry in entries:
            last_by_field[entry.field_name] = entry
        for field, entry in last_by_field.items():
            expected = normalise_identifier(field, entry.new_value)
            actual = normalise_identifier(field, getattr(identity, field))
            if expected and actual and expected != actual:
                problems.append(
                    f"{user_id}:{field}: snapshot {getattr(identity, field)!r} does not match "
                    f"last audited value {entry.new_value!r} ({entry.audit_id})"
                )
    return tuple(problems)
