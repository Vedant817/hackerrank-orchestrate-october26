"""T01 acceptance tests for identity resolution and historical reconstruction."""

from __future__ import annotations

import datetime as dt

import pytest

from ghostwatch.identity import (
    AmbiguousSubjectError,
    IdentityIndex,
    IdentityResolutionError,
    UnknownSubjectError,
    audit_verbatim_consistency,
    build_index,
)
from ghostwatch.ingest import IdentityAuditEntry, UserIdentity

UTC = dt.timezone.utc


def ts(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def make_identity(user_id: str, email: str, phone: str, email_hash: str, updated: str) -> UserIdentity:
    return UserIdentity(
        user_id=user_id,
        name=user_id,
        email=email,
        phone=phone,
        email_hash=email_hash,
        updated_at=ts(updated),
    )


def make_entry(audit_id: str, user_id: str, when: str, field: str, old: str, new: str) -> IdentityAuditEntry:
    return IdentityAuditEntry(
        audit_id=audit_id,
        user_id=user_id,
        event_time=ts(when),
        field_name=field,
        old_value=old,
        new_value=new,
    )


@pytest.fixture
def index() -> IdentityIndex:
    identities = [
        make_identity("user_a", "new.address@example.com", "+44 20 7946 0001", "hash_a", "2026-02-01T00:00:00Z"),
        make_identity("user_b", "grace@example.com", "+1 202 555 0100", "hash_b", "2026-01-01T00:00:00Z"),
    ]
    audit = [
        make_entry("audit_01", "user_a", "2026-01-15T00:00:00Z", "email", "old.address@example.com", "new.address@example.com"),
        make_entry("audit_02", "user_a", "2026-01-20T00:00:00Z", "phone", "+44 20 7946 0000", "+44 20 7946 0001"),
    ]
    return IdentityIndex(identities, audit)


# --------------------------------------------------------------------------------------
# Historical resolution
# --------------------------------------------------------------------------------------


def test_historical_email_resolution(index: IdentityIndex) -> None:
    """A request email may predate the current snapshot."""

    current = index.resolve_email("new.address@example.com")
    assert current.user_id == "user_a"
    assert current.matched_via == "current_email"

    historical = index.resolve_email("OLD.ADDRESS@example.com")
    assert historical.user_id == "user_a"
    assert historical.matched_via == "historical_email"

    # The historical address is not the current one, but it still resolves.
    assert historical.identity.email == "new.address@example.com"


def test_email_resolution_ignores_case_and_whitespace(index: IdentityIndex) -> None:
    resolved = index.resolve_email("  New.Address@Example.COM  ")
    assert resolved.user_id == "user_a"


def test_unknown_and_ambiguous_emails_fail_loudly(index: IdentityIndex) -> None:
    with pytest.raises(UnknownSubjectError):
        index.resolve_email("nobody@example.com")

    with pytest.raises(UnknownSubjectError):
        index.resolve_email("not-an-email")

    # Two subjects sharing one historical address must not be guessed between.
    shared = IdentityIndex(
        [
            make_identity("user_x", "shared@example.com", "+1", "hx", "2026-01-01T00:00:00Z"),
            make_identity("user_y", "shared@example.com", "+2", "hy", "2026-01-01T00:00:00Z"),
        ]
    )
    with pytest.raises(AmbiguousSubjectError) as excinfo:
        shared.resolve_email("shared@example.com")
    assert "user_x" in str(excinfo.value) and "user_y" in str(excinfo.value)


def test_resolve_by_phone_and_hash(index: IdentityIndex) -> None:
    by_phone = index.resolve_identifier("phone", "+44 20 7946 0001")
    assert by_phone.user_id == "user_a"

    by_hash = index.resolve_identifier("email_hash", "hash_b")
    assert by_hash.user_id == "user_b"

    with pytest.raises(IdentityResolutionError):
        index.resolve_identifier("nickname", "ada")


# --------------------------------------------------------------------------------------
# Temporal cutoffs
# --------------------------------------------------------------------------------------


def test_identity_history_cutoff(index: IdentityIndex) -> None:
    """Only identifiers in force at an instant are reported as current."""

    before_change = ts("2026-01-10T00:00:00Z")
    in_force = index.identifiers_at("user_a", before_change)
    values = {(item.kind, item.value) for item in in_force}
    assert ("email", "old.address@example.com") in values
    assert ("email", "new.address@example.com") not in values

    after_change = ts("2026-02-01T00:00:00Z")
    later = {(item.kind, item.value) for item in index.identifiers_at("user_a", after_change)}
    assert ("email", "new.address@example.com") in later
    assert ("email", "old.address@example.com") not in later


def test_future_identifiers_do_not_leak_backwards(index: IdentityIndex) -> None:
    """A snapshot change after the cutoff must not appear in an earlier view."""

    early = ts("2026-01-01T00:00:00Z")
    used = index.identifiers_used_by("user_a", early)
    assert all(item.value != "new.address@example.com" for item in used)
    assert all(item.valid_from is None or item.valid_from <= early for item in used)

    sets = index.identifier_sets("user_a", early)
    assert "new.address@example.com" not in sets["email"]


def test_identifiers_used_by_is_wider_than_identifiers_at(index: IdentityIndex) -> None:
    """Evidence may legitimately contain an address the person has since changed."""

    at = ts("2026-02-01T00:00:00Z")
    in_force = {item.value for item in index.identifiers_at("user_a", at)}
    ever_used = {item.value for item in index.identifiers_used_by("user_a", at)}

    assert "new.address@example.com" in in_force
    assert "old.address@example.com" not in in_force
    # The historical address is recalled for retrieval but is not "current".
    assert "old.address@example.com" in ever_used
    assert in_force <= ever_used


def test_subject_identifier_helpers(index: IdentityIndex) -> None:
    subject = index.resolve_email("new.address@example.com")
    at = ts("2026-02-01T00:00:00Z")
    assert "new.address@example.com" in subject.emails(at)
    assert "old.address@example.com" in subject.emails(at)
    # Phone digits are normalised, so the historical and current forms both appear.
    assert subject.phones(at) == ("+44 20 7946 0000", "+44 20 7946 0001")
    assert subject.email_hashes(at) == ("hash_a",)


def test_owners_of_returns_every_owner(index: IdentityIndex) -> None:
    assert index.owners_of("email", "old.address@example.com") == frozenset({"user_a"})
    assert index.owners_of("email", "nobody@example.com") == frozenset()


# --------------------------------------------------------------------------------------
# Consistency helpers and errors
# --------------------------------------------------------------------------------------


def test_audit_history_chains_into_the_snapshot(index: IdentityIndex) -> None:
    assert audit_verbatim_consistency(index) == ()


def test_audit_history_mismatch_is_reported() -> None:
    identities = [make_identity("user_a", "current@example.com", "+1", "h", "2026-01-01T00:00:00Z")]
    audit = [make_entry("audit_01", "user_a", "2026-01-01T00:00:00Z", "email", "x@example.com", "different@example.com")]
    problems = audit_verbatim_consistency(IdentityIndex(identities, audit))
    assert problems and "user_a:email" in problems[0]


def test_unknown_audit_user_and_duplicate_snapshot_user_are_rejected() -> None:
    with pytest.raises(IdentityResolutionError):
        IdentityIndex(
            [make_identity("user_a", "a@example.com", "+1", "h", "2026-01-01T00:00:00Z")],
            [make_entry("audit_01", "user_z", "2026-01-01T00:00:00Z", "email", "x", "y")],
        )

    with pytest.raises(IdentityResolutionError):
        IdentityIndex(
            [
                make_identity("user_a", "a@example.com", "+1", "h", "2026-01-01T00:00:00Z"),
                make_identity("user_a", "b@example.com", "+2", "h2", "2026-01-01T00:00:00Z"),
            ]
        )


def test_build_index_matches_constructor(index: IdentityIndex) -> None:
    rebuilt = build_index(
        [index.identity(user_id) for user_id in index.user_ids],
        index.audit_entries("user_a"),
    )
    assert rebuilt.user_ids == ("user_a", "user_b")
    assert rebuilt.resolve_email("old.address@example.com").user_id == "user_a"


def test_real_dataset_identity_history_is_self_consistent(real_dataset) -> None:
    """The supplied history must chain into the current snapshot for every subject."""

    index = IdentityIndex(real_dataset.identities, real_dataset.audit_log)
    assert len(index.user_ids) == 850
    assert audit_verbatim_consistency(index) == ()

    resolved = 0
    for request in real_dataset.requests:
        subject = index.resolve_email(request.email)
        resolved += 1
        assert subject.user_id
    assert resolved == len(real_dataset.requests)
