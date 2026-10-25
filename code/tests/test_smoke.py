"""Real participant-ingestion smoke test.

Unlike the unit tests, this exercises the actual supplied ``dataset/`` end to end: every
request resolves to a subject, every evidence file parses, and retrieval returns grounded,
cutoff-respecting records. It is the check that proves the T01 layer works on the real
inputs rather than only on fixtures.

The test never reads ``sample_output.csv``: that file holds evaluation labels.
"""

from __future__ import annotations

import pytest

from ghostwatch.evidence import EvidenceLibrary
from ghostwatch.identity import IdentityIndex

EXPECTED_REQUESTS = 518


@pytest.fixture(scope="module")
def indexed(real_dataset):
    index = IdentityIndex(real_dataset.identities, real_dataset.audit_log)
    library = EvidenceLibrary(real_dataset)
    return real_dataset, index, library


def test_real_requests_load_with_the_contracted_row_count(real_dataset) -> None:
    assert len(real_dataset.requests) == EXPECTED_REQUESTS
    assert len(real_dataset.case_ids) == EXPECTED_REQUESTS
    # Case ids are unique and the dataset places no blanks in required fields.
    assert len(set(real_dataset.case_ids)) == EXPECTED_REQUESTS
    assert all(request.email and request.request_text for request in real_dataset.requests)
    assert all(request.reported_status for request in real_dataset.requests)


def test_every_real_request_resolves_to_a_subject(indexed) -> None:
    dataset, index, _library = indexed
    resolved = 0
    for request in dataset.requests:
        subject = index.resolve_email(request.email)
        assert subject.user_id in index
        resolved += 1
    assert resolved == EXPECTED_REQUESTS


def test_every_real_evidence_file_parses_with_provenance(indexed) -> None:
    dataset, _index, library = indexed
    documents = library.documents(strict=True)
    assert len(documents) == len(dataset.evidence_manifest)
    assert library.failures == ()

    kinds = {document.kind for document in documents}
    # The dataset genuinely mixes formats; all must be handled.
    assert {"sql", "json", "log", "text", "pdf", "image"} <= kinds

    manifest_by_id = {entry.file_id: entry for entry in dataset.evidence_manifest}
    for document in documents:
        entry = manifest_by_id[document.evidence.file_id]
        assert document.sha256 and len(document.sha256) == 64
        assert document.size_bytes > 0
        for record in document.records:
            assert record.evidence_id == entry.file_id
            assert record.dataset_path == entry.file_path
            assert record.origin == entry.origin
            assert record.captured_at == entry.captured_at


def test_real_identifiers_are_well_formed(indexed) -> None:
    _dataset, _index, library = indexed
    seen = 0
    for document in library.documents(strict=True):
        for record in document.records:
            for kind, value in record.identifiers:
                assert kind in {"email", "email_hash", "phone", "user_id", "resource_id"}
                assert value == value.strip() and value
                seen += 1
    assert seen > 0


def test_retrieval_is_grounded_and_cutoff_respecting(indexed) -> None:
    dataset, index, library = indexed
    sampled = dataset.requests[:: max(1, len(dataset.requests) // 25)]

    matched_total = 0
    for request in sampled:
        subject = index.resolve_email(request.email)
        result = library.resolve(subject, request.audit_at, index=index)
        assert result.subject.user_id == subject.user_id
        for match in result.matches:
            assert match.record.captured_at <= request.audit_at
            if match.record.observed_at is not None:
                assert match.record.observed_at <= request.audit_at
            # A direct match must genuinely share an identifier.
            if match.match_kind != "resource_link":
                assert match.matched_values
        matched_total += len(result.matches)
    assert matched_total > 0


def test_no_evidence_from_after_the_cutoff_is_ever_returned(indexed) -> None:
    dataset, index, library = indexed
    for request in dataset.requests[:: max(1, len(dataset.requests) // 10)]:
        subject = index.resolve_email(request.email)
        result = library.resolve(subject, request.audit_at, index=index)
        late = [m for m in result.matches if m.record.captured_at > request.audit_at]
        assert late == []
        late_observed = [
            m
            for m in result.matches
            if m.record.observed_at is not None and m.record.observed_at > request.audit_at
        ]
        assert late_observed == []


def test_activity_selection_respects_the_cutoff(indexed) -> None:
    dataset, index, library = indexed
    for request in dataset.requests[:20]:
        subject = index.resolve_email(request.email)
        result = library.resolve(subject, request.audit_at, index=index)
        for event in result.activity:
            assert event.event_time <= request.audit_at


def test_sql_snapshots_keep_replica_topology(indexed) -> None:
    dataset, _index, library = indexed
    topologies = set()
    for entry in dataset.evidence_manifest:
        if entry.file_path.endswith(".sql"):
            document = library.document(entry.file_id, strict=True)
            topologies.add(document.meta("topology"))
    # The dataset deliberately supplies several topologies; they must stay distinguishable.
    assert {"read_replica", "reporting_replica", "failover_replica"} <= topologies
    assert "regional_replicas" in topologies


def test_dataset_describe_matches_the_supplied_files(indexed) -> None:
    dataset, _index, _library = indexed
    described = dataset.describe()
    assert described["requests"] == EXPECTED_REQUESTS
    assert described["identities"] == 850
    assert described["rules"] == 15
    assert described["evidence_manifest"] == 94


def test_smoke_is_deterministic(indexed) -> None:
    """Two passes over the same subject produce identical matches."""

    dataset, index, library = indexed
    request = dataset.requests[0]
    subject = index.resolve_email(request.email)
    first = library.resolve(subject, request.audit_at, index=index)
    second = library.resolve(subject, request.audit_at, index=index)
    assert [m.record.locator for m in first.matches] == [m.record.locator for m in second.matches]
    assert first.resource_ids == second.resource_ids
    assert first.activity_ids() == second.activity_ids()
