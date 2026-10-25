"""T02 acceptance tests for multilingual deletion authorization.

The tests deliberately avoid any case-id table: every assertion is about the *text* of the
request, so the classifier cannot be passing by having memorised a label. Both positive and
negative phrasing is covered, including the explicit refusals the contract calls out
(access, export, correction, marketing opt-out, login help) and non-English deletion asks.
"""

from __future__ import annotations

import pytest

from ghostwatch.authorization import (
    DECISION_AMBIGUOUS,
    DECISION_AUTHORIZED,
    DECISION_NOT_APPLICABLE,
    ModelUsage,
    AuthorizationDecision,
    ModelRouteError,
    authorize,
    callable_classifier,
    classify_request_text,
    resolve_ambiguous_as_not_applicable,
    summarise_decisions,
)


def test_non_deletion_multilingual_and_negation() -> None:
    """Deletion is authorized from the text alone, in several languages and phrasings."""

    authorized = [
        "Please delete my account and all personal data attached to it.",
        "I would like the account associated with this address to be erased.",
        "I no longer use this account and would like it permanently deleted.",
        "Solicito la eliminación permanente de la cuenta asociada a este correo.",
        "Solicito a exclusão permanente da conta associada a este e-mail.",
        "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
        "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
        "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
        "Please remove my profile and the personal details attached to it.",
        "Please close this account and delete everything linked to it.",
    ]
    for text in authorized:
        decision = classify_request_text(text)
        assert decision.decision == DECISION_AUTHORIZED, (text, decision)
        assert decision.matched_terms
        assert decision.reason

    non_deletion = [
        "Can you tell me what personal information you hold about me? "
        "This is an information request, not a request to erase it.",
        "I'd like to download my account information in a portable format. "
        "Please keep the account as it is.",
        "My surname is misspelled on the account. Can you correct it without removing "
        "any of my records?",
        "Please remove me from marketing lists only. I still want receipts and service "
        "messages for this account.",
        "Please change the email address used for this account. I want to continue using "
        "the service.",
        "I can't access my profile and need help resetting the login. Do not close the "
        "account.",
    ]
    for text in non_deletion:
        decision = classify_request_text(text)
        assert decision.decision == DECISION_NOT_APPLICABLE, (text, decision)


def test_non_deletion_is_never_inferred_from_reported_status() -> None:
    """The classifier is a pure function of the text; it has no access to any status."""

    import inspect

    parameters = inspect.signature(classify_request_text).parameters
    assert list(parameters) == ["text"]
    decision = classify_request_text("Please stop the promotional emails.")
    assert decision.decision == DECISION_NOT_APPLICABLE


def test_negated_deletion_words_do_not_authorize() -> None:
    """A deletion word inside a negation must not be read as an authorization."""

    text = (
        "I am not asking for deletion. I still use the account and want to keep it."
    )
    decision = classify_request_text(text)
    assert decision.decision == DECISION_NOT_APPLICABLE
    assert "delete" in decision.negated_terms or decision.matched_terms == ("do-not-delete",)


def test_empty_text_is_ambiguous_not_authorized() -> None:
    decision = classify_request_text("   ")
    assert decision.decision == DECISION_AMBIGUOUS
    assert decision.confidence == 0.0

    # The runner folds unresolved ambiguity into NOT_APPLICABLE rather than deleting data
    # nobody asked to delete.
    folded = resolve_ambiguous_as_not_applicable(decision)
    assert folded.decision == DECISION_NOT_APPLICABLE
    assert "ambiguity" in folded.reason


def test_no_case_label_table_exists() -> None:
    """Guard against a hidden request/case label table: the module never names a case id."""

    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "ghostwatch" / "authorization.py"
    text = source.read_text(encoding="utf-8")
    assert "case_" not in text


def test_optional_model_route_is_used_and_metered() -> None:
    """A configured classifier is consulted only for ambiguity, and its usage is real."""

    calls: list[str] = []

    def fake(text: str):
        calls.append(text)
        return (
            AuthorizationDecision(
                decision=DECISION_AUTHORIZED,
                reason="model decided the request is a deletion",
                matched_terms=("model",),
                negated_terms=(),
            ),
            ModelUsage(
                provider="example",
                model="example-1",
                calls=1,
                input_tokens=11,
                output_tokens=7,
            ),
        )

    classifier = callable_classifier(fake)

    # An unambiguous request never reaches the model.
    clear = authorize("Please delete my account.")
    assert clear.method == "lexicon"
    assert calls == []

    # An ambiguous request does, and the usage is carried back.
    resolved = authorize("rem", classifier=classifier)
    assert calls == ["rem"]
    assert resolved.method == "model"
    assert resolved.model_usage is not None
    assert resolved.model_usage.input_tokens == 11
    assert resolved.model_usage.output_tokens == 7
    assert resolved.model_usage.total_tokens == 18


def test_model_route_failure_is_surfaced_not_swallowed() -> None:
    def exploding(text: str):
        raise RuntimeError("provider unavailable")

    with pytest.raises(ModelRouteError) as excinfo:
        authorize("rem", classifier=callable_classifier(exploding))
    assert "provider unavailable" in str(excinfo.value)


def test_summarise_decisions_counts_outcomes() -> None:
    decisions = [
        classify_request_text("Please delete my account."),
        classify_request_text("Please send me a copy of my data."),
        classify_request_text(""),
    ]
    counts = summarise_decisions(decisions)
    assert counts[DECISION_AUTHORIZED] == 1
    assert counts[DECISION_NOT_APPLICABLE] == 1
    assert counts[DECISION_AMBIGUOUS] == 1
