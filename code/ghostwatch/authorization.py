"""Deletion authorization: does ``request_text`` actually ask for deletion?

The contract is blunt about this: a request for access, correction, export, marketing
opt-out or another non-deletion action is ``NOT_APPLICABLE`` even when every other field
resembles a deletion case. So the first decision in the audit is a language decision, and
it must be made without trusting ``reported_status``.

Design:

* **Deterministic first.** A multilingual lexicon plus negation handling decides the
  common, unambiguous cases with an auditable reason. No request text is ever keyed to a
  case id: the decision is a pure function of the text.
* **Explicit ambiguity.** When the text mixes a deletion ask with a competing
  non-deletion ask, or clearly denies deletion, the result is recorded with the matched
  spans so a later reviewer can see *why*.
* **Optional model, never required.** A model may only be used through an explicitly
  configured route. When no route is configured the deterministic result is final; when a
  route is configured but fails, the failure is surfaced, never silently converted into an
  authorization decision. Usage is metered so the caller can report real token counts.

``sample_output.csv`` is never consulted; the authorization decision is derived from the
request text alone.
"""

from __future__ import annotations

import dataclasses
import re
import unicodedata
from typing import Callable, Iterable, Protocol, Sequence

# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------


class AuthorizationError(RuntimeError):
    """Base class for authorization problems."""


class UnsupportedRequestLanguageError(AuthorizationError):
    """The request cannot be classified and no configured model route is available."""


class ModelRouteError(AuthorizationError):
    """A configured model route failed; the failure is surfaced, never swallowed."""


# --------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------

#: ``AUTHORIZED`` — the text asks for deletion; ``NOT_APPLICABLE`` — it does not;
#: ``AMBIGUOUS`` — the text supports both readings and must not be resolved by guessing.
DECISION_AUTHORIZED = "AUTHORIZED"
DECISION_NOT_APPLICABLE = "NOT_APPLICABLE"
DECISION_AMBIGUOUS = "AMBIGUOUS"


@dataclasses.dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """The authorization outcome plus the grounded reason for it."""

    decision: str
    reason: str
    matched_terms: tuple[str, ...]
    negated_terms: tuple[str, ...]
    method: str = "lexicon"
    confidence: float = 1.0
    model_usage: "ModelUsage | None" = None

    @property
    def authorized(self) -> bool:
        return self.decision == DECISION_AUTHORIZED

    @property
    def is_not_applicable(self) -> bool:
        return self.decision == DECISION_NOT_APPLICABLE


@dataclasses.dataclass(frozen=True, slots=True)
class ModelUsage:
    """Real, measured usage for one model call (never estimated)."""

    provider: str
    model: str
    calls: int
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


# --------------------------------------------------------------------------------------
# Lexicon
# --------------------------------------------------------------------------------------

#: ``(canonical_term, [pattern, ...])``. Patterns are matched case-insensitively on a
#: Unicode-folded copy of the text. Deletion phrasing across the languages present in the
#: dataset (English, Spanish, Portuguese, French, Japanese, Korean) plus a few common
#: variants. Terms are intentionally *actions*, not case labels.
_DELETION_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("delete", (r"\bdelet(?:e|ed|ing|ion)\b", r"\bdelete\b")),
    ("erase", (r"\beras(?:e|ed|ing|ure)\b",)),
    ("remove-account-data", (
        r"\bremov(?:e|ed|ing|al)\b[^.]{0,40}\b(?:account|profile|personal|data|information|details|copy|copies|records?|name)\b",
        r"\bremov(?:e|ed|ing)\b[^.]{0,25}\bmy\b",
    )),
    ("close-account", (r"\bclos(?:e|ed|ing)\b[^.]{0,40}\baccount\b",)),
    ("permanently-delete", (r"\bpermanent(?:ly)?\b[^.]{0,30}\bdelet",)),
    # A request to *finish/verify* a deletion that was claimed complete is still an
    # authorization to complete it: the person is asking for the deletion to be true.
    ("complete-deletion", (
        r"\b(?:confirm|verify|check|audit|inspect|investigate|complete|finish|tell me whether|see whether|find out whether)\b[^.]{0,160}\b(?:delet|remov|erased|gone|no longer|failed|still (?:existed|exists|recognized|recognised|works|appears|points|find|shown))\b",
        r"\b(?:still (?:existed|exists|recognized|recognised|works|appears|point|find|shown))\b",
        r"\bwhether the account\b[^.]{0,80}\b(?:removed|deleted|erased|gone)\b",
    )),
    ("eliminar", (r"\belimin\w*",)),          # es
    ("suprimir", (r"\bsuprim\w*",)),          # es/pt
    ("exclusao", (r"\bexclus\w*",)),          # pt: exclusão
    ("suppression", (r"\bsupprim\w*", r"\bsuppress\w*")),  # fr
    ("effacement", (r"\beffac\w*",)),         # fr
    ("sakujo", (r"削除",)),                   # ja
    ("sakujo-kana", (r"さくじょ",)),
    ("sakje", (r"삭제",)),                    # ko
    ("malso", (r"말소",)),
    ("right-to-erasure", (r"\berasure\b", r"\bright to be forgotten\b")),
)

#: Non-deletion asks. A request that matches one of these and no deletion term is
#: ``NOT_APPLICABLE``; a request that matches both is ``AMBIGUOUS``.
_NON_DELETION_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("access", (r"\bwhat personal information\b", r"\bwhat (?:data|information) (?:you|do you) (?:hold|have)\b")),
    ("export", (r"\bdownload\b[^.]{0,30}\b(?:information|data|account)\b", r"\bportable format\b", r"\bcopy of\b[^.]{0,30}\b(?:invoices|information|data)\b")),
    ("correction", (r"\b(?:misspell\w*|incorrect|wrong|out of date|outdated|update)\b[^.]{0,40}\b(?:surname|name|number|phone|email|address|profile)\b", r"\bcorrect\b[^.]{0,30}\b(?:my|the)\b[^.]{0,20}\b(?:name|surname|details|record)\b", r"\breplace it\b")),
    ("marketing-opt-out", (r"\b(?:stop|remove me from|opt[- ]?out of)\b[^.]{0,40}\b(?:promotional|marketing|newsletter)\b", r"\bmarketing lists?\b[^.]{0,20}\bonly\b")),
    ("change-email", (r"\bchange the email\b", r"\bchange my email\b", r"\bswitch (?:the|my) email\b")),
    ("login-help", (r"\breset(?:ting)? (?:the|my) (?:login|password)\b", r"\bcan'?t access my profile\b", r"\bcannot access my profile\b")),
    ("continue-service", (r"\bcontinue using the service\b", r"\bleave the account active\b", r"\bkeep the account as it is\b", r"\bstill (?:need|use) (?:the account|it)\b")),
)

#: Phrases that explicitly *deny* deletion. These invert an otherwise-deletion request.
_NEGATION_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("not-a-deletion-request", (r"\bnot a request to erase\b", r"\bthis is an information request\b")),
    ("do-not-delete", (r"\b(?:please )?do not (?:delete|close|remove|erase)\b", r"\bdon'?t delete\b", r"\bnot asking for deletion\b", r"\bwithout removing any of my records\b")),
    ("keep-records", (r"\bleave my profile and purchase history in place\b", r"\bleave .{0,20}in place\b")),
)

_CLAUSE_SPLIT_RE = re.compile(r"(?<=[.!?;。！？])\s+|\n+")

#: A window around a negation inside which a deletion term is considered negated.
_NEGATION_WINDOW = 64


#: Blocks whose characters carry meaning and must never be decomposed: Hangul syllables
#: and the CJK/kana ranges. ``NFKD`` would split a Hangul syllable into jamo and break
#: every Korean substring match, so those code points are composed with ``NFC`` instead.
_PRESERVE_BLOCKS: tuple[tuple[int, int], ...] = (
    (0x1100, 0x11FF),   # Hangul Jamo
    (0x3040, 0x30FF),   # Hiragana + Katakana
    (0x3400, 0x4DBF),   # CJK Extension A
    (0x4E00, 0x9FFF),   # CJK Unified Ideographs
    (0xAC00, 0xD7AF),   # Hangul syllables
    (0xF900, 0xFAFF),   # CJK compatibility ideographs
    (0xFF00, 0xFFEF),   # Halfwidth/fullwidth forms
)


def _is_preserved(char: str) -> bool:
    point = ord(char)
    return any(start <= point <= end for start, end in _PRESERVE_BLOCKS)


def _fold(text: str) -> str:
    """Case- and diacritic-fold while preserving CJK and Hangul characters.

    Latin text is normalized with ``NFKD`` so ``exclusão`` folds to ``exclusao``; CJK and
    Hangul runs are composed with ``NFC`` first so ``삭제`` stays a single token instead of
    being split into jamo that no substring pattern can match.
    """

    latin_normalised = unicodedata.normalize("NFKD", text)
    kept = [char for char in latin_normalised if not unicodedata.combining(char)]
    folded = "".join(kept)
    # Re-compose the preserved blocks; NFKD may have decomposed Hangul before the
    # combining-mark filter ran, so this restores the syllable forms.
    return unicodedata.normalize("NFC", folded).casefold()


def _find_terms(text: str, terms: Iterable[tuple[str, tuple[str, ...]]]) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for canonical, patterns in terms:
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match is not None:
                found.append((canonical, match.start()))
                break
    return found


def _negated_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for _canonical, patterns in _NEGATION_TERMS:
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                spans.append(match.span())
    return spans


def _is_negated(position: int, spans: Sequence[tuple[int, int]]) -> bool:
    for start, end in spans:
        if start - _NEGATION_WINDOW <= position <= end + _NEGATION_WINDOW:
            return True
    return False


#: Objects a deletion clause can name. When the deletion clause and the non-deletion
#: clause share one of these, the deletion ask is about that same object.
_TARGET_NOUN_RE = re.compile(
    r"\b(export|copy|copies|archive|file|result|profile|records?|data|information|"
    r"attachment|document|link)\b",
    re.IGNORECASE,
)

#: Words that confine a clause to a narrow scope rather than the whole account.
_SCOPE_ONLY_RE = re.compile(r"\b(?:only|just|solely)\b", re.IGNORECASE)


def _clause_around(text: str, position: int) -> str:
    start = max(0, position - 120)
    end = min(len(text), position + 120)
    return text[start:end]


def _deletion_targets_non_deletion(
    text: str,
    deletion_hits: Sequence[tuple[str, int]],
    non_deletion_hits: Sequence[tuple[str, int]],
) -> bool:
    """True when a deletion clause names the same object as a non-deletion clause.

    ``"I closed my account, but an old download-your-data link still works. Please delete
    that export file as well."`` has an export clause and a deletion clause that both point
    at the export, so the deletion is the instruction and the export mention is its object.
    """

    for _term, deletion_pos in deletion_hits:
        deletion_clause = _clause_around(text, deletion_pos)
        deletion_nouns = {match.group(1).casefold() for match in _TARGET_NOUN_RE.finditer(deletion_clause)}
        if not deletion_nouns:
            continue
        for _non_term, non_pos in non_deletion_hits:
            non_clause = _clause_around(text, non_pos)
            for noun in _TARGET_NOUN_RE.finditer(non_clause):
                if noun.group(1).casefold() in deletion_nouns:
                    return True
    return False


def _is_scoped_only(text: str, non_deletion_hits: Sequence[tuple[str, int]]) -> bool:
    """True when a non-deletion clause is explicitly confined ("marketing lists only")."""

    for _term, position in non_deletion_hits:
        clause = _clause_around(text, position)
        if _SCOPE_ONLY_RE.search(clause):
            return True
    return False


# --------------------------------------------------------------------------------------
# Deterministic classifier
# --------------------------------------------------------------------------------------


def classify_request_text(text: str) -> AuthorizationDecision:
    """Classify ``request_text`` without any model or case-specific table.

    The rules, in order:

    1. An explicit "this is not a deletion request" phrase wins outright.
    2. A deletion term that is not negated, together with no competing non-deletion ask,
       authorizes deletion.
    3. A non-deletion ask alone is ``NOT_APPLICABLE``.
    4. A deletion ask and a non-deletion ask in the same message is ``AMBIGUOUS`` unless a
       negation clause resolves it.
    5. Empty or unrecognised text is ``AMBIGUOUS`` and is reported, never assumed.

    The result carries the canonical terms that fired so a reviewer can audit it without
    reading the raw request again.
    """

    folded = _fold(text or "")
    if not folded.strip():
        return AuthorizationDecision(
            decision=DECISION_AMBIGUOUS,
            reason="request text is empty; authorization cannot be established",
            matched_terms=(),
            negated_terms=(),
            confidence=0.0,
        )

    deletion_hits = _find_terms(folded, _DELETION_TERMS)
    non_deletion_hits = _find_terms(folded, _NON_DELETION_TERMS)
    negation_spans = _negated_spans(folded)
    negation_hits = _find_terms(folded, _NEGATION_TERMS)

    explicit_refusal = [
        (term, pos)
        for term, pos in negation_hits
        if term in {"not-a-deletion-request", "do-not-delete"}
    ]

    active_deletions = [
        (term, pos) for term, pos in deletion_hits if not _is_negated(pos, negation_spans)
    ]
    negated_deletions = [
        (term, pos) for term, pos in deletion_hits if _is_negated(pos, negation_spans)
    ]

    matched = tuple(sorted({term for term, _ in active_deletions}))
    negated = tuple(sorted({term for term, _ in negated_deletions}))

    if explicit_refusal and not active_deletions:
        return AuthorizationDecision(
            decision=DECISION_NOT_APPLICABLE,
            reason=(
                "the message explicitly states it is not a deletion request"
                if any(term == "not-a-deletion-request" for term, _ in explicit_refusal)
                else "the message explicitly asks not to delete"
            ),
            matched_terms=tuple(sorted({term for term, _ in negation_hits})),
            negated_terms=negated,
        )

    non_deletion_terms = tuple(sorted({term for term, _ in non_deletion_hits}))

    if active_deletions and not non_deletion_terms:
        return AuthorizationDecision(
            decision=DECISION_AUTHORIZED,
            reason="the message asks for deletion of the account or its personal data",
            matched_terms=matched,
            negated_terms=negated,
        )

    if not active_deletions and non_deletion_terms:
        return AuthorizationDecision(
            decision=DECISION_NOT_APPLICABLE,
            reason=(
                "the message requests a non-deletion action "
                f"({', '.join(non_deletion_terms)}) and does not ask for deletion"
            ),
            matched_terms=non_deletion_terms,
            negated_terms=negated,
        )

    if active_deletions and non_deletion_terms:
        # A deletion ask next to an access/export/correction ask. If the non-deletion ask
        # is itself negated ("I don't want a copy, delete it") the deletion reading wins.
        non_deletion_positions = [pos for _term, pos in non_deletion_hits]
        if non_deletion_positions and all(
            _is_negated(pos, negation_spans) for pos in non_deletion_positions
        ):
            return AuthorizationDecision(
                decision=DECISION_AUTHORIZED,
                reason="the non-deletion phrasing is negated; the deletion ask controls",
                matched_terms=matched,
                negated_terms=negated,
            )
        # A deletion ask that *targets* the object named by the non-deletion ask (e.g.
        # "delete that export file as well") is the controlling instruction, not a
        # competing one: the person wants the very copy the other clause mentions removed.
        if _deletion_targets_non_deletion(folded, active_deletions, non_deletion_hits):
            return AuthorizationDecision(
                decision=DECISION_AUTHORIZED,
                reason=(
                    "the deletion ask names the same object as the other clause, so the "
                    "deletion instruction controls"
                ),
                matched_terms=matched,
                negated_terms=negated,
                confidence=0.8,
            )
        # A scoped opt-out ("remove me from marketing lists only") is not account
        # deletion; the word "only" or "just" confines it and the account stays.
        if _is_scoped_only(folded, non_deletion_hits):
            return AuthorizationDecision(
                decision=DECISION_NOT_APPLICABLE,
                reason=(
                    "the deletion-sounding clause is confined to a narrow opt-out "
                    f"({', '.join(non_deletion_terms)}), not the account"
                ),
                matched_terms=non_deletion_terms,
                negated_terms=negated,
            )
        return AuthorizationDecision(
            decision=DECISION_AMBIGUOUS,
            reason=(
                "the message contains both a deletion ask "
                f"({', '.join(matched)}) and a non-deletion ask ({', '.join(non_deletion_terms)})"
            ),
            matched_terms=matched,
            negated_terms=negated,
            confidence=0.5,
        )

    return AuthorizationDecision(
        decision=DECISION_AMBIGUOUS,
        reason="the message does not match any known deletion or non-deletion phrasing",
        matched_terms=(),
        negated_terms=negated,
        confidence=0.0,
    )


# --------------------------------------------------------------------------------------
# Optional model route
# --------------------------------------------------------------------------------------


class SemanticClassifier(Protocol):
    """A model-backed classifier.

    Implementations must return a decision and *real* usage; the audit only ever calls a
    classifier the caller explicitly handed in, so no hidden network access can occur.
    """

    def classify(self, text: str) -> tuple[AuthorizationDecision, ModelUsage]: ...


def authorize(
    text: str,
    *,
    classifier: SemanticClassifier | None = None,
    min_confidence: float = 0.6,
) -> AuthorizationDecision:
    """Authorize deletion for ``text``.

    The deterministic classifier runs first. ``classifier`` is only consulted when the
    deterministic result is ``AMBIGUOUS`` or falls below ``min_confidence``. A classifier
    that raises is not retried and its error propagates as :class:`ModelRouteError`, so a
    provider outage can never be mistaken for an authorization decision.
    """

    decision = classify_request_text(text)
    if decision.decision != DECISION_AMBIGUOUS and decision.confidence >= min_confidence:
        return decision
    if classifier is None:
        return decision
    try:
        model_decision, usage = classifier.classify(text)
    except Exception as exc:  # pragma: no cover - provider dependent
        raise ModelRouteError(
            f"the configured semantic classifier failed: {type(exc).__name__}: {exc}"
        ) from exc
    if model_decision.decision not in {
        DECISION_AUTHORIZED,
        DECISION_NOT_APPLICABLE,
        DECISION_AMBIGUOUS,
    }:
        raise ModelRouteError(
            f"the configured semantic classifier returned an unknown decision "
            f"{model_decision.decision!r}"
        )
    return dataclasses.replace(
        model_decision,
        method="model",
        model_usage=usage,
        matched_terms=model_decision.matched_terms or decision.matched_terms,
    )


def authorize_many(
    texts: Iterable[str],
    *,
    classifier: SemanticClassifier | None = None,
) -> tuple[AuthorizationDecision, ...]:
    return tuple(authorize(text, classifier=classifier) for text in texts)


def summarise_decisions(decisions: Iterable[AuthorizationDecision]) -> dict[str, int]:
    """Count decisions by outcome; used by the coverage report."""

    counts: dict[str, int] = {}
    for decision in decisions:
        counts[decision.decision] = counts.get(decision.decision, 0) + 1
    return counts


def resolve_ambiguous_as_not_applicable(
    decision: AuthorizationDecision,
) -> AuthorizationDecision:
    """Fold an unresolved ``AMBIGUOUS`` decision into ``NOT_APPLICABLE``.

    The contract only allows three statuses, and inventing a deletion from an unclear
    request would delete data that was never authorized. Unresolved ambiguity therefore
    becomes ``NOT_APPLICABLE`` with the ambiguity preserved in the reason, and the runner
    reports how often this fallback fired instead of hiding it.
    """

    if decision.decision != DECISION_AMBIGUOUS:
        return decision
    return dataclasses.replace(
        decision,
        decision=DECISION_NOT_APPLICABLE,
        reason=f"unresolved ambiguity treated as non-deletion: {decision.reason}",
        confidence=0.0,
    )


def is_authorized(decision: AuthorizationDecision) -> bool:
    """True when the deletion was positively authorized by this decision."""

    return decision.decision == DECISION_AUTHORIZED


def callable_classifier(fn: Callable[[str], tuple[AuthorizationDecision, ModelUsage]]) -> SemanticClassifier:
    """Adapt a bare callable to :class:`SemanticClassifier` for tests and integrations."""

    class _CallableClassifier:
        def classify(self, text: str) -> tuple[AuthorizationDecision, ModelUsage]:
            return fn(text)

    return _CallableClassifier()
