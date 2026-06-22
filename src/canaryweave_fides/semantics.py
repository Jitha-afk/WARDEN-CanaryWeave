from __future__ import annotations

from collections import Counter
import difflib
import math
import re

_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "with",
}


def _tokens(text: str) -> list[str]:
    return [
        token
        for token in re.split(r"[^a-z0-9]+", text.lower())
        if token and token not in _STOPWORDS
    ]


def _cosine(left: Counter[str], right: Counter[str]) -> float:
    if not left or not right:
        return 0.0
    dot = sum(count * right[token] for token, count in left.items())
    left_norm = math.sqrt(sum(count * count for count in left.values()))
    right_norm = math.sqrt(sum(count * count for count in right.values()))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def similarity(text: str, reference: str) -> float:
    """Return a deterministic provider-free similarity score in ``[0, 1]``.

    Text is normalized to lowercase alphanumeric tokens with a small English
    stopword list removed. The primary score is multiset token cosine, which is
    order-independent and rewards shared intent-bearing words. For short or
    morphologically close strings, the cosine is blended with a SequenceMatcher
    ratio over sorted unique tokens, keeping the fallback deterministic while
    avoiding raw word-order sensitivity. The returned score is the stronger of
    the pure token cosine and the blended score.
    """
    left_tokens = _tokens(text or "")
    right_tokens = _tokens(reference or "")
    token_cosine = _cosine(Counter(left_tokens), Counter(right_tokens))
    if not left_tokens or not right_tokens:
        return 0.0

    left_sorted = " ".join(sorted(set(left_tokens)))
    right_sorted = " ".join(sorted(set(right_tokens)))
    sequence_ratio = difflib.SequenceMatcher(None, left_sorted, right_sorted).ratio()
    score = max(token_cosine, 0.5 * token_cosine + 0.5 * sequence_ratio)
    return max(0.0, min(1.0, score))


def best_score(text: str, references: list[str]) -> float:
    """Return the best similarity score for ``text`` against any reference."""
    return max((similarity(text, reference) for reference in references), default=0.0)
