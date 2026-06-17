from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any


class RuleValidationError(ValueError):
    pass


_ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
_ALLOWED_ACTIONS = {"allow", "audit", "quarantine", "block_and_audit"}
_ALLOWED_NAMESPACES = {"signals", "keywords", "semantics", "llm", "fides"}
# Authors only have to declare what a rule actually means: a name, how serious a
# hit is, the boolean condition, and at least one detection section. Everything
# else (id, version, category, scope, description, action, notes) is
# optional and defaulted so clean rules stay readable.
_REQUIRED_FIELDS = {"name", "severity", "condition"}
_DETECTION_SECTIONS = ("signals", "keywords", "semantics", "llm", "fides")
_BOOLEAN_WORDS = {"and", "or", "not", "true", "false"}
_NAMESPACED_REF_RE = re.compile(r"\b(signals|keywords|semantics|llm|fides)\.([A-Za-z_][A-Za-z0-9_]*)\b")
_IDENTIFIER_RE = re.compile(r"(?<!\.)\b[A-Za-z_][A-Za-z0-9_]*\b")
# `any of <ns>.*` / `all of <ns>.*` and `any of (a, b)` / `all of (a, b)` are the
# only quantifier shapes the condition grammar understands. They are expanded the
# same way here (for validation) and in the engine (for evaluation).
_WILDCARD_QUANTIFIER_RE = re.compile(
    r"\b(any|all)\s+of\s+(signals|keywords|semantics|llm|fides)\s*\.\s*\*"
)
_LIST_QUANTIFIER_RE = re.compile(r"\b(any|all)\s+of\s*\(([^)]*)\)")
_REGEX_FLAG_MAP = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A, "u": re.U}


def parse_regex_flags(flags: str) -> int:
    bits = 0
    for char in flags or "":
        try:
            bits |= _REGEX_FLAG_MAP[char]
        except KeyError as exc:
            raise RuleValidationError(f"Unsupported regex flag: {char!r}") from exc
    return bits


def compile_keyword_regex(pattern: str, flags: str = "") -> "re.Pattern[str]":
    try:
        return re.compile(pattern, parse_regex_flags(flags))
    except re.error as exc:
        raise RuleValidationError(f"Invalid regex pattern {pattern!r}: {exc}") from exc


def _split_regex_literal(value: str) -> tuple[str, str] | None:
    """Split a ``/pattern/flags`` literal into ``(pattern, flags)``.

    The closing delimiter is the final ``/``, so patterns may contain internal
    slashes (common in filesystem paths) without escaping.
    """
    if len(value) >= 2 and value.startswith("/"):
        closing = value.rfind("/")
        if closing > 0:
            return value[1:closing], value[closing + 1 :]
    return None


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "rule"


@dataclass(frozen=True)
class SignalDefinition:
    name: str
    type: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KeywordPattern:
    name: str
    type: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SemanticPattern:
    name: str
    description: str
    threshold: float
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FidesCheck:
    name: str
    prompt: str
    threshold: float
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleDefinition:
    id: str
    name: str
    version: str
    category: str
    severity: str
    scope: str
    description: str
    signals: tuple[SignalDefinition, ...]
    condition: str
    recommended_action: str
    fixtures: dict[str, list[str]]
    safety_notes: str
    meta: dict[str, Any] = field(default_factory=dict)
    keywords: tuple[KeywordPattern, ...] = ()
    semantics: tuple[SemanticPattern, ...] = ()
    fides_checks: tuple[FidesCheck, ...] = ()


def _threshold(value: Any, section: str, name: str) -> float:
    try:
        threshold = float(value)
    except (TypeError, ValueError) as exc:
        raise RuleValidationError(f"{section}.{name} threshold must be numeric") from exc
    if not 0.0 <= threshold <= 1.0:
        raise RuleValidationError(f"{section}.{name} threshold must be between 0.0 and 1.0")
    return threshold


def _parse_signals(raw_signals: Any) -> tuple[SignalDefinition, ...]:
    if raw_signals is None:
        return ()
    if not isinstance(raw_signals, list):
        if not isinstance(raw_signals, dict):
            raise RuleValidationError("signals must be a list or mapping")
        raw_signals = [
            {"name": str(raw_name), **(raw if isinstance(raw, dict) else {"type": raw})}
            for raw_name, raw in raw_signals.items()
        ]
    signals: list[SignalDefinition] = []
    seen: set[str] = set()
    for raw in raw_signals:
        if not isinstance(raw, dict) or "name" not in raw or "type" not in raw:
            raise RuleValidationError("every signal needs name and type")
        name = str(raw["name"])
        if name in seen:
            raise RuleValidationError(f"Duplicate signal name: {name}")
        seen.add(name)
        params = {k: v for k, v in raw.items() if k not in {"name", "type"}}
        signals.append(SignalDefinition(name=name, type=str(raw["type"]), params=params))
    return tuple(signals)


def _keyword_from_terse(name: str, value: Any) -> KeywordPattern:
    """Build a keyword from the terse keyed-by-name form.

    A string value is a ``/regex/flags`` literal when slash-delimited, otherwise a
    case-insensitive exact substring. A mapping value is the explicit structured
    form (``type`` plus ``pattern``/``value``/``feature``).
    """
    if isinstance(value, str):
        literal = _split_regex_literal(value)
        if literal is not None:
            pattern, flags = literal
            compile_keyword_regex(pattern, flags)
            return KeywordPattern(name=name, type="regex", params={"pattern": pattern, "flags": flags})
        return KeywordPattern(name=name, type="exact", params={"value": value})
    if isinstance(value, dict):
        kind = str(value.get("type", "regex" if "pattern" in value else "exact"))
        if kind == "feature":
            return KeywordPattern(name=name, type="feature", params={"feature": str(value.get("feature", name))})
        if kind not in {"exact", "regex"}:
            raise RuleValidationError(f"Unsupported keyword type: {kind}")
        params = {k: v for k, v in value.items() if k != "type"}
        if "pattern" not in params and "value" not in params:
            raise RuleValidationError(f"keyword {name} requires pattern or value")
        if kind == "regex":
            compile_keyword_regex(str(params.get("pattern", params.get("value"))), str(params.get("flags", "")))
        return KeywordPattern(name=name, type=kind, params=params)
    raise RuleValidationError(f"keyword {name} must be a string or mapping")


def _parse_keywords(raw_keywords: Any) -> tuple[KeywordPattern, ...]:
    if raw_keywords is None:
        return ()
    patterns: list[KeywordPattern] = []
    seen: set[str] = set()
    if isinstance(raw_keywords, dict):
        for raw_name, value in raw_keywords.items():
            name = str(raw_name)
            if name in seen:
                raise RuleValidationError(f"Duplicate keyword name: {name}")
            seen.add(name)
            patterns.append(_keyword_from_terse(name, value))
        return tuple(patterns)
    if not isinstance(raw_keywords, list):
        raise RuleValidationError("keywords must be a list or mapping")
    for raw in raw_keywords:
        if not isinstance(raw, dict) or "name" not in raw or "type" not in raw:
            raise RuleValidationError("every keyword needs name and type")
        name = str(raw["name"])
        if name in seen:
            raise RuleValidationError(f"Duplicate keyword name: {name}")
        seen.add(name)
        kind = str(raw["type"])
        if kind not in {"exact", "regex", "feature"}:
            raise RuleValidationError(f"Unsupported keyword type: {kind}")
        params = {k: v for k, v in raw.items() if k not in {"name", "type"}}
        if kind in {"exact", "regex"} and not ("pattern" in params or "value" in params):
            raise RuleValidationError(f"keyword {name} requires pattern or value")
        if kind == "regex":
            compile_keyword_regex(str(params.get("pattern", params.get("value"))), str(params.get("flags", "")))
        patterns.append(KeywordPattern(name=name, type=kind, params=params))
    return tuple(patterns)


def _parse_semantics(raw_semantics: Any) -> tuple[SemanticPattern, ...]:
    if raw_semantics is None:
        return ()
    if not isinstance(raw_semantics, list):
        if not isinstance(raw_semantics, dict):
            raise RuleValidationError("semantics must be a list or mapping")
        raw_semantics = [
            {"name": str(raw_name), **(raw if isinstance(raw, dict) else {"phrase": raw})}
            for raw_name, raw in raw_semantics.items()
        ]
    patterns: list[SemanticPattern] = []
    seen: set[str] = set()
    for raw in raw_semantics:
        if not isinstance(raw, dict) or "name" not in raw:
            raise RuleValidationError("every semantic pattern needs name")
        name = str(raw["name"])
        if name in seen:
            raise RuleValidationError(f"Duplicate semantic name: {name}")
        seen.add(name)
        phrase = raw.get("phrase", raw.get("description"))
        if phrase is None:
            raise RuleValidationError(f"semantic pattern {name} needs phrase")
        threshold = _threshold(raw.get("threshold", 0.5), "semantics", name)
        params = {k: v for k, v in raw.items() if k not in {"name", "phrase", "description", "threshold"}}
        patterns.append(SemanticPattern(name=name, description=str(phrase), threshold=threshold, params=params))
    return tuple(patterns)


def _parse_llm_checks(raw_checks: Any, section: str) -> tuple[FidesCheck, ...]:
    if raw_checks is None:
        return ()
    if not isinstance(raw_checks, list):
        if not isinstance(raw_checks, dict):
            raise RuleValidationError(f"{section} must be a list or mapping")
        raw_checks = [
            {"name": str(raw_name), **(raw if isinstance(raw, dict) else {"query": raw})}
            for raw_name, raw in raw_checks.items()
        ]
    checks: list[FidesCheck] = []
    seen: set[str] = set()
    for raw in raw_checks:
        if not isinstance(raw, dict) or "name" not in raw:
            raise RuleValidationError(f"every {section} check needs name")
        name = str(raw["name"])
        if name in seen:
            raise RuleValidationError(f"Duplicate {section} check name: {name}")
        seen.add(name)
        query = raw.get("query", raw.get("prompt"))
        if query is None:
            raise RuleValidationError(f"{section} check {name} needs query")
        threshold = _threshold(raw.get("threshold", 0.5), section, name)
        params = {k: v for k, v in raw.items() if k not in {"name", "query", "prompt", "threshold"}}
        checks.append(FidesCheck(name=name, prompt=str(query), threshold=threshold, params=params))
    return tuple(checks)


def _condition_references(condition: str, names_by_namespace: dict[str, set[str]]) -> set[str]:
    refs: set[str] = set()
    residual = condition

    def take_wildcard(match: "re.Match[str]") -> str:
        quant, namespace = match.group(1), match.group(2)
        names = names_by_namespace.get(namespace, set())
        if not names:
            raise RuleValidationError(
                f"condition uses '{quant} of {namespace}.*' but rule defines no {namespace}"
            )
        refs.update(f"{namespace}.{name}" for name in names)
        return " True "

    def take_list(match: "re.Match[str]") -> str:
        for item in match.group(2).split(","):
            token = item.strip()
            if token:
                refs.add(token)
        return " True "

    residual = _WILDCARD_QUANTIFIER_RE.sub(take_wildcard, residual)
    residual = _LIST_QUANTIFIER_RE.sub(take_list, residual)

    refs.update(f"{namespace}.{name}" for namespace, name in _NAMESPACED_REF_RE.findall(residual))
    stripped = _NAMESPACED_REF_RE.sub(" ", residual)
    refs.update(
        token for token in _IDENTIFIER_RE.findall(stripped)
        if token.lower() not in _BOOLEAN_WORDS and token not in _ALLOWED_NAMESPACES
    )
    return refs


def validate_rule(data: dict[str, Any]) -> RuleDefinition:
    if "fixtures" in data:
        raise RuleValidationError("fixtures are no longer part of the WARDEN rule grammar")
    if "llm" in data and "fides" in data:
        raise RuleValidationError("Use llm; fides is only accepted as a deprecated alias")
    missing = sorted(_REQUIRED_FIELDS - set(data))
    if missing:
        raise RuleValidationError(f"Missing required rule fields: {missing}")
    name = str(data["name"])
    severity = str(data["severity"])
    if severity not in _ALLOWED_SEVERITIES:
        raise RuleValidationError(f"Invalid severity: {severity}")
    action = str(data.get("recommended_action", "audit"))
    if action not in _ALLOWED_ACTIONS:
        raise RuleValidationError(f"Invalid recommended_action: {action}")

    signals = _parse_signals(data.get("signals"))
    keywords = _parse_keywords(data.get("keywords"))
    semantics = _parse_semantics(data.get("semantics"))
    llm_section = "llm" if "llm" in data else "fides"
    fides_checks = _parse_llm_checks(data.get(llm_section), llm_section)
    if not (signals or keywords or semantics or fides_checks):
        raise RuleValidationError(
            "rule needs at least one detection section: signals, keywords, semantics, or llm"
        )

    names_by_namespace = {
        "signals": {item.name for item in signals},
        "keywords": {item.name for item in keywords},
        "semantics": {item.name for item in semantics},
        "llm": {item.name for item in fides_checks},
        "fides": {item.name for item in fides_checks},
    }
    valid_refs = set(names_by_namespace["signals"])
    for namespace, names in names_by_namespace.items():
        valid_refs.update(f"{namespace}.{name}" for name in names)

    condition = str(data["condition"])
    referenced = _condition_references(condition, names_by_namespace)
    unknown = sorted(referenced - valid_refs)
    if unknown:
        raise RuleValidationError(f"Condition references unknown rule terms: {', '.join(unknown)}")

    meta = data.get("meta") or {}
    if not isinstance(meta, dict):
        raise RuleValidationError("meta must be a mapping when provided")

    return RuleDefinition(
        id=str(data.get("id") or _slug(name)),
        name=name,
        version=str(data.get("version", "0.1.0")),
        category=str(data.get("category", "uncategorized")),
        severity=severity,
        scope=str(data.get("scope", "event_window")),
        description=str(data.get("description", "")),
        signals=signals,
        condition=condition,
        recommended_action=action,
        fixtures={"positive": [], "negative": []},
        safety_notes=str(data.get("safety_notes", "")),
        meta=dict(meta),
        keywords=keywords,
        semantics=semantics,
        fides_checks=fides_checks,
    )
