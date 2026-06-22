"""Schema and validation for the CanaryWeave WARDEN rule DSL.

A ``.war`` file is a *ruleset*: an ordered set of ``rule Name { ... }`` blocks.
Each rule carries an identity envelope (``meta:``) plus up to three detection
layers (``patterns``, ``semantics``, ``judge``) and a boolean ``condition`` over
the terms those layers declare and the built-in ``$fact`` references.

The DSL grammar lives in :mod:`canaryweave_fides.rule_loader` (the tokenizer and
block parser). This module owns *semantics*: it consumes the structured dict a
parsed rule produces and validates it into a frozen :class:`RuleDefinition`.

The contract enforced here:

* ``meta.id`` (``cwfr-*``), ``meta.severity`` and at least one
  ``meta.technique`` anchor are required.
* A rule must declare at least one detection layer (``patterns``,
  ``semantics`` or ``judge``) or reference at least one built-in ``$fact``. A
  rule's character is *descriptive*, not declared: a patterns-only rule is a
  brittle signature; a rule that reasons over facts/semantics/judge is a
  structured policy. The brittle-vs-structured contrast lives at the guard-stack
  level, not on the rule.
* Every ``$term`` declared by a layer must be referenced by ``condition`` and
  every ``$term`` referenced must be either declared by a layer or a built-in
  ``$fact`` (no dead terms, no unknown terms); term names are unique across
  layers.
* The technique anchor's MITRE framework is inferred from the id prefix and its
  tactic becomes the rule's classification axis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from .fact_registry import FACT_NAMES


class RuleValidationError(ValueError):
    pass


_ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
_ALLOWED_ACTIONS = {"allow", "audit", "quarantine", "block_and_audit"}
_ALLOWED_MAPPING_STRENGTHS = {"direct", "analogical"}
_ID_PREFIX = "cwfr-"
_DETECTION_LAYERS = ("patterns", "semantics", "judge")
# meta keys promoted to typed RuleDefinition fields; everything else survives in
# the free-form ``meta`` mapping (author, status, source, license, ...).
_RESERVED_META = {
    "id",
    "version",
    "severity",
    "action",
    "scope",
    "description",
    "technique",
    "defense",
    "safety",
}

# Condition grammar. References are bare ``$name`` tokens (YARA-faithful); the
# only quantifier shapes are ``any|all of <layer>``, ``any|all of them`` and
# ``any|all of ($a, $b)``. These regexes are shared with the engine so that
# validation and evaluation expand conditions identically.
_TERM_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_LAYER_QUANTIFIER_RE = re.compile(
    r"\b(any|all)\s+of\s+(patterns|semantics|judge|them)\b"
)
_LIST_QUANTIFIER_RE = re.compile(r"\b(any|all)\s+of\s*\(([^)]*)\)")
_BOOLEAN_WORDS = {"and", "or", "not", "true", "false"}

_REGEX_FLAG_MAP = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A, "u": re.U}


def parse_regex_flags(flags: str) -> int:
    bits = 0
    for char in flags or "":
        try:
            bits |= _REGEX_FLAG_MAP[char]
        except KeyError as exc:
            raise RuleValidationError(f"Unsupported regex flag: {char!r}") from exc
    return bits


def compile_pattern_regex(pattern: str, flags: str = "") -> "re.Pattern[str]":
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


def _split_top_level(text: str, separator: str = ",") -> list[str]:
    """Split ``text`` on ``separator`` characters that sit outside parentheses."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
            current.append(char)
        elif char == ")":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PatternDef:
    """A text indicator: a regex or an exact (case-insensitive) substring."""

    name: str
    type: str  # "regex" | "exact"
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SemanticPattern:
    """An engine-scored similarity check against a natural-language description."""

    name: str
    description: str
    threshold: float
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class JudgeCheck:
    """A natural-language question routed to the FIDES judge on a WARDEN miss."""

    name: str
    prompt: str
    threshold: float
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TechniqueRef:
    """A MITRE technique anchor: framework inferred from the id prefix."""

    framework: str  # "ATT&CK" | "ATLAS" | "D3FEND"
    technique_id: str
    tactic: str | None = None
    mapping_strength: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "framework": self.framework,
            "technique_id": self.technique_id,
        }
        if self.tactic:
            data["tactic"] = self.tactic
        if self.mapping_strength:
            data["mapping_strength"] = self.mapping_strength
        return data


@dataclass(frozen=True)
class RuleDefinition:
    id: str
    name: str
    version: str
    severity: str
    scope: str
    description: str
    action: str
    tactic: str
    technique: tuple[TechniqueRef, ...]
    defense: tuple[TechniqueRef, ...]
    condition: str
    safety: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    patterns: tuple[PatternDef, ...] = ()
    facts: tuple[str, ...] = ()
    semantics: tuple[SemanticPattern, ...] = ()
    judge_checks: tuple[JudgeCheck, ...] = ()

    @property
    def layer_names(self) -> dict[str, set[str]]:
        return {
            "patterns": {item.name for item in self.patterns},
            "semantics": {item.name for item in self.semantics},
            "judge": {item.name for item in self.judge_checks},
        }


# --------------------------------------------------------------------------- #
# Layer parsing
# --------------------------------------------------------------------------- #


def _threshold(value: Any, layer: str, name: str) -> float:
    try:
        threshold = float(value)
    except (TypeError, ValueError) as exc:
        raise RuleValidationError(f"{layer} ${name} threshold must be numeric") from exc
    if not 0.0 <= threshold <= 1.0:
        raise RuleValidationError(
            f"{layer} ${name} threshold must be between 0.0 and 1.0"
        )
    return threshold


def _require_name(raw: Any, layer: str) -> str:
    if not isinstance(raw, dict) or "name" not in raw:
        raise RuleValidationError(f"every {layer} entry needs a name")
    return str(raw["name"])


def _parse_patterns(raw_patterns: Any) -> tuple[PatternDef, ...]:
    if raw_patterns is None:
        return ()
    if not isinstance(raw_patterns, list):
        raise RuleValidationError("patterns must be a list")
    patterns: list[PatternDef] = []
    for raw in raw_patterns:
        name = _require_name(raw, "patterns")
        kind = str(raw.get("type", "exact"))
        if kind == "regex":
            pattern = str(raw.get("pattern", ""))
            flags = str(raw.get("flags", ""))
            compile_pattern_regex(pattern, flags)
            patterns.append(
                PatternDef(
                    name=name, type="regex", params={"pattern": pattern, "flags": flags}
                )
            )
        elif kind == "exact":
            if "value" not in raw:
                raise RuleValidationError(f"pattern ${name} requires a value")
            patterns.append(
                PatternDef(name=name, type="exact", params={"value": str(raw["value"])})
            )
        else:
            raise RuleValidationError(f"Unsupported pattern type: {kind}")
    return tuple(patterns)


def _parse_semantics(raw_semantics: Any) -> tuple[SemanticPattern, ...]:
    if raw_semantics is None:
        return ()
    if not isinstance(raw_semantics, list):
        raise RuleValidationError("semantics must be a list")
    patterns: list[SemanticPattern] = []
    for raw in raw_semantics:
        name = _require_name(raw, "semantics")
        if "description" not in raw:
            raise RuleValidationError(f"semantic ${name} needs a description")
        threshold = _threshold(raw.get("threshold", 0.5), "semantics", name)
        patterns.append(
            SemanticPattern(
                name=name, description=str(raw["description"]), threshold=threshold
            )
        )
    return tuple(patterns)


def _parse_judge(raw_judge: Any) -> tuple[JudgeCheck, ...]:
    if raw_judge is None:
        return ()
    if not isinstance(raw_judge, list):
        raise RuleValidationError("judge must be a list")
    checks: list[JudgeCheck] = []
    for raw in raw_judge:
        name = _require_name(raw, "judge")
        if "prompt" not in raw:
            raise RuleValidationError(f"judge check ${name} needs a prompt")
        threshold = _threshold(raw.get("threshold", 0.5), "judge", name)
        checks.append(
            JudgeCheck(name=name, prompt=str(raw["prompt"]), threshold=threshold)
        )
    return tuple(checks)


# --------------------------------------------------------------------------- #
# Technique anchor parsing
# --------------------------------------------------------------------------- #


def _infer_framework(technique_id: str) -> str:
    if technique_id.startswith("AML."):
        return "ATLAS"
    if technique_id.startswith("D3-") or technique_id.startswith("D3FEND"):
        return "D3FEND"
    if technique_id.startswith("T") and technique_id[1:2].isdigit():
        return "ATT&CK"
    raise RuleValidationError(
        f"Cannot infer MITRE framework from technique id: {technique_id!r}"
    )


def _parse_technique_anchor(raw: Any, *, label: str) -> tuple[TechniqueRef, ...]:
    if raw in (None, ""):
        return ()
    if isinstance(raw, (list, tuple)):
        items = [str(item) for item in raw]
    else:
        items = _split_top_level(str(raw))
    refs: list[TechniqueRef] = []
    for item in items:
        match = re.match(r"^([A-Za-z0-9.\-]+)\s*(?:\((.*)\))?\s*$", item)
        if not match:
            raise RuleValidationError(f"Malformed {label} anchor: {item!r}")
        technique_id = match.group(1)
        framework = _infer_framework(technique_id)
        tactic: str | None = None
        mapping_strength: str | None = None
        inner = match.group(2)
        if inner:
            parts = _split_top_level(inner)
            if parts:
                tactic = parts[0]
            if len(parts) > 1:
                mapping_strength = parts[1].lower()
                if mapping_strength not in _ALLOWED_MAPPING_STRENGTHS:
                    raise RuleValidationError(
                        f"{label} mapping_strength must be direct or analogical, got {mapping_strength!r}"
                    )
        refs.append(
            TechniqueRef(
                framework=framework,
                technique_id=technique_id,
                tactic=tactic,
                mapping_strength=mapping_strength,
            )
        )
    return tuple(refs)


# --------------------------------------------------------------------------- #
# Condition validation
# --------------------------------------------------------------------------- #


def _condition_references(condition: str, layer_names: dict[str, set[str]]) -> set[str]:
    """Return the set of ``$term`` names a condition references.

    Layer and list quantifiers are expanded first; empty-layer quantifiers are a
    validation error so authors cannot reference a layer they did not declare.
    """
    refs: set[str] = set()
    all_names = set().union(*layer_names.values()) if layer_names else set()

    def take_layer(match: "re.Match[str]") -> str:
        quant, layer = match.group(1), match.group(2)
        names = all_names if layer == "them" else layer_names.get(layer, set())
        if not names:
            raise RuleValidationError(
                f"condition uses '{quant} of {layer}' but rule declares no such terms"
            )
        refs.update(names)
        return " True "

    def take_list(match: "re.Match[str]") -> str:
        for term in _TERM_RE.findall(match.group(2)):
            refs.add(term)
        return " True "

    residual = _LIST_QUANTIFIER_RE.sub(take_list, condition)
    residual = _LAYER_QUANTIFIER_RE.sub(take_layer, residual)
    refs.update(_TERM_RE.findall(residual))

    leftover = _TERM_RE.sub(" ", residual)
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", leftover):
        if token.lower() not in _BOOLEAN_WORDS:
            raise RuleValidationError(
                f"condition contains an undelimited term (missing $?): {token!r}"
            )
    return refs


# --------------------------------------------------------------------------- #
# Top-level validation
# --------------------------------------------------------------------------- #


def _meta_str(meta: dict[str, Any], key: str, default: str) -> str:
    value = meta.get(key, default)
    return default if value is None else str(value)


def validate_rule(data: dict[str, Any]) -> RuleDefinition:
    if "name" not in data:
        raise RuleValidationError("rule is missing its name (the rule header)")
    name = str(data["name"])

    meta = data.get("meta") or {}
    if not isinstance(meta, dict):
        raise RuleValidationError("meta must be a mapping")

    rule_id = str(meta.get("id", "")).strip()
    if not rule_id:
        raise RuleValidationError(f"rule {name} is missing meta.id")
    if not rule_id.startswith(_ID_PREFIX):
        raise RuleValidationError(f"rule id must start with {_ID_PREFIX!r}: {rule_id}")

    severity = str(meta.get("severity", "")).strip()
    if severity not in _ALLOWED_SEVERITIES:
        raise RuleValidationError(f"Invalid severity for {rule_id}: {severity!r}")

    action = _meta_str(meta, "action", "audit")
    if action not in _ALLOWED_ACTIONS:
        raise RuleValidationError(f"Invalid action for {rule_id}: {action!r}")

    technique = _parse_technique_anchor(meta.get("technique"), label="technique")
    if not any(ref.framework in {"ATT&CK", "ATLAS"} for ref in technique):
        raise RuleValidationError(
            f"rule {rule_id} needs at least one ATT&CK or ATLAS technique anchor"
        )
    defense = _parse_technique_anchor(meta.get("defense"), label="defense")
    for ref in defense:
        if ref.framework != "D3FEND":
            raise RuleValidationError(
                f"meta.defense anchors must be D3FEND ids, got {ref.technique_id}"
            )

    patterns = _parse_patterns(data.get("patterns"))
    semantics = _parse_semantics(data.get("semantics"))
    judge_checks = _parse_judge(data.get("judge"))

    # Names are unique across all layers (bare-$ references are global per rule).
    declared: set[str] = set()
    for layer in (patterns, semantics, judge_checks):
        for item in layer:
            if item.name in declared:
                raise RuleValidationError(
                    f"rule {rule_id} reuses term name ${item.name} across layers"
                )
            declared.add(item.name)

    layer_names = {
        "patterns": {item.name for item in patterns},
        "semantics": {item.name for item in semantics},
        "judge": {item.name for item in judge_checks},
    }

    condition = str(data.get("condition", "")).strip()
    if not condition:
        raise RuleValidationError(f"rule {rule_id} is missing a condition")
    referenced = _condition_references(condition, layer_names)

    # ``$fact`` references are built-in (the frozen registry is their
    # declaration), so they are "known" without appearing in any layer.
    facts = tuple(sorted(referenced & FACT_NAMES))
    unknown = sorted(referenced - declared - FACT_NAMES)
    if unknown:
        raise RuleValidationError(
            f"condition references undeclared terms: {', '.join('$' + u for u in unknown)}"
        )
    dead = sorted(declared - referenced)
    if dead:
        raise RuleValidationError(
            f"rule {rule_id} declares terms never used in its condition: {', '.join('$' + d for d in dead)}"
        )

    # A rule's character is descriptive, not declared: it needs at least one
    # detection layer or a built-in ``$fact`` reference. Brittle-vs-structured is
    # read from which layers/facts it uses; the head-to-head lives at the stack
    # level.
    if not (patterns or semantics or judge_checks or facts):
        raise RuleValidationError(
            f"rule {rule_id} must declare at least one detection layer "
            f"(patterns, semantics, or judge) or reference at least one fact"
        )

    tactic = next(
        (
            ref.tactic
            for ref in technique
            if ref.framework in {"ATT&CK", "ATLAS"} and ref.tactic
        ),
        "unspecified",
    )

    leftover_meta = {k: v for k, v in meta.items() if k not in _RESERVED_META}

    return RuleDefinition(
        id=rule_id,
        name=name,
        version=_meta_str(meta, "version", "0.1.0"),
        severity=severity,
        scope=_meta_str(meta, "scope", "event_window"),
        description=_meta_str(meta, "description", ""),
        action=action,
        tactic=tactic,
        technique=technique,
        defense=defense,
        condition=condition,
        safety=_meta_str(meta, "safety", ""),
        meta=leftover_meta,
        patterns=patterns,
        facts=facts,
        semantics=semantics,
        judge_checks=judge_checks,
    )
