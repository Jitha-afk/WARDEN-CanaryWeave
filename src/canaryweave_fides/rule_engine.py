"""Deterministic evaluation engine for the WARDEN rule DSL.

The engine evaluates each rule's detection layers (``patterns``, ``semantics``,
``judge``) plus the built-in boolean ``facts`` against a flat
:class:`~canaryweave_fides.models.EvaluationRecord` — the raw ``text`` plus the
six frozen facts — then resolves the rule's boolean ``condition`` over the
resulting per-term truth values. The record is projected from a normalized
:class:`TraceEvent` window by :func:`build_evaluation_record` (internal plumbing
today, the MCP wire later), so both the gate and ``query_llm`` share one
evaluation surface. ``judge`` terms are held False in the deterministic pass;
when a rule would only fire *with* a judge term, the engine emits a
:class:`PendingFidesCheck` so the gate can route the rule's questions to the
FIDES judge on a WARDEN miss.
"""

from __future__ import annotations

import re
from typing import Iterable

from .fact_registry import FROZEN_FACTS
from .models import EvaluationRecord, PendingFidesCheck, PolicyContext, RuleDecision, RuleHit, TraceEvent
from .normalization import has_hidden_unicode_structure, has_untrusted_instruction_shape
from .rule_schema import (
    _LAYER_QUANTIFIER_RE,
    _LIST_QUANTIFIER_RE,
    _TERM_RE,
    JudgeCheck,
    PatternDef,
    RuleDefinition,
    SemanticPattern,
    _condition_references,
    compile_pattern_regex,
)
from .semantics import best_score


class RuleEngineError(ValueError):
    pass


_SAFE_EXPR_RE = re.compile(r"[TrueFalsandornt ()]+")

# Schema-shape labels the framework treats as "structurally a tool call/plan".
_TOOL_CALL_SHAPES = frozenset({"tool_plan_like_json", "tool_plan", "tool_plan_like", "tool_call"})
# The untrusted MCP content origins (ADR 0003 / fact_registry: "tools/call
# result, resources/read, server manifest, sampling/createMessage"). Origin trust
# is a property of where content entered on the wire, not of host policy, so this
# set is fixed rather than policy-relative.
_UNTRUSTED_ORIGINS = frozenset({"resource_content", "tool_output", "server_manifest", "server_sampling"})


def _compute_fact(name: str, events: tuple[TraceEvent, ...], policy: PolicyContext) -> bool:
    """Resolve one frozen fact against a normalized trace window.

    Each fact is a framework-owned boolean derived from the
    :class:`TraceEvent` fields (today) and the MCP wire (later). The closed
    vocabulary lives in :mod:`canaryweave_fides.fact_registry`.
    """
    if name == "from_untrusted_origin":
        return any(event.origin in _UNTRUSTED_ORIGINS for event in events)
    if name == "capability_denied":
        return any(
            event.capability is not None and event.capability not in policy.allowed_capabilities
            for event in events
        )
    if name == "canary_outside_sink":
        return any(
            event.canary_present and event.sink not in policy.allowed_canary_sinks
            for event in events
        )
    if name == "tool_call_shape":
        return any(event.schema_shape in _TOOL_CALL_SHAPES for event in events)
    if name == "hidden_unicode":
        return any(has_hidden_unicode_structure(event.text) for event in events)
    if name == "instruction_shape":
        return any(has_untrusted_instruction_shape(event.text) for event in events)
    raise RuleEngineError(f"Unknown fact: ${name}")


def build_evaluation_record(
    trace: Iterable[TraceEvent], policy: PolicyContext | None = None
) -> EvaluationRecord:
    """Project a normalized :class:`TraceEvent` window onto the flat
    ``{text, facts}`` :class:`EvaluationRecord` the engine evaluates.

    This is the framework-internal plumbing seam: it derives the raw text and the
    six frozen facts from the trace + policy — synthetically today, from the MCP
    wire later. Both the gate and ``query_llm`` route through this so they share a
    single evaluation surface.
    """
    events = tuple(trace)
    ctx = policy or PolicyContext()
    text = " ".join(event.text for event in events if event.text)
    facts = {spec.name: _compute_fact(spec.name, events, ctx) for spec in FROZEN_FACTS}
    return EvaluationRecord(text=text, facts=facts)


class RuleEngine:
    def __init__(self, rules: Iterable[RuleDefinition]):
        self.rules = tuple(rules)

    def evaluate(self, trace: Iterable[TraceEvent], policy: PolicyContext | None = None) -> RuleDecision:
        """Evaluate the corpus over a trace window.

        Thin compatibility adapter: the trace is internal plumbing that is
        projected onto a flat :class:`EvaluationRecord`, then evaluated by the
        shared :meth:`evaluate_record` core.
        """
        return self.evaluate_record(build_evaluation_record(trace, policy))

    def evaluate_record(self, record: EvaluationRecord) -> RuleDecision:
        hits: list[RuleHit] = []
        pending_fides: list[PendingFidesCheck] = []
        for rule in self.rules:
            pattern_values = {p.name: self._eval_pattern(p, record.text) for p in rule.patterns}
            fact_values = {name: record.fact(name) for name in rule.facts}
            semantic_values = {s.name: self._eval_semantic(s, record.text) for s in rule.semantics}
            judge_values = {check.name: False for check in rule.judge_checks}
            term_values: dict[str, bool] = {**pattern_values, **fact_values, **semantic_values, **judge_values}
            layer_names = rule.layer_names

            baseline_hit = self._eval_condition(rule.condition, term_values, layer_names)
            if baseline_hit:
                hits.append(RuleHit(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.tactic,
                    severity=rule.severity,
                    action=rule.action,
                    matched_signals=tuple(name for name, value in fact_values.items() if value),
                    evidence={
                        "scope": rule.scope,
                        "matched_patterns": [name for name, value in pattern_values.items() if value],
                        "matched_semantics": [name for name, value in semantic_values.items() if value],
                    },
                ))

            referenced = _condition_references(rule.condition, layer_names)
            referenced_judge = tuple(check for check in rule.judge_checks if check.name in referenced)
            if referenced_judge and not baseline_hit:
                escalated = dict(term_values)
                for check in referenced_judge:
                    escalated[check.name] = True
                if self._eval_condition(rule.condition, escalated, layer_names):
                    pending_fides.append(PendingFidesCheck(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        action=rule.action,
                        checks=referenced_judge,
                    ))
        final_action = self._final_action(hits)
        return RuleDecision(hits=tuple(hits), final_action=final_action, pending_fides=tuple(pending_fides))

    def _eval_pattern(self, pattern: PatternDef, text: str) -> bool:
        if pattern.type == "regex":
            regex = compile_pattern_regex(str(pattern.params.get("pattern", "")), str(pattern.params.get("flags", "")))
            return bool(regex.search(text or ""))
        needle = str(pattern.params.get("value", "")).lower()
        if not needle:
            return False
        return needle in (text or "").lower()

    def _eval_semantic(self, semantic: SemanticPattern, text: str) -> bool:
        references = [semantic.description]
        if not any(references):
            return False
        return best_score(text or "", references) >= semantic.threshold

    def _expand_quantifiers(self, condition: str, layer_names: dict[str, set[str]]) -> str:
        all_names = set().union(*layer_names.values()) if layer_names else set()

        def expand_list(match: re.Match[str]) -> str:
            quant = match.group(1)
            terms = _TERM_RE.findall(match.group(2))
            if not terms:
                return "False" if quant == "any" else "True"
            joiner = " or " if quant == "any" else " and "
            return "(" + joiner.join(f"${term}" for term in terms) + ")"

        def expand_layer(match: re.Match[str]) -> str:
            quant, layer = match.group(1), match.group(2)
            names = all_names if layer == "them" else layer_names.get(layer, set())
            if not names:
                return "False" if quant == "any" else "True"
            joiner = " or " if quant == "any" else " and "
            return "(" + joiner.join(f"${name}" for name in sorted(names)) + ")"

        expr = _LIST_QUANTIFIER_RE.sub(expand_list, condition)
        return _LAYER_QUANTIFIER_RE.sub(expand_layer, expr)

    def _eval_condition(self, condition: str, term_values: dict[str, bool], layer_names: dict[str, set[str]]) -> bool:
        expr = self._expand_quantifiers(condition, layer_names)

        def replace_term(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in term_values:
                raise RuleEngineError(f"Unknown condition term: ${name}")
            return "True" if term_values[name] else "False"

        expr = _TERM_RE.sub(replace_term, expr)
        if not _SAFE_EXPR_RE.fullmatch(expr):
            raise RuleEngineError(f"Unsafe condition expression: {condition}")
        return bool(eval(expr, {"__builtins__": {}}, {}))

    def _final_action(self, hits: list[RuleHit]) -> str:
        if any(hit.action == "block_and_audit" or hit.severity == "critical" for hit in hits):
            return "block"
        if any(hit.action == "quarantine" for hit in hits):
            return "quarantine"
        return "allow"
