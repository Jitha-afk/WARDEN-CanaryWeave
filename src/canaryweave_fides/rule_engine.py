from __future__ import annotations

import re
from typing import Iterable

from .models import PendingFidesCheck, PolicyContext, RuleDecision, RuleHit, TraceEvent
from .normalization import has_hidden_unicode_structure, has_untrusted_instruction_shape
from .rule_schema import (
    _LIST_QUANTIFIER_RE,
    _NAMESPACED_REF_RE,
    _WILDCARD_QUANTIFIER_RE,
    FidesCheck,
    KeywordPattern,
    RuleDefinition,
    SemanticPattern,
    SignalDefinition,
    compile_keyword_regex,
)
from .semantics import best_score


class RuleEngineError(ValueError):
    pass


class RuleEngine:
    def __init__(self, rules: Iterable[RuleDefinition]):
        self.rules = tuple(rules)

    def evaluate(self, trace: Iterable[TraceEvent], policy: PolicyContext | None = None) -> RuleDecision:
        events = tuple(trace)
        ctx = policy or PolicyContext()
        hits: list[RuleHit] = []
        pending_fides: list[PendingFidesCheck] = []
        for rule in self.rules:
            signal_values = {signal.name: self._eval_signal(signal, events, ctx) for signal in rule.signals}
            keyword_values = {keyword.name: self._eval_keyword(keyword, events) for keyword in rule.keywords}
            semantic_values = {semantic.name: self._eval_semantic(semantic, events) for semantic in rule.semantics}
            fides_false_values = {check.name: False for check in rule.fides_checks}
            namespaces: dict[str, dict[str, bool]] = {
                "signals": signal_values,
                "keywords": keyword_values,
                "semantics": semantic_values,
                "llm": fides_false_values,
                "fides": fides_false_values,
            }
            baseline_hit = self._eval_condition(rule.condition, namespaces)
            if baseline_hit:
                matched = tuple(name for name, value in signal_values.items() if value)
                matched_keywords = tuple(name for name, value in keyword_values.items() if value)
                matched_semantics = tuple(name for name, value in semantic_values.items() if value)
                hits.append(RuleHit(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action=rule.recommended_action,
                    matched_signals=matched,
                    evidence={
                        "scope": rule.scope,
                        "matched_keywords": list(matched_keywords),
                        "matched_semantics": list(matched_semantics),
                    },
                ))
            referenced_fides = self._referenced_fides_checks(rule.condition, rule.fides_checks)
            if referenced_fides and not baseline_hit:
                fides_true_namespaces = dict(namespaces)
                fides_true_namespaces["llm"] = {check.name: True for check in rule.fides_checks}
                fides_true_namespaces["fides"] = {check.name: True for check in rule.fides_checks}
                if self._eval_condition(rule.condition, fides_true_namespaces):
                    pending_fides.append(PendingFidesCheck(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        action=rule.recommended_action,
                        checks=referenced_fides,
                    ))
        final_action = self._final_action(hits)
        return RuleDecision(hits=tuple(hits), final_action=final_action, pending_fides=tuple(pending_fides))

    def _eval_keyword(self, keyword: KeywordPattern, events: tuple[TraceEvent, ...]) -> bool:
        params = keyword.params
        if keyword.type == "feature":
            feature = str(params.get("feature", keyword.name))
            return any(bool(event.metadata.get(feature, False)) for event in events)
        raw = params.get("pattern", params.get("value"))
        if raw is None:
            return False
        if keyword.type == "regex":
            regex = compile_keyword_regex(str(raw), str(params.get("flags", "")))
            return any(regex.search(event.text or "") for event in events)
        needle = str(raw)
        if bool(params.get("case_sensitive", False)):
            return any(needle in (event.text or "") for event in events)
        lowered = needle.lower()
        return any(lowered in (event.text or "").lower() for event in events)

    def _eval_semantic(self, semantic: SemanticPattern, events: tuple[TraceEvent, ...]) -> bool:
        references = [semantic.description]
        for key in ("phrases", "examples"):
            references.extend(self._semantic_references(semantic.params.get(key)))
        nested_params = semantic.params.get("params")
        if isinstance(nested_params, dict):
            for key in ("phrases", "examples"):
                references.extend(self._semantic_references(nested_params.get(key)))
        usable_references = [reference for reference in references if reference]
        if not usable_references:
            return False
        return any(best_score(event.text or "", usable_references) >= semantic.threshold for event in events)

    def _semantic_references(self, raw: object) -> list[str]:
        if raw is None:
            return []
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, list):
            return [str(item) for item in raw if item]
        return []

    def _referenced_fides_checks(self, condition: str, checks: tuple[FidesCheck, ...]) -> tuple[FidesCheck, ...]:
        checks_by_name = {check.name: check for check in checks}
        referenced: set[str] = set()
        residual = condition

        def take_wildcard(match: re.Match[str]) -> str:
            namespace = match.group(2)
            if namespace in {"llm", "fides"}:
                referenced.update(checks_by_name)
            return " "

        def take_list(match: re.Match[str]) -> str:
            for item in match.group(2).split(","):
                token = item.strip()
                if token.startswith(("llm.", "fides.")):
                    referenced.add(token.split(".", 1)[1])
            return " "

        residual = _WILDCARD_QUANTIFIER_RE.sub(take_wildcard, residual)
        residual = _LIST_QUANTIFIER_RE.sub(take_list, residual)
        referenced.update(name for namespace, name in _NAMESPACED_REF_RE.findall(residual) if namespace in {"llm", "fides"})
        return tuple(check for check in checks if check.name in referenced)

    def _eval_signal(self, signal: SignalDefinition, events: tuple[TraceEvent, ...], policy: PolicyContext) -> bool:
        params = signal.params
        if signal.type == "event_field_equals":
            field = str(params["field"])
            value = params["value"]
            return any(event.field_value(field) == value for event in events)
        if signal.type == "event_field_in":
            field = str(params["field"])
            values = set(params.get("values", []))
            return any(event.field_value(field) in values for event in events)
        if signal.type == "schema_shape":
            shape = params.get("shape")
            return any(event.schema_shape == shape for event in events)
        if signal.type == "capability_policy":
            relation = params.get("relation")
            if relation != "not_in_allowed_capabilities":
                raise RuleEngineError(f"Unsupported capability relation: {relation}")
            return any(
                event.capability is not None and event.capability not in policy.allowed_capabilities
                for event in events
            )
        if signal.type == "canary_flow":
            relation = params.get("relation")
            if relation != "outside_allowed_sink":
                raise RuleEngineError(f"Unsupported canary relation: {relation}")
            return any(
                event.canary_present and event.sink not in policy.allowed_canary_sinks
                for event in events
            )
        if signal.type == "feature_flag":
            feature = str(params.get("feature"))
            expected = bool(params.get("value", True))
            return any(bool(event.metadata.get(feature, False)) is expected for event in events)
        if signal.type == "event_field_contains":
            field = str(params["field"])
            needle = str(params["value"]).lower()
            return any(needle in str(event.field_value(field) or "").lower() for event in events)
        if signal.type == "text_structure":
            feature = params.get("feature")
            if feature == "hidden_unicode":
                return any(has_hidden_unicode_structure(event.text) for event in events)
            if feature == "untrusted_instruction_shape":
                return any(has_untrusted_instruction_shape(event.text) for event in events)
            raise RuleEngineError(f"Unsupported text feature: {feature}")
        raise RuleEngineError(f"Unsupported signal type: {signal.type}")

    def _expand_quantifiers(self, condition: str, namespaces: dict[str, dict[str, bool]]) -> str:
        def expand_wildcard(match: re.Match[str]) -> str:
            quant, namespace = match.group(1), match.group(2)
            refs = [f"{namespace}.{name}" for name in namespaces.get(namespace, {})]
            if not refs:
                return "False" if quant == "any" else "True"
            joiner = " or " if quant == "any" else " and "
            return "(" + joiner.join(refs) + ")"

        def expand_list(match: re.Match[str]) -> str:
            quant = match.group(1)
            items = [item.strip() for item in match.group(2).split(",") if item.strip()]
            if not items:
                return "False" if quant == "any" else "True"
            joiner = " or " if quant == "any" else " and "
            return "(" + joiner.join(items) + ")"

        expr = _WILDCARD_QUANTIFIER_RE.sub(expand_wildcard, condition)
        return _LIST_QUANTIFIER_RE.sub(expand_list, expr)

    def _eval_condition(self, condition: str, namespaces: dict[str, dict[str, bool]]) -> bool:
        expr = self._expand_quantifiers(condition, namespaces)
        signal_values = namespaces.get("signals", {})

        def replace_namespaced(match: re.Match[str]) -> str:
            namespace = match.group(1)
            name = match.group(2)
            table = namespaces.get(namespace, {})
            if name in table:
                return "True" if table[name] else "False"
            if namespace in {"signals", "keywords", "semantics"}:
                raise RuleEngineError(f"Unknown condition token: {namespace}.{name}")
            # LLM/FIDES checks are validated by the schema but are not evaluated by this
            # deterministic engine. It stays false here and is handled downstream.
            return "False"

        expr = _NAMESPACED_REF_RE.sub(replace_namespaced, expr)

        def replace_bare(match: re.Match[str]) -> str:
            token = match.group(0)
            lower = token.lower()
            if lower in {"and", "or", "not", "true", "false"}:
                return lower.title() if lower in {"true", "false"} else lower
            if token not in signal_values:
                raise RuleEngineError(f"Unknown condition token: {token}")
            return "True" if signal_values[token] else "False"

        expr = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", replace_bare, expr)
        if not re.fullmatch(r"[TrueFalsandornt ()]+", expr):
            raise RuleEngineError(f"Unsafe condition expression: {condition}")
        return bool(eval(expr, {"__builtins__": {}}, {}))

    def _final_action(self, hits: list[RuleHit]) -> str:
        if any(hit.action == "block_and_audit" or hit.severity == "critical" for hit in hits):
            return "block"
        if any(hit.action == "quarantine" for hit in hits):
            return "quarantine"
        return "allow"
