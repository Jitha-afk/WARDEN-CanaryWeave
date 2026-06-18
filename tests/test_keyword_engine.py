from pathlib import Path

import pytest

from canaryweave_fides.models import TraceEvent
from canaryweave_fides.rule_engine import RuleEngine
from canaryweave_fides.rule_loader import load_rules, parse_ruleset
from canaryweave_fides.rule_schema import RuleValidationError


ROOT = Path(__file__).resolve().parents[1]


_SIG_TEMPLATE = """rule {name} {{
    meta:
        id          = {rule_id}
        severity    = {severity}
        technique   = T1059 (Execution, direct)
    patterns:
{patterns}
    condition:
        {condition}
}}
"""


def _signature(patterns, condition, *, name="SigRule", rule_id="cwfr-test-0001", severity="high"):
    text = _SIG_TEMPLATE.format(
        name=name, rule_id=rule_id, severity=severity, patterns=patterns, condition=condition
    )
    return parse_ruleset(text)


def _engine(patterns, condition, **kwargs):
    return RuleEngine(list(_signature(patterns, condition, **kwargs)))


def _event(text: str) -> TraceEvent:
    return TraceEvent(event_id="e1", origin="tool_output", surface="content", text=text)


def test_minimal_pattern_only_rule_validates_with_defaults():
    (rule,) = _signature(r"        $secret_path = /\/etc\/shadow/i", "any of patterns")

    assert rule.id == "cwfr-test-0001"
    assert rule.version == "0.1.0"
    assert rule.action == "audit"
    assert rule.patterns[0].type == "regex"


def test_terse_regex_pattern_matches_event_text():
    engine = _engine(r"        $shadow = /\/etc\/(passwd|shadow)/i", "any of patterns")

    assert engine.evaluate([_event("please read /etc/shadow")]).hits
    assert not engine.evaluate([_event("a perfectly benign sentence")]).hits


def test_terse_exact_pattern_is_case_insensitive():
    engine = _engine('        $phrase = "DROP TABLE"', "any of patterns")

    assert engine.evaluate([_event("then we drop table users")]).hits
    assert not engine.evaluate([_event("keep the data")]).hits


def test_all_of_patterns_requires_every_match():
    patterns = "        $a = /alpha/i\n        $b = /bravo/i"
    engine = _engine(patterns, "all of patterns")

    assert engine.evaluate([_event("alpha and bravo present")]).hits
    assert not engine.evaluate([_event("only alpha here")]).hits


def test_list_quantifier_over_explicit_refs():
    patterns = "        $a = /alpha/i\n        $b = /bravo/i\n        $c = /charlie/i"
    engine = _engine(patterns, "any of ($a, $b) or ($a and $c)")

    assert engine.evaluate([_event("bravo only")]).hits
    assert not engine.evaluate([_event("charlie only")]).hits


def test_matched_patterns_recorded_in_evidence():
    engine = _engine("        $first = /needle/i", "any of patterns")

    decision = engine.evaluate([_event("a needle in text")])
    assert decision.hits[0].evidence["matched_patterns"] == ["first"]


def test_wildcard_quantifier_requires_declared_section():
    text = """rule NoPatterns {
    meta:
        id          = cwfr-test-0009
        severity    = low
        technique   = T1059 (Execution, analogical)
    signals:
        $s = event_field_equals(origin, server_sampling)
    condition:
        any of patterns
}
"""
    with pytest.raises(RuleValidationError, match="patterns"):
        parse_ruleset(text)


def test_policy_rule_without_relational_layer_is_rejected():
    text = """rule Empty {
    meta:
        id          = cwfr-test-0002
        severity    = low
        technique   = T1059 (Execution, analogical)
    condition:
        true
}
"""
    with pytest.raises(RuleValidationError, match="at least one"):
        parse_ruleset(text)


def test_ppe_benchmark_corpus_loads():
    rules = load_rules(ROOT / "rules")
    ppe = [rule for rule in rules if rule.id.startswith("cwfr-ppe-")]
    assert len(ppe) == 20
    assert all(rule.patterns for rule in ppe)
    assert all(not (rule.signals or rule.semantics or rule.judge_checks) for rule in ppe)
