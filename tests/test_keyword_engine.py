from canaryweave_fides.models import TraceEvent
from canaryweave_fides.rule_engine import RuleEngine
from canaryweave_fides.rule_loader import load_rules
from canaryweave_fides.rule_schema import RuleValidationError, validate_rule

import pytest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _engine(rule_dict):
    return RuleEngine([validate_rule(rule_dict)])


def _event(text: str) -> TraceEvent:
    return TraceEvent(event_id="e1", origin="tool_output", surface="content", text=text)


def test_minimal_keyword_only_rule_validates_with_defaults():
    rule = validate_rule({
        "name": "MinimalKeywordRule",
        "severity": "high",
        "keywords": {"secret_path": "/\\/etc\\/shadow/i"},
        "condition": "any of keywords.*",
    })

    assert rule.id == "minimalkeywordrule"
    assert rule.version == "0.1.0"
    assert rule.recommended_action == "audit"
    assert rule.keywords[0].type == "regex"


def test_terse_regex_keyword_matches_event_text():
    engine = _engine({
        "name": "ShadowAccess",
        "severity": "critical",
        "keywords": {"shadow": "/\\/etc\\/(passwd|shadow)/i"},
        "condition": "any of keywords.*",
    })

    assert engine.evaluate([_event("please read /etc/shadow")]).hits
    assert not engine.evaluate([_event("a perfectly benign sentence")]).hits


def test_terse_exact_keyword_is_case_insensitive():
    engine = _engine({
        "name": "ExactMatch",
        "severity": "low",
        "keywords": {"phrase": "DROP TABLE"},
        "condition": "any of keywords.*",
    })

    assert engine.evaluate([_event("then we drop table users")]).hits
    assert not engine.evaluate([_event("keep the data")]).hits


def test_all_of_keywords_requires_every_match():
    rule = {
        "name": "BothTokens",
        "severity": "medium",
        "keywords": {"a": "/alpha/i", "b": "/bravo/i"},
        "condition": "all of keywords.*",
    }
    engine = _engine(rule)

    assert engine.evaluate([_event("alpha and bravo present")]).hits
    assert not engine.evaluate([_event("only alpha here")]).hits


def test_list_quantifier_over_explicit_refs():
    engine = _engine({
        "name": "ListQuantifier",
        "severity": "medium",
        "keywords": {"a": "/alpha/i", "b": "/bravo/i", "c": "/charlie/i"},
        "condition": "any of (keywords.a, keywords.b)",
    })

    assert engine.evaluate([_event("bravo only")]).hits
    assert not engine.evaluate([_event("charlie only")]).hits


def test_matched_keywords_recorded_in_evidence():
    engine = _engine({
        "name": "EvidenceRule",
        "severity": "high",
        "keywords": {"first": "/needle/i"},
        "condition": "any of keywords.*",
    })

    decision = engine.evaluate([_event("a needle in text")])
    assert decision.hits[0].evidence["matched_keywords"] == ["first"]


def test_wildcard_quantifier_requires_declared_section():
    with pytest.raises(RuleValidationError, match="keywords"):
        validate_rule({
            "name": "NoKeywords",
            "severity": "low",
            "signals": [{"name": "s", "type": "event_field_equals", "field": "origin", "value": "x"}],
            "condition": "any of keywords.*",
        })


def test_rule_without_any_detection_section_is_rejected():
    with pytest.raises(RuleValidationError, match="detection section"):
        validate_rule({"name": "Empty", "severity": "low", "condition": "true"})


def test_ppe_benchmark_corpus_loads():
    rules = load_rules(ROOT / "rules")
    ppe = [rule for rule in rules if rule.id.startswith("cwfr-ppe-")]
    assert len(ppe) == 20
    assert all(rule.keywords for rule in ppe)
