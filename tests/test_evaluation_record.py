"""The flat ``{text, facts}`` evaluation surface (ADR 0003, slice 5).

A rule — and a test case — reasons over exactly an :class:`EvaluationRecord`:
the raw text plus the six frozen facts. The richer trace window is internal
plumbing that *populates* this record, so a case can be literally
``(record, expected)`` with no :class:`TraceEvent` construction.
"""

from canaryweave_fides.models import EvaluationRecord, PolicyContext, TraceEvent
from canaryweave_fides.rule_engine import RuleEngine, build_evaluation_record
from canaryweave_fides.rule_loader import parse_ruleset

_FACT_RULE = """rule UntrustedToolCall {
    meta:
        id          = cwfr-test-0001
        severity    = high
        technique   = T1059 (Execution, direct)
    condition:
        $from_untrusted_origin and $tool_call_shape
}
"""


def _engine() -> RuleEngine:
    return RuleEngine(list(parse_ruleset(_FACT_RULE)))


def test_evaluate_record_fires_from_flat_facts_without_a_trace():
    record = EvaluationRecord(
        text="", facts={"from_untrusted_origin": True, "tool_call_shape": True}
    )

    decision = _engine().evaluate_record(record)

    assert [hit.rule_name for hit in decision.hits] == ["UntrustedToolCall"]
    assert set(decision.hits[0].matched_signals) == {
        "from_untrusted_origin",
        "tool_call_shape",
    }


def test_evaluate_record_allows_when_facts_absent():
    record = EvaluationRecord(
        text="benign note",
        facts={"from_untrusted_origin": False, "tool_call_shape": False},
    )

    decision = _engine().evaluate_record(record)

    assert list(decision.hits) == []


def test_build_evaluation_record_projects_trace_text_and_facts():
    events = (
        TraceEvent(
            event_id="e1",
            origin="tool_output",
            surface="content",
            text="hello",
            schema_shape="tool_plan_like_json",
        ),
    )

    record = build_evaluation_record(events, PolicyContext())

    assert record.text == "hello"
    assert record.fact("from_untrusted_origin") is True
    assert record.fact("tool_call_shape") is True
    assert record.fact("capability_denied") is False


def test_evaluate_and_evaluate_record_agree_on_a_trace():
    events = (
        TraceEvent(
            event_id="e1",
            origin="tool_output",
            surface="content",
            text="hello",
            schema_shape="tool_plan_like_json",
        ),
    )
    engine = _engine()

    via_trace = engine.evaluate(events, PolicyContext())
    via_record = engine.evaluate_record(
        build_evaluation_record(events, PolicyContext())
    )

    assert [hit.rule_name for hit in via_trace.hits] == [
        hit.rule_name for hit in via_record.hits
    ]
