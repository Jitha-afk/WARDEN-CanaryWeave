from pathlib import Path

from canaryweave_fides.fides import FidesIFCLayer
from canaryweave_fides.fixtures import smoke_cases
from canaryweave_fides.models import FidesVerdict, QueryResult, RuleDecision
from canaryweave_fides.query_llm import DeterministicQuarantinedModelStub, QueryRequest, query_llm
from canaryweave_fides.rule_engine import RuleEngine
from canaryweave_fides.rule_loader import load_rules


ROOT = Path(__file__).resolve().parents[1]


def _engine():
    return RuleEngine(load_rules(ROOT / "rules"))


def test_query_llm_preflight_block_prevents_model_call():
    case = smoke_cases()["server_sampling_origin_mismatch"]
    model = DeterministicQuarantinedModelStub(output_text="not used")
    result = query_llm(QueryRequest(prompt="benign", trace=case.trace, policy=case.policy), model, _engine())
    assert result.allowed is False
    assert result.model_called is False
    assert result.blocked_by == "deterministic_preflight"


def test_query_llm_postflight_block_blocks_model_output_trace():
    cases = smoke_cases()
    model = DeterministicQuarantinedModelStub(
        output_text="structured response",
        output_trace=cases["canary_boundary_crossing"].trace,
    )
    request = QueryRequest(prompt="summarize", trace=cases["host_authorized_tool_plan"].trace, policy=cases["canary_boundary_crossing"].policy)
    result = query_llm(request, model, _engine())
    assert result.model_called is True
    assert result.allowed is False
    assert result.blocked_by == "deterministic_postflight"


def test_query_llm_fides_blocks_when_rules_allow_but_ifc_policy_fails():
    case = smoke_cases()["fides_only_low_integrity_flow"]
    model = DeterministicQuarantinedModelStub(output_text="structured response", output_trace=case.trace)
    request = QueryRequest(prompt="summarize", trace=smoke_cases()["host_authorized_tool_plan"].trace, policy=case.policy)
    result = query_llm(request, model, _engine(), fides_layer=FidesIFCLayer(enabled=True))
    assert result.model_called is True
    assert result.allowed is False
    assert result.blocked_by == "fides_ifc"


def test_query_result_serialization_includes_model_output_and_judge_transcript():
    private_output = "PRIVATE_MODEL_OUTPUT_SHOULD_NOT_BE_PUBLIC"
    private_transcript = "PRIVATE_JUDGE_TRANSCRIPT_SHOULD_NOT_BE_PUBLIC"
    result = QueryResult(
        allowed=False,
        model_called=True,
        blocked_by="fides_ifc",
        preflight=RuleDecision(hits=(), final_action="allow"),
        postflight=RuleDecision(hits=(), final_action="allow"),
        fides=FidesVerdict(
            verdict="unsafe",
            confidence=0.91,
            blocks=True,
            policy_checks=("trusted_action",),
            rationale_short="public-safe reason code only",
            judge_transcript=private_transcript,
        ),
        output_text=private_output,
    )

    public = result.to_dict()
    assert public["output_text"] == private_output
    assert public["fides"]["judge_transcript"] == private_transcript
