from canaryweave_fides.adapters import (
    AdapterConfig,
    AdapterResult,
    AdapterStatus,
    SyntheticAdapter,
)
from canaryweave_fides.cases import AttackCase
from canaryweave_fides.gate import FidesJudgeResult, StaticFidesJudge
from canaryweave_fides.reporting import build_public_report
from canaryweave_fides.runner import EvaluationRunConfig, run_evaluation


class _StaticAdapter(SyntheticAdapter):
    dataset_id = "evidence_fixture"

    def __init__(self, cases):
        super().__init__(AdapterConfig())
        self._cases = tuple(cases)

    def load(self):
        return AdapterResult(
            dataset_id=self.dataset_id,
            status=AdapterStatus.LOADED,
            cases=self._cases,
            message="evidence fixture",
            safe_metadata={"public_safe": True},
        )


def _attack_case(case_id, *, category, surface="mcp_tool", safe_features=None):
    features = {
        "origin_labels": ["user"],
        "trust_labels": ["trusted"],
        "instruction_shape": False,
        "tool_plan_shape": False,
        "requested_tool": "read_task",
        "requested_sink": "local_audit",
        "length": 32,
        "schema_shape": "plain_text",
    }
    features.update(safe_features or {})
    return AttackCase(
        case_id=case_id,
        dataset_id="evidence_fixture",
        split="ci",
        case_kind="attack",
        attack_category=category,
        surface=surface,
        safe_features=features,
        policy_context={
            "allowed_tools": ["read_task"],
            "allowed_sinks": ["local_audit"],
            "trusted_origins": ["user", "host_policy"],
        },
        expected_behavior="block",
    )


def test_public_report_summarizes_security_and_maintainability_metrics():
    raw = run_evaluation(
        EvaluationRunConfig(adapters=(SyntheticAdapter(AdapterConfig()),), iterations=2)
    )

    report = build_public_report(raw)

    assert report["schema_version"] == "canaryweave_fides.public_report.v1"
    assert report["total_iterations"] == raw["total_iterations"]
    assert "asr" in report["security_metrics"]["no_guard"]
    assert "asr_reduction_vs_regex" in report["security_metrics"]["yara_rules"]
    assert report["incremental_metrics"]["warden_incremental_catches_vs_regex"] >= 0
    assert report["incremental_metrics"]["fides_incremental_catches_vs_warden"] >= 0
    assert report["maintainability_metrics"]["rule_engine_codename"] == "WARDEN"
    assert report["safety"]["public_safe"] is True


def test_public_report_does_not_include_case_level_payload_fields():
    raw = run_evaluation(
        EvaluationRunConfig(
            adapters=(SyntheticAdapter(AdapterConfig(max_cases=1)),), iterations=1
        )
    )
    report = build_public_report(raw)
    text = str(report).lower()

    assert "case_results" not in report
    assert "raw_ref" not in text
    assert "private_data" not in text
    assert "payload" not in text


def test_public_report_omits_model_output_and_judge_transcripts_from_private_rows():
    raw = run_evaluation(
        EvaluationRunConfig(
            adapters=(SyntheticAdapter(AdapterConfig(max_cases=1)),), iterations=1
        )
    )
    raw["case_results"][0]["decisions"][0][
        "model_output"
    ] = "PRIVATE_MODEL_OUTPUT_SHOULD_NOT_BE_PUBLIC"
    raw["case_results"][0]["decisions"][0][
        "judge_transcript"
    ] = "PRIVATE_JUDGE_TRANSCRIPT_SHOULD_NOT_BE_PUBLIC"

    report = build_public_report(raw)
    text = str(report)

    assert "PRIVATE_MODEL_OUTPUT_SHOULD_NOT_BE_PUBLIC" not in text
    assert "PRIVATE_JUDGE_TRANSCRIPT_SHOULD_NOT_BE_PUBLIC" not in text
    assert report["safety"]["model_outputs_included"] is False
    assert report["safety"]["judge_transcripts_included"] is False


def test_incremental_metrics_keys_include_case_id_to_avoid_collisions():
    raw = {
        "schema_version": "canaryweave_fides.gate_eval.v1",
        "iterations": 1,
        "total_cases": 2,
        "total_iterations": 2,
        "provider_calls": 0,
        "case_results": [
            {
                "case_id": "case.allowed",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "same_category",
                "surface": "mcp_tool",
                "iteration": 0,
                "decisions": [
                    {"stack": "regex_baseline", "decision": "allow", "rule_ids": []},
                    {"stack": "yara_rules", "decision": "allow", "rule_ids": []},
                    {"stack": "rules_plus_fides", "decision": "allow", "rule_ids": []},
                ],
            },
            {
                "case_id": "case.blocked",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "same_category",
                "surface": "mcp_tool",
                "iteration": 0,
                "decisions": [
                    {
                        "stack": "regex_baseline",
                        "decision": "block",
                        "rule_ids": ["regex.marker"],
                    },
                    {
                        "stack": "yara_rules",
                        "decision": "block",
                        "rule_ids": ["cwfr-0001"],
                    },
                    {
                        "stack": "rules_plus_fides",
                        "decision": "block",
                        "rule_ids": ["cwfr-0001"],
                    },
                ],
            },
        ],
    }

    report = build_public_report(raw)

    assert report["incremental_metrics"]["warden_incremental_catches_vs_regex"] == 0


def test_public_report_includes_disagreement_matrix_without_case_ids():
    raw = {
        "schema_version": "canaryweave_fides.gate_eval.v1",
        "iterations": 1,
        "total_cases": 3,
        "total_iterations": 3,
        "provider_calls": 0,
        "case_results": [
            {
                "case_id": "case.all_allowed",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "category_one",
                "surface": "mcp_tool",
                "iteration": 0,
                "decisions": [
                    {"stack": "regex_baseline", "decision": "allow", "rule_ids": []},
                    {"stack": "yara_rules", "decision": "allow", "rule_ids": []},
                    {"stack": "rules_plus_fides", "decision": "allow", "rule_ids": []},
                ],
            },
            {
                "case_id": "case.warden_catch",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "category_one",
                "surface": "mcp_tool",
                "iteration": 0,
                "decisions": [
                    {"stack": "regex_baseline", "decision": "allow", "rule_ids": []},
                    {
                        "stack": "yara_rules",
                        "decision": "block",
                        "rule_ids": ["cwfr-0001"],
                    },
                    {
                        "stack": "rules_plus_fides",
                        "decision": "block",
                        "rule_ids": ["cwfr-0001"],
                    },
                ],
            },
            {
                "case_id": "case.fides_catch",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "category_two",
                "surface": "api_message",
                "iteration": 0,
                "decisions": [
                    {"stack": "regex_baseline", "decision": "allow", "rule_ids": []},
                    {"stack": "yara_rules", "decision": "allow", "rule_ids": []},
                    {
                        "stack": "rules_plus_fides",
                        "decision": "quarantine",
                        "rule_ids": [],
                        "blocked_by": "fides_judge",
                    },
                ],
            },
        ],
    }

    report = build_public_report(raw)
    matrix = report["disagreement_matrix"]

    assert matrix["stacks"] == ["regex_baseline", "yara_rules", "rules_plus_fides"]
    assert matrix["pairs"]["regex_baseline__yara_rules"]["same_action"] == 2
    assert matrix["pairs"]["regex_baseline__yara_rules"]["different_action"] == 1
    assert (
        matrix["pairs"]["yara_rules__rules_plus_fides"]["different_block_outcome"] == 1
    )
    assert matrix["joint_patterns"]["allow|block|block"] == 1
    assert "case.warden_catch" not in str(matrix)


def test_public_report_includes_rule_coverage_by_dataset_and_category_and_zero_coverage_rules():
    raw = run_evaluation(
        EvaluationRunConfig(adapters=(SyntheticAdapter(AdapterConfig()),), iterations=1)
    )

    report = build_public_report(raw, all_rule_ids={"cwfr-0001", "cwfr-unused"})
    maintainability = report["maintainability_metrics"]

    assert "cwfr-unused" in maintainability["rules_with_no_coverage"]
    assert maintainability["rules_with_no_coverage_count"] == 1
    dataset_coverage = maintainability["rule_coverage_by_dataset"]["synthetic"]
    assert dataset_coverage["covered_rule_count"] >= 1
    assert "cwfr-0001" in dataset_coverage["covered_rule_ids"]
    category_coverage = maintainability["rule_coverage_by_dataset_and_category"][
        "synthetic"
    ]["origin_authority_confusion"]
    assert "cwfr-0001" in category_coverage["covered_rule_ids"]
    assert category_coverage["covered_rule_count"] >= 1


def test_public_report_includes_fides_incremental_rate_latency_and_call_metrics():
    cases = [
        _attack_case("fides.catch.001", category="semantic_miss"),
        _attack_case(
            "warden.catch.001",
            category="structural_catch",
            safe_features={
                "origin_labels": ["server_sampling"],
                "trust_labels": ["untrusted"],
                "instruction_shape": True,
                "tool_plan_shape": True,
                "requested_tool": "admin_action",
                "requested_action": "consequential_update",
                "schema_shape": "tool_plan_like",
            },
        ),
    ]
    raw = run_evaluation(
        EvaluationRunConfig(adapters=(_StaticAdapter(cases),), iterations=1),
        fides_judge=StaticFidesJudge(
            {
                "fides.catch.001": FidesJudgeResult(
                    verdict="unsafe",
                    confidence=0.9,
                    reason_codes=("semantic_policy_violation",),
                    latency_ms=25.0,
                    provider_calls=1,
                )
            }
        ),
    )

    report = build_public_report(raw)
    metrics = report["incremental_metrics"]

    assert metrics["fides_incremental_catches_vs_warden"] == 1
    assert metrics["fides_incremental_catch_rate_vs_warden_misses"] == 1.0
    assert metrics["fides_incremental_catch_rate_vs_all_attacks"] == 0.5
    assert metrics["remaining_miss_rate_after_rules_plus_fides"] == 0.0
    assert metrics["fides_calls"] == 1
    assert metrics["fides_provider_calls"] == 0
    assert metrics["fides_latency_ms"]["avg"] == 25.0


def test_public_report_summarizes_missing_prerequisites_when_case_facts_are_available():
    raw = {
        "schema_version": "canaryweave_fides.gate_eval.v1",
        "iterations": 1,
        "total_cases": 2,
        "total_iterations": 2,
        "provider_calls": 0,
        "case_results": [
            {
                "case_id": "missing.one",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "execution",
                "surface": "api_message",
                "iteration": 0,
                "ground_truth": {
                    "expected_rule_ids": ["cwfr-0106"],
                    "labels": {
                        "required_fields": [
                            "features.command_execution_shape",
                            "requested.capability",
                        ]
                    },
                },
                "safe_features": {"command_execution_shape": True},
                "policy_context": {"allowed_tools": ["read_task"]},
                "decisions": [
                    {"stack": "yara_rules", "decision": "allow", "rule_ids": []},
                    {"stack": "rules_plus_fides", "decision": "allow", "rule_ids": []},
                ],
            },
            {
                "case_id": "missing.two",
                "dataset_id": "synthetic",
                "case_kind": "attack",
                "attack_category": "execution",
                "surface": "api_message",
                "iteration": 0,
                "ground_truth": {
                    "expected_rule_ids": ["cwfr-0106"],
                    "labels": {
                        "required_fields": [
                            "features.command_execution_shape",
                            "requested.capability",
                        ]
                    },
                },
                "safe_features": {},
                "policy_context": {},
                "decisions": [
                    {"stack": "yara_rules", "decision": "allow", "rule_ids": []},
                    {"stack": "rules_plus_fides", "decision": "allow", "rule_ids": []},
                ],
            },
        ],
    }

    report = build_public_report(raw)
    summary = report["missing_prerequisite_summary"]

    assert summary["available"] is True
    assert summary["total_missing_prerequisites"] == 3
    assert summary["by_field"]["requested.capability"] == 2
    assert summary["by_dataset"]["synthetic"] == 3
    assert summary["by_dataset_and_category"]["synthetic"]["execution"] == 3
    assert "missing.one" not in str(summary)
