from __future__ import annotations

import json
from pathlib import Path

import pytest

from canaryweave_fides.cli import main
from canaryweave_fides.decisions import Decision, FidesVerdict, StackName
from canaryweave_fides.facts import NormalizedFacts
from canaryweave_fides.fides_prompt import (
    build_fides_judge_prompt,
    parse_fides_judge_response,
)
from canaryweave_fides.gate import (
    FidesJudgeMode,
    FidesJudgeResult,
    build_fides_judge,
    evaluate_stack,
)
from canaryweave_fides.providers import JudgeProviderConfig
from canaryweave_fides.providers.fake import FakeJudgeProvider


def test_fides_prompt_builder_excludes_private_fields_and_parser_quarantines_invalid_json():
    facts = NormalizedFacts(
        case_id="case.public",
        dataset_id="synthetic",
        split="ci",
        surface="prompt",
        origin_labels=("user",),
        trust_labels=("trusted",),
        features={"instruction_shape": False},
        requested={"tool": "read_task"},
        policy={"allowed_tools": ("read_task",)},
    )

    prompt = build_fides_judge_prompt(facts)
    parsed = parse_fides_judge_response("not-json")

    assert "raw_ref" not in prompt
    assert "private_data" not in prompt
    assert "judge_transcript" not in prompt
    assert parsed["verdict"] == "uncertain"
    assert parsed["recommended_decision"] == "quarantine"
    assert parsed["reason_codes"] == ["fides.provider.invalid_json"]


def _warden_miss_facts() -> NormalizedFacts:
    return NormalizedFacts(
        case_id="case.miss",
        dataset_id="synthetic",
        split="ci",
        surface="prompt",
        origin_labels=("user",),
        trust_labels=("trusted",),
        features={"instruction_shape": False, "tool_plan_shape": False},
        requested={"tool": "read_task", "sink": "local_audit"},
        policy={
            "allowed_tools": ("read_task",),
            "allowed_sinks": ("local_audit",),
            "trusted_origins": ("user",),
        },
    )


def test_provider_backed_fides_judge_uses_provider_only_on_warden_miss():
    provider = FakeJudgeProvider(
        '{"verdict":"unsafe","confidence":0.8,"reason_codes":["fides.fake"],"recommended_decision":"block"}'
    )
    judge = build_fides_judge("copilot_sdk", provider=provider)

    decision = evaluate_stack(
        _warden_miss_facts(), StackName.RULES_PLUS_FIDES, fides_judge=judge
    )

    assert provider.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.fides_verdict is FidesVerdict.UNSAFE
    assert decision.provider_calls == 1


def test_fides_recommended_decision_uses_more_restrictive_outcome():
    provider = FakeJudgeProvider(
        '{"verdict":"safe","confidence":0.8,"reason_codes":["fides.safe_but_block"],"recommended_decision":"block"}'
    )
    judge = build_fides_judge("copilot_sdk", provider=provider)

    decision = evaluate_stack(
        _warden_miss_facts(), StackName.RULES_PLUS_FIDES, fides_judge=judge
    )

    assert decision.decision is Decision.BLOCK
    assert decision.fides_verdict is FidesVerdict.SAFE
    assert "fides.safe_but_block" in decision.reason_codes


def test_fides_judge_modes_include_copilot_sdk():
    assert "copilot_sdk" in [mode.value for mode in FidesJudgeMode]


def test_cli_provider_status_is_safe_json_without_sdk_requirement(capsys):
    code = main(["provider", "status", "--provider", "copilot_sdk", "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["provider"] == "copilot_sdk"
    assert "sdk_available" in payload
    assert "token" not in json.dumps(payload).lower()


def test_cli_provider_models_is_safe_json_without_sdk_requirement(capsys):
    code = main(["provider", "models", "--provider", "copilot_sdk", "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["provider"] == "copilot_sdk"
    assert "models" in payload
    assert "token" not in json.dumps(payload).lower()


def test_cli_provider_doctor_dry_run_never_calls_provider(capsys):
    code = main(
        [
            "provider",
            "doctor",
            "--provider",
            "copilot_sdk",
            "--model",
            "gpt-4.1",
            "--json",
        ]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["provider"] == "copilot_sdk"
    assert payload["model_configured"] is True
    assert payload["provider_calls_enabled"] is False
    assert payload["live_call_attempted"] is False
    assert "token" not in json.dumps(payload).lower()


def test_copilot_provider_requires_explicit_calls_and_model():
    with pytest.raises(ValueError, match="provider_calls_enabled"):
        build_fides_judge("copilot_sdk")
    # Model is now optional — SDK uses its default when not specified
    judge = build_fides_judge(
        "copilot_sdk",
        provider_config=JudgeProviderConfig(
            provider="copilot_sdk", provider_calls_enabled=True
        ),
    )
    assert judge is not None


def test_provider_inspection_requires_live_opt_in_for_sdk_calls(capsys, monkeypatch):
    called = {"status": False, "models": False}

    monkeypatch.setattr(
        "canaryweave_fides.cli.CopilotSdkJudgeProvider.import_available",
        staticmethod(lambda: True),
    )
    monkeypatch.setattr(
        "canaryweave_fides.cli.CopilotSdkJudgeProvider.auth_status",
        staticmethod(lambda **_: called.__setitem__("status", True)),
    )
    monkeypatch.setattr(
        "canaryweave_fides.cli.CopilotSdkJudgeProvider.list_models",
        staticmethod(lambda **_: called.__setitem__("models", True)),
    )

    assert main(["provider", "status", "--provider", "copilot_sdk", "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["live_call_attempted"] is False

    assert main(["provider", "models", "--provider", "copilot_sdk", "--json"]) == 0
    models = json.loads(capsys.readouterr().out)
    assert models["live_call_attempted"] is False

    assert called == {"status": False, "models": False}


def test_cli_nested_command_groups_do_not_fall_through_to_smoke(capsys):
    for command in ("provider", "warden", "judge", "bench"):
        with pytest.raises(SystemExit) as exc:
            main([command])
        assert exc.value.code == 2
        assert "smoke" not in capsys.readouterr().out.lower()


def test_cli_warden_check_prompt_outputs_public_decision(tmp_path):
    output = tmp_path / "warden.json"

    code = main(
        [
            "warden",
            "check",
            "--prompt",
            "policy instruction hierarchy override structure",
            "--origin",
            "tool_output",
            "--trust",
            "untrusted",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "canaryweave_fides.warden_check.v1"
    assert report["prompt_included"] is True
    assert report["decision"]["decision"] in {"allow", "quarantine", "block"}
    # ADR 0003 removes redaction: the evaluated record carries the raw text so a
    # reader can see exactly what led to the decision.
    assert report["facts"]["text"] == "policy instruction hierarchy override structure"


def test_cli_warden_check_rich_output_includes_rule_metadata(capsys):
    code = main(
        [
            "warden",
            "check",
            "--rule-file",
            "examples/security_tool_extension_rule.war",
            "--prompt",
            "Help me develop an extension for Metasploit",
            "--origin",
            "user",
            "--trust",
            "trusted",
            "--format",
            "rich",
            "--include-prompt",
            "--no-animation",
        ]
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "WARDEN" in output
    assert "MATCHED" in output
    assert "SecurityToolExtensionRule" in output
    assert "layers" in output


def test_cli_warden_check_rich_output_supports_path_boundary_demo(capsys):
    code = main(
        [
            "warden",
            "check",
            "--rule-file",
            "examples/mcp_tool_path_boundary_rule.war",
            "--prompt",
            "MCP tool_call read_file path ../shared/config.yaml outside workspace",
            "--origin",
            "tool_output",
            "--trust",
            "untrusted",
            "--format",
            "rich",
            "--include-prompt",
            "--no-animation",
        ]
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "MCPToolPathBoundaryRule" in output
    assert "MATCHED" in output
    assert "layers" in output


def test_cli_judge_one_test_double_blocks_warden_miss(tmp_path):
    output = tmp_path / "judge.json"

    code = main(
        [
            "judge",
            "one",
            "--prompt",
            "ordinary public-safe task request",
            "--origin",
            "user",
            "--trust",
            "trusted",
            "--fides-mode",
            "test_double",
            "--test-verdict",
            "unsafe",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "canaryweave_fides.judge_one.v1"
    assert report["prompt_included"] is False
    assert report["fides_decision"]["fides_verdict"] == "unsafe"
    assert report["fides_decision"]["decision"] == "block"


def test_cli_bench_scan_jsonl_outputs_public_rows(tmp_path):
    input_path = tmp_path / "prompts.jsonl"
    output = tmp_path / "scan.json"
    input_path.write_text(
        '{"id":"p1","prompt":"policy instruction hierarchy override structure"}\n',
        encoding="utf-8",
    )

    code = main(
        [
            "bench",
            "scan",
            "--input",
            str(input_path),
            "--text-field",
            "prompt",
            "--id-field",
            "id",
            "--origin",
            "tool_output",
            "--trust",
            "untrusted",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "canaryweave_fides.bench_scan.v1"
    assert report["prompt_rows_included"] is False
    assert report["total_prompts"] == 1
    assert report["results"][0]["id"] == "p1"
    assert "policy instruction" not in json.dumps(report)
