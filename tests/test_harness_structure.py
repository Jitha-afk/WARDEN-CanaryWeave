from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

MILESTONE_1_FILES = [
    "conf/default.yaml",
    "conf/datasets.yaml",
    "conf/stacks.yaml",
    "data/datasets/README.md",
    "data/datasets/synthetic.yaml",
    "data/datasets/asb.yaml",
    "data/datasets/agentdefensebench.yaml",
    "data/evals/smoke.yaml",
    "data/evals/multi_dataset_gate.yaml",
    "data/prompts/fides_judge.yaml",
    "data/yara/baseline_regex.yaml",
    "data/yara/canaryweave_rules.yaml",
    "docs/thesis.md",
    "docs/rule_authoring.md",
    "docs/datasets.md",
    "docs/fides_judge.md",
    "docs/running_evals.md",
    "scripts/run_smoke.sh",
    "scripts/run_multi_dataset_eval.sh",
    "scripts/check_public_artifacts.py",
]

YAML_FILES = [path for path in MILESTONE_1_FILES if path.endswith((".yaml", ".yml"))]


def test_milestone_1_files_exist():
    missing = [path for path in MILESTONE_1_FILES if not (ROOT / path).exists()]
    assert missing == []


def test_milestone_1_yaml_files_are_loadable_and_versioned():
    for rel in YAML_FILES:
        data = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
        assert isinstance(data, dict), rel
        assert data.get("schema_version") == 1, rel


def test_harness_defaults_keep_private_material_disabled():
    defaults = yaml.safe_load((ROOT / "conf/default.yaml").read_text(encoding="utf-8"))
    safety = defaults["safety"]
    assert safety["raw_payloads_allowed_in_repo"] is False
    assert safety["raw_prompts_allowed_in_repo"] is False
    assert safety["provider_calls_enabled_by_default"] is False


def test_fides_prompt_contract_forbids_raw_inputs():
    prompt = yaml.safe_load((ROOT / "data/prompts/fides_judge.yaml").read_text(encoding="utf-8"))
    safety = prompt["safety"]
    assert safety["allow_raw_payload_text"] is False
    assert safety["allow_raw_prompts"] is False
    assert safety["allow_judge_transcript_public_export"] is False


def test_milestone_1_shell_scripts_are_executable():
    for rel in ["scripts/run_smoke.sh", "scripts/run_multi_dataset_eval.sh"]:
        assert (ROOT / rel).stat().st_mode & 0o111, rel
