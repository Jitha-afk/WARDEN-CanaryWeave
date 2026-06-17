import csv
import json

from canaryweave_fides.adapters import ASBAdapter, AdapterConfig, SyntheticAdapter
from canaryweave_fides.runner import EvaluationRunConfig, run_evaluation


def test_runner_repeats_cases_for_configured_iterations():
    adapter = SyntheticAdapter(AdapterConfig(max_cases=1))

    report = run_evaluation(EvaluationRunConfig(adapters=(adapter,), iterations=3))

    assert report["schema_version"] == "canaryweave_fides.gate_eval.v1"
    assert report["iterations"] == 3
    assert report["total_cases"] == 1
    assert report["total_iterations"] == 3
    assert report["provider_calls"] == 0
    assert set(report["defense_stacks"]) == {"no_guard", "regex_baseline", "yara_rules", "rules_plus_fides"}
    assert report["defense_stacks"]["no_guard"]["allow"] == 3
    assert report["defense_stacks"]["yara_rules"]["block"] >= 1
    assert "adapter_results" in report
    assert report["adapter_results"][0]["dataset_id"] == "synthetic"


def test_runner_defaults_to_fifty_iterations():
    adapter = SyntheticAdapter(AdapterConfig(max_cases=1))
    config = EvaluationRunConfig(adapters=(adapter,))

    report = run_evaluation(config)

    assert report["iterations"] == 50
    assert report["total_iterations"] == 50


def test_runner_output_is_public_safe():
    adapter = SyntheticAdapter(AdapterConfig(max_cases=1))
    report = run_evaluation(EvaluationRunConfig(adapters=(adapter,), iterations=1))
    text = str(report).lower()

    assert "raw_ref" not in text
    assert "private_data" not in text


def test_runner_writes_private_reviewer_csv_with_raw_io_and_labels(tmp_path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    record = {
        "Attacker Tool": "opaque local tool name",
        "Attacker Instruction": "policy instruction hierarchy override structure",
        "Description": "structural metadata only",
        "Attack goal": "structural goal label",
        "Attack Type": "Stealthy Attack",
        "Corresponding Agent": "system_admin_agent",
        "Aggressive": "False",
    }
    (dataset / "records.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    output = tmp_path / "private-review" / "review.csv"

    report = run_evaluation(
        EvaluationRunConfig(adapters=(ASBAdapter(AdapterConfig(root=dataset)),), iterations=1),
        private_review_csv=output,
    )

    assert report["private_review_csv"] == str(output)
    rows = list(csv.DictReader(output.open(newline="", encoding="utf-8")))
    assert len(rows) == 4
    row = next(item for item in rows if item["stack"] == "yara_rules")
    assert row["case_id"]
    assert row["dataset_id"] == "asb"
    assert row["case_kind"] == "attack"
    assert row["expected_behavior"] == "block"
    assert row["llm_label"] == "not_called"
    assert row["decision"] in {"allow", "block", "quarantine"}
    assert row["raw_input"] == "opaque local tool name\npolicy instruction hierarchy override structure\nstructural metadata only\nstructural goal label"
    assert "decision" in row["raw_output"]
    assert row["raw_ref"].startswith("asb:file_hmac=")
    assert row["expected_rule_ids"] == "cwfr-0003"
    assert row["rule_ids"]


def test_runner_private_reviewer_csv_neutralizes_spreadsheet_formula_cells(tmp_path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    record = {"payload": "=formula-like reviewer payload", "label": "attack"}
    (dataset / "records.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    output = tmp_path / "private-review" / "review.csv"

    run_evaluation(
        EvaluationRunConfig(adapters=(ASBAdapter(AdapterConfig(root=dataset)),), iterations=1),
        private_review_csv=output,
    )

    rows = list(csv.DictReader(output.open(newline="", encoding="utf-8")))
    assert rows[0]["raw_input"] == "'=formula-like reviewer payload"


def test_runner_rejects_private_reviewer_csv_under_public_artifacts(tmp_path):
    adapter = SyntheticAdapter(AdapterConfig(max_cases=1))
    public_path = "artifacts/review.csv"

    try:
        run_evaluation(EvaluationRunConfig(adapters=(adapter,), iterations=1), private_review_csv=public_path)
    except ValueError as exc:
        assert "private reviewer CSV" in str(exc)
    else:
        raise AssertionError("expected private reviewer CSV path guard to reject public artifact path")
