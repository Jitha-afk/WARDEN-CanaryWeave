from __future__ import annotations

import csv
import json

from canaryweave_fides.cli import main
from canaryweave_fides.config import load_eval_config


def test_load_eval_config_builds_adapters_and_reports_optional_skips():
    loaded = load_eval_config("data/evals/multi_dataset_gate.yaml")

    assert [adapter.dataset_id for adapter in loaded.adapters] == ["synthetic", "asb", "agentdefensebench"]
    assert loaded.iterations == 50
    assert [stack.value for stack in loaded.stacks] == ["no_guard", "regex_baseline", "yara_rules", "rules_plus_fides"]

    statuses = {adapter.dataset_id: adapter.load().status.value for adapter in loaded.adapters}
    assert statuses["synthetic"] == "loaded"
    assert statuses["asb"] == "skipped_missing_local_path"
    assert statuses["agentdefensebench"] == "skipped_missing_local_path"


def test_cli_eval_uses_config_and_can_skip_missing_optional_datasets(tmp_path, capsys):
    output = tmp_path / "configured-eval.json"

    code = main([
        "eval",
        "--config",
        "data/evals/multi_dataset_gate.yaml",
        "--iterations",
        "1",
        "--output",
        str(output),
    ])

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    statuses = {result["dataset_id"]: result["status"] for result in report["adapter_results"]}
    assert statuses["synthetic"] == "loaded"
    assert statuses["asb"] == "skipped_missing_local_path"
    assert statuses["agentdefensebench"] == "skipped_missing_local_path"
    assert report["total_cases"] >= 1
    assert "skipped_missing_local_path" in capsys.readouterr().out


def test_cli_eval_can_fail_on_missing_optional_dataset(tmp_path):
    output = tmp_path / "configured-eval.json"

    code = main([
        "eval",
        "--config",
        "data/evals/multi_dataset_gate.yaml",
        "--iterations",
        "1",
        "--output",
        str(output),
        "--fail-on-missing-optional-dataset",
    ])

    assert code == 2
    assert not output.exists()


def test_cli_eval_iterations_override_works_when_invoked_as_script(tmp_path, monkeypatch):
    output = tmp_path / "configured-eval.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "canaryweave-fides",
            "eval",
            "--config",
            "data/evals/fides_test_double_gate.yaml",
            "--iterations",
            "2",
            "--output",
            str(output),
        ],
    )

    code = main()

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["iterations"] == 2
    assert report["total_iterations"] == report["total_cases"] * 2


def test_cli_eval_iterations_equals_form_overrides_config(tmp_path, monkeypatch):
    output = tmp_path / "configured-eval.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "canaryweave-fides",
            "eval",
            "--config",
            "data/evals/fides_test_double_gate.yaml",
            "--iterations=2",
            "--output",
            str(output),
        ],
    )

    code = main()

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["iterations"] == 2
    assert report["total_iterations"] == report["total_cases"] * 2


def test_cli_eval_writes_private_review_csv(tmp_path):
    output = tmp_path / "configured-eval.json"
    review_csv = tmp_path / "controlled-private-review" / "review.csv"

    code = main([
        "eval",
        "--config",
        "data/evals/fides_test_double_gate.yaml",
        "--iterations",
        "1",
        "--output",
        str(output),
        "--private-review-csv",
        str(review_csv),
    ])

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert "private_review_csv" not in report
    assert review_csv.exists()
    rows = list(csv.DictReader(review_csv.open(newline="", encoding="utf-8")))
    assert len(rows) == report["total_iterations"] * len(report["security_metrics"])
    assert {"raw_input", "raw_output", "llm_label", "decision", "stack"} <= set(rows[0])
