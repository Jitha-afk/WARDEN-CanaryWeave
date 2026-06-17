from __future__ import annotations

import json

from canaryweave_fides.cli import main
from canaryweave_fides.config import load_eval_config
from canaryweave_fides.gate import FidesJudgeMode


def test_load_eval_config_supports_fides_test_double_rules():
    loaded = load_eval_config("data/evals/fides_test_double_gate.yaml")

    assert loaded.fides_mode is FidesJudgeMode.TEST_DOUBLE
    assert loaded.public_report is True
    assert loaded.fides_test_double_evidence_rules
    rule = loaded.fides_test_double_evidence_rules[0]
    assert rule["verdict"] == "unsafe"
    assert rule["provider_calls"] == 0


def test_cli_eval_fides_test_double_produces_incremental_catches(tmp_path):
    output = tmp_path / "fides-report.json"

    code = main([
        "eval",
        "--config",
        "data/evals/fides_test_double_gate.yaml",
        "--iterations",
        "1",
        "--output",
        str(output),
    ])

    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "canaryweave_fides.public_report.v1"
    assert report["incremental_metrics"]["fides_incremental_catches_vs_warden"] > 0
    assert report["incremental_metrics"]["fides_provider_calls"] == 0
    assert report["safety"]["judge_transcripts_included"] is False
