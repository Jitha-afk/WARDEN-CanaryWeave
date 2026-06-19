from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from canaryweave_fides import resources
from canaryweave_fides.cli import run_smoke
from canaryweave_fides.config import load_eval_config
from canaryweave_fides.gate import _default_rule_engine
from canaryweave_fides.reporting import _default_rule_ids
from canaryweave_fides.rule_loader import load_rules


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_RULE_COUNT = 55


def test_source_resource_root_discovers_all_public_rules_and_configs():
    root = resources.resource_root()

    assert root == ROOT
    assert resources.rules_root() == ROOT / "rules"
    assert resources.conf_root() == ROOT / "conf"
    assert resources.data_root() == ROOT / "data"
    assert len(load_rules(resources.rules_root())) == EXPECTED_RULE_COUNT
    assert (resources.conf_root() / "datasets.yaml").is_file()
    assert (resources.data_root() / "evals" / "smoke.yaml").is_file()


def test_missing_or_incomplete_rules_root_fails_loudly(tmp_path):
    missing = tmp_path / "missing-rules"
    with pytest.raises(FileNotFoundError, match="rules root does not exist"):
        resources.validate_rules_root(missing)

    incomplete = tmp_path / "rules"
    incomplete.mkdir()
    with pytest.raises(RuntimeError, match="no .war rulesets"):
        resources.validate_rules_root(incomplete)


def test_default_rule_consumers_use_resource_resolver():
    _default_rule_engine.cache_clear()

    engine = _default_rule_engine()
    rule_ids = {rule.id for rule in engine.rules}

    assert len(engine.rules) == EXPECTED_RULE_COUNT
    assert rule_ids == _default_rule_ids()


def test_cli_and_config_defaults_use_portable_resources(tmp_path):
    smoke_report = run_smoke(tmp_path / "smoke.json")
    loaded = load_eval_config(None)

    assert smoke_report["total_cases"] >= 1
    assert (tmp_path / "smoke.json").is_file()
    assert [adapter.dataset_id for adapter in loaded.adapters] == ["synthetic"]
    assert loaded.default_output == ROOT / "artifacts" / "smoke_report.json"


def test_shell_scripts_use_uv_run_python_instead_of_host_python3():
    for rel in ("scripts/run_smoke.sh", "scripts/run_multi_dataset_eval.sh"):
        script = (ROOT / rel).read_text(encoding="utf-8")
        assert "uv run python" in script, rel
        assert "python3" not in script, rel


def test_root_gitignore_protects_private_reverse_engineering_outputs():
    ignore = (ROOT.parents[1] / ".gitignore").read_text(encoding="utf-8")
    required_patterns = (
        "reverse-engineering/",
        "poc/canaryweave-fides/reverse-engineering/",
        "*.private.csv",
        "*_private.csv",
        "*private-review*.csv",
        "*judge_transcript*",
        "*transcript*.jsonl",
    )
    for pattern in required_patterns:
        assert pattern in ignore


@pytest.mark.skipif(sys.version_info < (3, 11), reason="build frontend dependency is Python 3.11+")
def test_built_wheel_contains_packaged_rules_configs_and_data(tmp_path):
    build_dir = tmp_path / "dist"
    subprocess.run(
        [
            "uv",
            "run",
            "--no-extra",
            "copilot",
            "--with",
            "build",
            "python",
            "-m",
            "build",
            "--wheel",
            "--outdir",
            str(build_dir),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wheel = next(build_dir.glob("*.whl"))

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    packaged_rules = [name for name in names if name.startswith("canaryweave_fides/assets/rules/") and name.endswith(".war")]
    expected_rule_files = len(list((ROOT / "rules").rglob("*.war")))
    assert len(packaged_rules) == expected_rule_files
    assert "canaryweave_fides/assets/conf/default.yaml" in names
    assert "canaryweave_fides/assets/conf/datasets.yaml" in names
    assert "canaryweave_fides/assets/conf/stacks.yaml" in names
    assert "canaryweave_fides/assets/data/evals/smoke.yaml" in names
    assert "canaryweave_fides/assets/data/yara/canaryweave_rules.yaml" in names
