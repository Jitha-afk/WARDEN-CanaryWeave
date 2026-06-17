from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from .adapters import AdapterConfig, DatasetAdapter, create_adapter
from .decisions import StackName
from .gate import FidesJudgeMode
from .resources import conf_root, resource_root


@dataclass(frozen=True)
class LoadedEvalConfig:
    adapters: tuple[DatasetAdapter, ...]
    iterations: int
    stacks: tuple[StackName, ...]
    fides_mode: FidesJudgeMode = FidesJudgeMode.DISABLED
    fides_test_double_evidence_rules: tuple[Mapping[str, Any], ...] = ()
    public_report: bool | None = None
    default_output: Path | None = None


def _read_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ValueError(f"config file must contain a mapping: {path}")
    return dict(data)


def _repo_root() -> Path:
    return resource_root()


def _resolve_path(value: Any, *, base: Path) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(str(value))
    return path if path.is_absolute() else base / path


def _dataset_catalog(path: Path | None, *, base: Path) -> dict[str, Mapping[str, Any]]:
    if path is None:
        path = conf_root() / "datasets.yaml"
    data = _read_yaml(path)
    datasets = data.get("datasets", {})
    if not isinstance(datasets, Mapping):
        raise ValueError("datasets config must contain a mapping at 'datasets'")
    return {str(dataset_id): dict(config or {}) for dataset_id, config in datasets.items()}


def _stack_order(path: Path | None, *, base: Path) -> tuple[StackName, ...]:
    if path is None:
        path = conf_root() / "stacks.yaml"
    data = _read_yaml(path)
    values = data.get("stack_order", ())
    if not isinstance(values, list):
        raise ValueError("stacks config must contain a list at 'stack_order'")
    return tuple(StackName.coerce(value) for value in values)


def _max_cases_from_sample(sample: Any) -> int | None:
    if sample is None or sample == "all" or sample == "configured_private_manifest":
        return None
    if isinstance(sample, int):
        return int(sample)
    if isinstance(sample, Mapping) and "max_cases" in sample:
        return int(sample["max_cases"])
    return None


def _adapter_for_dataset(dataset_entry: Mapping[str, Any], catalog: Mapping[str, Mapping[str, Any]], *, base: Path) -> DatasetAdapter:
    dataset_id = str(dataset_entry.get("dataset_id") or dataset_entry.get("id") or dataset_entry.get("name") or "")
    if not dataset_id:
        raise ValueError("dataset entry missing dataset_id")
    catalog_entry = dict(catalog.get(dataset_id, {}))
    adapter_name = str(dataset_entry.get("adapter") or catalog_entry.get("adapter") or dataset_id)
    root_value = dataset_entry.get("root") or dataset_entry.get("path") or dataset_entry.get("local_path")
    if root_value is None:
        root_value = catalog_entry.get("root") or catalog_entry.get("path") or catalog_entry.get("local_path")
    root = _resolve_path(root_value, base=base)
    max_cases = dataset_entry.get("max_cases")
    if max_cases is None:
        max_cases = catalog_entry.get("max_cases")
    if max_cases is None:
        max_cases = _max_cases_from_sample(dataset_entry.get("sample"))
    config = AdapterConfig(
        root=root,
        split=dataset_entry.get("split") or catalog_entry.get("split"),
        # Eval specs are allowed to select optional datasets even when the
        # catalog keeps them disabled by default for CI. If an eval lists a
        # dataset, attempt to load it unless that eval entry explicitly sets
        # enabled: false; missing optional roots are reported as explicit skips.
        enabled=bool(dataset_entry.get("enabled", True)),
        required=bool(dataset_entry.get("required", catalog_entry.get("required", False))),
        max_cases=max_cases,
        options={
            "dataset_id": dataset_id,
            "absent_behavior": dataset_entry.get("missing_status") or catalog_entry.get("absent_behavior"),
            "public_safe": dataset_entry.get("public_safe", catalog_entry.get("public_safe")),
        },
    )
    return create_adapter(adapter_name, config)


def load_eval_config(
    eval_config: Path | str | None,
    *,
    datasets_config: Path | str | None = None,
    stacks_config: Path | str | None = None,
    base_dir: Path | str | None = None,
) -> LoadedEvalConfig:
    base = Path(base_dir) if base_dir is not None else _repo_root()
    eval_path = _resolve_path(eval_config or "data/evals/smoke.yaml", base=base)
    if eval_path is None:
        raise ValueError("eval_config is required")
    data = _read_yaml(eval_path)
    catalog = _dataset_catalog(_resolve_path(datasets_config, base=base), base=base)
    adapters = tuple(_adapter_for_dataset(entry, catalog, base=base) for entry in data.get("datasets", ()))
    configured_stacks = tuple(StackName.coerce(stack) for stack in data.get("stacks", ()))
    if not configured_stacks:
        configured_stacks = _stack_order(_resolve_path(stacks_config, base=base), base=base)
    runner = data.get("runner", {}) or {}
    outputs = data.get("outputs", {}) or {}
    if not isinstance(runner, Mapping) or not isinstance(outputs, Mapping):
        raise ValueError("eval config runner/outputs sections must be mappings")
    return LoadedEvalConfig(
        adapters=adapters,
        iterations=int(runner.get("iterations", 50)),
        stacks=configured_stacks,
        fides_mode=FidesJudgeMode.coerce(runner.get("fides_mode", FidesJudgeMode.DISABLED)),
        fides_test_double_evidence_rules=tuple(
            dict(rule) for rule in runner.get("fides_test_double_evidence_rules", ())
        ),
        public_report=(outputs.get("include_case_level_rows") is False),
        default_output=_resolve_path(outputs.get("default_report"), base=base),
    )
