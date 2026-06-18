from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .adapters import AdapterConfig, DatasetAdapter, SyntheticAdapter
from .cases import AttackCase, GroundTruth, _public_safe
from .decisions import Decision, GateDecision, StackName
from .gate import FidesJudge, FidesJudgeMode, StaticFidesJudge, build_fides_judge, build_test_double_evidence_results, evaluate_case
from .rule_engine import RuleEngine


@dataclass(frozen=True)
class EvaluationRunConfig:
    adapters: tuple[DatasetAdapter, ...] = ()
    iterations: int = 50
    fides_mode: FidesJudgeMode | str = FidesJudgeMode.DISABLED
    fides_test_double_evidence_rules: tuple[Mapping[str, Any], ...] = ()
    stacks: tuple[StackName | str, ...] = (
        StackName.NO_GUARD,
        StackName.REGEX_BASELINE,
        StackName.YARA_RULES,
        StackName.RULES_PLUS_FIDES,
    )

    def __post_init__(self) -> None:
        adapters = tuple(self.adapters) if self.adapters else (SyntheticAdapter(AdapterConfig()),)
        object.__setattr__(self, "adapters", adapters)
        object.__setattr__(self, "iterations", int(self.iterations))
        object.__setattr__(self, "fides_mode", FidesJudgeMode.coerce(self.fides_mode))
        object.__setattr__(self, "fides_test_double_evidence_rules", tuple(dict(rule) for rule in self.fides_test_double_evidence_rules))
        object.__setattr__(self, "stacks", tuple(StackName.coerce(stack) for stack in self.stacks))
        if self.iterations < 1:
            raise ValueError("iterations must be >= 1")


def _with_iteration(case: AttackCase, iteration: int) -> AttackCase:
    return AttackCase(
        case_id=case.case_id,
        dataset_id=case.dataset_id,
        split=case.split,
        case_kind=case.case_kind,
        attack_category=case.attack_category,
        surface=case.surface,
        safe_features=case.safe_features,
        policy_context=case.policy_context,
        expected_behavior=case.expected_behavior,
        ground_truth=case.ground_truth,
        iteration_seed=iteration,
        raw_ref=case.raw_ref,
        private_data=case.private_data,
    )


def _empty_stack_counts(stacks: Sequence[StackName]) -> dict[str, dict[str, int]]:
    return {stack.value: {"allow": 0, "quarantine": 0, "block": 0} for stack in stacks}


def _summarize_decisions(decisions: Iterable[GateDecision]) -> dict[str, object]:
    decision_list = tuple(decisions)
    return {
        "decisions": [decision.to_dict() for decision in decision_list],
        "provider_calls": sum(decision.provider_calls for decision in decision_list),
    }


_PRIVATE_REVIEW_COLUMNS = (
    "case_id",
    "dataset_id",
    "split",
    "iteration",
    "stack",
    "case_kind",
    "expected_behavior",
    "attack_category",
    "surface",
    "decision",
    "blocked_by",
    "rule_ids",
    "reason_codes",
    "fides_verdict",
    "llm_label",
    "provider_calls",
    "raw_ref",
    "raw_input",
    "raw_output",
    "expected_rule_ids",
    "required_fields",
)


def _join_public_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Iterable):
        return ";".join(str(item) for item in value)
    return str(value)


def _private_review_rows(case: AttackCase, iteration: int, decisions: Sequence[GateDecision]) -> list[dict[str, object]]:
    ground_truth = case.ground_truth if isinstance(case.ground_truth, GroundTruth) else None
    labels = dict(ground_truth.labels) if ground_truth is not None else {}
    required_fields = labels.get("required_fields") or ()
    expected_rule_ids = ground_truth.expected_rule_ids if ground_truth is not None else ()
    raw_input = str(case.private_data.get("raw_input") or "")
    rows: list[dict[str, object]] = []
    for decision in decisions:
        raw_output = {
            "decision": decision.decision.value,
            "blocked_by": decision.blocked_by.value,
            "rule_ids": list(decision.rule_ids),
            "reason_codes": list(decision.reason_codes),
            "fides_verdict": decision.fides_verdict.value,
            "provider_calls": decision.provider_calls,
        }
        rows.append(
            {
                "case_id": case.case_id,
                "dataset_id": case.dataset_id,
                "split": case.split,
                "iteration": iteration,
                "stack": decision.stack.value,
                "case_kind": case.case_kind.value,
                "expected_behavior": case.expected_behavior.value,
                "attack_category": case.attack_category,
                "surface": case.surface,
                "decision": decision.decision.value,
                "blocked_by": decision.blocked_by.value,
                "rule_ids": _join_public_list(decision.rule_ids),
                "reason_codes": _join_public_list(decision.reason_codes),
                "fides_verdict": decision.fides_verdict.value,
                "llm_label": decision.fides_verdict.value,
                "provider_calls": decision.provider_calls,
                "raw_ref": case.raw_ref or "",
                "raw_input": raw_input,
                "raw_output": json.dumps(raw_output, sort_keys=True),
                "expected_rule_ids": _join_public_list(expected_rule_ids),
                "required_fields": _join_public_list(required_fields),
            }
        )
    return rows


_PUBLIC_REVIEW_FORBIDDEN_ROOTS = {"artifacts", "conf", "data", "design", "docs", "research", "rules", "scripts", "src", "tests"}


def _neutralize_csv_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return value


def _validate_private_review_csv_path(path: Path) -> None:
    if not path.is_absolute() and path.parts and path.parts[0] in _PUBLIC_REVIEW_FORBIDDEN_ROOTS:
        raise ValueError("private reviewer CSV must be written to a controlled, non-public path")
    repo_root = Path(__file__).resolve().parents[2]
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path.absolute()
    for public_root in _PUBLIC_REVIEW_FORBIDDEN_ROOTS:
        try:
            resolved.relative_to(repo_root / public_root)
        except ValueError:
            continue
        raise ValueError("private reviewer CSV must be written to a controlled, non-public path")


def _write_private_review_csv(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    _validate_private_review_csv_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_PRIVATE_REVIEW_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _neutralize_csv_cell(value) for key, value in row.items()})


def run_evaluation(
    config: EvaluationRunConfig | None = None,
    fides_judge: FidesJudge | None = None,
    rule_engine: RuleEngine | None = None,
    private_review_csv: Path | str | None = None,
) -> dict[str, object]:
    config = config or EvaluationRunConfig()
    stacks = tuple(StackName.coerce(stack) for stack in config.stacks)
    adapter_results = [adapter.load() for adapter in config.adapters]
    cases: list[AttackCase] = []
    for result in adapter_results:
        cases.extend(result.cases)

    test_double_results = {}
    if config.fides_mode == FidesJudgeMode.TEST_DOUBLE and config.fides_test_double_evidence_rules:
        test_double_results = build_test_double_evidence_results(cases, config.fides_test_double_evidence_rules)
    if fides_judge is not None:
        judge = fides_judge
    elif test_double_results:
        judge = StaticFidesJudge(test_double_results)
    else:
        judge = build_fides_judge(config.fides_mode)

    stack_counts = _empty_stack_counts(stacks)
    per_case_results: list[dict[str, object]] = []
    private_review_rows: list[dict[str, object]] = []
    provider_calls = 0

    for case in cases:
        for iteration in range(config.iterations):
            iteration_case = _with_iteration(case, iteration)
            decisions = evaluate_case(iteration_case, stacks=stacks, fides_judge=judge, rule_engine=rule_engine)
            summary = _summarize_decisions(decisions)
            provider_calls += int(summary["provider_calls"])
            for decision in decisions:
                stack_counts[decision.stack.value][decision.decision.value] += 1
            if private_review_csv is not None:
                private_review_rows.extend(_private_review_rows(iteration_case, iteration, decisions))
            per_case_results.append(
                {
                    "case_id": iteration_case.case_id,
                    "dataset_id": iteration_case.dataset_id,
                    "split": iteration_case.split,
                    "case_kind": iteration_case.case_kind.value,
                    "attack_category": iteration_case.attack_category,
                    "surface": iteration_case.surface,
                    "iteration": iteration,
                    "safe_features": _public_safe(iteration_case.safe_features),
                    "policy_context": _public_safe(iteration_case.policy_context),
                    "ground_truth": (
                        iteration_case.ground_truth.to_dict()
                        if isinstance(iteration_case.ground_truth, GroundTruth)
                        else _public_safe(iteration_case.ground_truth or {})
                    ),
                    **summary,
                }
            )

    total_iterations = len(cases) * config.iterations
    if private_review_csv is not None:
        _write_private_review_csv(Path(private_review_csv), private_review_rows)

    report = {
        "schema_version": "canaryweave_fides.gate_eval.v1",
        "iterations": config.iterations,
        "total_cases": len(cases),
        "total_iterations": total_iterations,
        "fides_mode": FidesJudgeMode.coerce(config.fides_mode).value,
        "fides_test_double": {
            "enabled": config.fides_mode == FidesJudgeMode.TEST_DOUBLE,
            "evidence_rules_configured": len(config.fides_test_double_evidence_rules),
            "fixture_verdicts_configured": len(test_double_results),
            "provider_calls_enabled": False,
            "judge_transcripts_included": True,
            "label": "FIDES TEST DOUBLE EVIDENCE MODE" if config.fides_mode == FidesJudgeMode.TEST_DOUBLE else "FIDES DISABLED",
        },
        "defense_stacks": stack_counts,
        "adapter_results": [result.to_dict() for result in adapter_results],
        "case_results": per_case_results,
        "provider_calls": provider_calls,
        "safety_boundary": "raw prompt/tool text and judge transcripts are included when available",
    }
    if private_review_csv is not None:
        report["private_review_csv"] = str(private_review_csv)
        report["private_review_csv_rows"] = len(private_review_rows)
    return report
