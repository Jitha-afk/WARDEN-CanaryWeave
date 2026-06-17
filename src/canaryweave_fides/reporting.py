from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations
from statistics import mean
from typing import Any, Iterable, Mapping


_STACKS = ("no_guard", "regex_baseline", "yara_rules", "rules_plus_fides")
_DIAGNOSTIC_STACKS = ("regex_baseline", "yara_rules", "rules_plus_fides")
_BLOCKING_DECISIONS = {"block", "quarantine"}
_NOT_CALLED_FIDES_VERDICTS = {None, "", "not_called"}


def _decision_rows(run_report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_result in run_report.get("case_results", []):
        if not isinstance(case_result, Mapping):
            continue
        base = {
            "case_id": case_result.get("case_id"),
            "dataset_id": case_result.get("dataset_id"),
            "case_kind": case_result.get("case_kind"),
            "attack_category": case_result.get("attack_category"),
            "surface": case_result.get("surface"),
            "iteration": case_result.get("iteration"),
        }
        for decision in case_result.get("decisions", []):
            if isinstance(decision, Mapping):
                rows.append({**base, **dict(decision)})
    return rows


def _security_metrics_for_stack(rows: list[dict[str, Any]], stack: str) -> dict[str, float | int]:
    stack_rows = [row for row in rows if row.get("stack") == stack]
    attacks = [row for row in stack_rows if row.get("case_kind") == "attack"]
    benign = [row for row in stack_rows if row.get("case_kind") == "benign"]
    tp = sum(1 for row in attacks if row.get("decision") in _BLOCKING_DECISIONS)
    fn = len(attacks) - tp
    fp = sum(1 for row in benign if row.get("decision") in _BLOCKING_DECISIONS)
    tn = len(benign) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    asr = fn / len(attacks) if attacks else 0.0
    benign_refusal_rate = fp / len(benign) if benign else 0.0
    safe_pass_through_rate = tn / len(benign) if benign else 0.0
    return {
        "attack_cases": len(attacks),
        "benign_cases": len(benign),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "asr": round(asr, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "benign_refusal_rate": round(benign_refusal_rate, 4),
        "safe_pass_through_rate": round(safe_pass_through_rate, 4),
    }


def _case_key(row: Mapping[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (row.get("dataset_id"), row.get("case_id"), row.get("iteration"), row.get("attack_category"))


def _blocked_case_keys(rows: list[dict[str, Any]], stack: str, attack_only: bool = False) -> set[tuple[Any, Any, Any, Any]]:
    keys: set[tuple[Any, Any, Any, Any]] = set()
    for row in rows:
        if row.get("stack") != stack:
            continue
        if attack_only and row.get("case_kind") != "attack":
            continue
        if row.get("decision") in _BLOCKING_DECISIONS:
            keys.add(_case_key(row))
    return keys


def _allowed_attack_keys(rows: list[dict[str, Any]], stack: str) -> set[tuple[Any, Any, Any, Any]]:
    keys: set[tuple[Any, Any, Any, Any]] = set()
    for row in rows:
        if row.get("stack") == stack and row.get("case_kind") == "attack" and row.get("decision") == "allow":
            keys.add(_case_key(row))
    return keys


def _attack_keys(rows: list[dict[str, Any]], stack: str) -> set[tuple[Any, Any, Any, Any]]:
    return {_case_key(row) for row in rows if row.get("stack") == stack and row.get("case_kind") == "attack"}


def _group_counts(rows: list[dict[str, Any]], field: str) -> dict[str, dict[str, int]]:
    grouped: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked_or_quarantined": 0})
    for row in rows:
        if row.get("stack") != "rules_plus_fides":
            continue
        key = str(row.get(field) or "unknown")
        grouped[key]["total"] += 1
        if row.get("decision") in _BLOCKING_DECISIONS:
            grouped[key]["blocked_or_quarantined"] += 1
    return dict(grouped)


def _default_rule_ids() -> set[str]:
    from .resources import rules_root
    from .rule_loader import load_rules

    return {rule.id for rule in load_rules(rules_root())}


def _sorted_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in sorted(value)}


def _coverage_entry(rule_ids: set[str], hit_count: int, all_rule_ids: set[str]) -> dict[str, Any]:
    total = len(all_rule_ids)
    return {
        "covered_rule_ids": sorted(rule_ids),
        "covered_rule_count": len(rule_ids),
        "total_rule_count": total,
        "coverage_ratio": round(len(rule_ids) / total, 4) if total else 0.0,
        "hit_count": hit_count,
    }


def _rule_coverage(rows: list[dict[str, Any]], all_rule_ids: set[str]) -> dict[str, Any]:
    covered_rule_ids: set[str] = set()
    by_dataset: dict[str, set[str]] = defaultdict(set)
    by_category: dict[str, set[str]] = defaultdict(set)
    by_surface: dict[str, set[str]] = defaultdict(set)
    by_dataset_category: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    by_dataset_hits: Counter[str] = Counter()
    by_category_hits: Counter[str] = Counter()
    by_surface_hits: Counter[str] = Counter()
    by_dataset_category_hits: dict[str, Counter[str]] = defaultdict(Counter)
    observed_hits: set[tuple[Any, Any, Any, str]] = set()

    for row in rows:
        if row.get("stack") not in {"yara_rules", "rules_plus_fides"}:
            continue
        dataset = str(row.get("dataset_id") or "unknown")
        category = str(row.get("attack_category") or "unknown")
        surface = str(row.get("surface") or "unknown")
        for rule_id in row.get("rule_ids", []) or []:
            rule_id = str(rule_id)
            if not rule_id.startswith("cwfr-"):
                continue
            covered_rule_ids.add(rule_id)
            by_dataset[dataset].add(rule_id)
            by_category[category].add(rule_id)
            by_surface[surface].add(rule_id)
            by_dataset_category[dataset][category].add(rule_id)
            hit_key = (*_case_key(row)[:3], rule_id)
            if hit_key in observed_hits:
                continue
            observed_hits.add(hit_key)
            by_dataset_hits[dataset] += 1
            by_category_hits[category] += 1
            by_surface_hits[surface] += 1
            by_dataset_category_hits[dataset][category] += 1

    total_rule_ids = set(all_rule_ids) | covered_rule_ids
    return {
        "unique_rule_ids": sorted(covered_rule_ids),
        "covered_rule_count": len(covered_rule_ids),
        "total_rule_count": len(total_rule_ids),
        "rules_with_no_coverage": sorted(total_rule_ids - covered_rule_ids),
        "rules_with_no_coverage_count": len(total_rule_ids - covered_rule_ids),
        "dataset_rule_coverage": {dataset: sorted(ids) for dataset, ids in sorted(by_dataset.items())},
        "rule_coverage_by_dataset": _sorted_dict(
            {
                dataset: _coverage_entry(ids, by_dataset_hits[dataset], total_rule_ids)
                for dataset, ids in by_dataset.items()
            }
        ),
        "rule_coverage_by_category": _sorted_dict(
            {
                category: _coverage_entry(ids, by_category_hits[category], total_rule_ids)
                for category, ids in by_category.items()
            }
        ),
        "rule_coverage_by_surface": _sorted_dict(
            {
                surface: _coverage_entry(ids, by_surface_hits[surface], total_rule_ids)
                for surface, ids in by_surface.items()
            }
        ),
        "rule_coverage_by_dataset_and_category": _sorted_dict(
            {
                dataset: _sorted_dict(
                    {
                        category: _coverage_entry(ids, by_dataset_category_hits[dataset][category], total_rule_ids)
                        for category, ids in categories.items()
                    }
                )
                for dataset, categories in by_dataset_category.items()
            }
        ),
    }


def _decision_is_blocking(decision: Any) -> bool:
    return str(decision) in _BLOCKING_DECISIONS


def _decisions_by_case(rows: list[dict[str, Any]], stacks: Iterable[str]) -> dict[tuple[Any, Any, Any, Any], dict[str, str]]:
    wanted = set(stacks)
    by_case: dict[tuple[Any, Any, Any, Any], dict[str, str]] = defaultdict(dict)
    for row in rows:
        stack = str(row.get("stack") or "")
        if stack in wanted:
            by_case[_case_key(row)][stack] = str(row.get("decision") or "unknown")
    return by_case


def _disagreement_matrix(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_case = _decisions_by_case(rows, _DIAGNOSTIC_STACKS)
    pairs: dict[str, dict[str, int]] = {}
    for left, right in combinations(_DIAGNOSTIC_STACKS, 2):
        counts = {
            "total_compared": 0,
            "same_action": 0,
            "different_action": 0,
            "same_block_outcome": 0,
            "different_block_outcome": 0,
            "left_blocks_right_allows": 0,
            "left_allows_right_blocks": 0,
        }
        for decisions in by_case.values():
            if left not in decisions or right not in decisions:
                continue
            left_decision = decisions[left]
            right_decision = decisions[right]
            left_blocks = _decision_is_blocking(left_decision)
            right_blocks = _decision_is_blocking(right_decision)
            counts["total_compared"] += 1
            if left_decision == right_decision:
                counts["same_action"] += 1
            else:
                counts["different_action"] += 1
            if left_blocks == right_blocks:
                counts["same_block_outcome"] += 1
            else:
                counts["different_block_outcome"] += 1
            if left_blocks and not right_blocks:
                counts["left_blocks_right_allows"] += 1
            if not left_blocks and right_blocks:
                counts["left_allows_right_blocks"] += 1
        pairs[f"{left}__{right}"] = counts

    joint_patterns: Counter[str] = Counter()
    for decisions in by_case.values():
        if all(stack in decisions for stack in _DIAGNOSTIC_STACKS):
            joint_patterns["|".join(decisions[stack] for stack in _DIAGNOSTIC_STACKS)] += 1

    return {
        "stacks": list(_DIAGNOSTIC_STACKS),
        "pairs": pairs,
        "joint_patterns": dict(sorted(joint_patterns.items())),
        "case_level_rows_included": False,
    }


def _latency_summary(latencies: list[float]) -> dict[str, float | int | None]:
    if not latencies:
        return {"count": 0, "avg": None, "min": None, "max": None}
    return {
        "count": len(latencies),
        "avg": round(mean(latencies), 4),
        "min": round(min(latencies), 4),
        "max": round(max(latencies), 4),
    }


def _incremental_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    regex_allowed_attacks = _allowed_attack_keys(rows, "regex_baseline")
    warden_blocked_attacks = _blocked_case_keys(rows, "yara_rules", attack_only=True)
    warden_allowed_attacks = _allowed_attack_keys(rows, "yara_rules")
    fides_blocked_attacks = _blocked_case_keys(rows, "rules_plus_fides", attack_only=True)
    fides_allowed_attacks = _allowed_attack_keys(rows, "rules_plus_fides")
    attack_keys = _attack_keys(rows, "rules_plus_fides") or _attack_keys(rows, "yara_rules") or _attack_keys(rows, "regex_baseline")

    warden_incremental = len(regex_allowed_attacks & warden_blocked_attacks)
    fides_incremental = len(warden_allowed_attacks & fides_blocked_attacks)
    fides_rows = [row for row in rows if row.get("stack") == "rules_plus_fides"]
    fides_called_rows = [row for row in fides_rows if row.get("fides_verdict") not in _NOT_CALLED_FIDES_VERDICTS]
    provider_calls = sum(int(row.get("provider_calls") or 0) for row in fides_rows)
    latencies = [float(row["latency_ms"]) for row in fides_called_rows if row.get("latency_ms") is not None]

    attack_count = len(attack_keys)
    regex_allowed_count = len(regex_allowed_attacks)
    warden_miss_count = len(warden_allowed_attacks)
    return {
        "warden_incremental_catches_vs_regex": warden_incremental,
        "warden_incremental_catch_rate_vs_regex_misses": round(warden_incremental / regex_allowed_count, 4) if regex_allowed_count else 0.0,
        "fides_incremental_catches_vs_warden": fides_incremental,
        "fides_incremental_catch_rate_vs_warden_misses": round(fides_incremental / warden_miss_count, 4) if warden_miss_count else 0.0,
        "fides_incremental_catch_rate_vs_all_attacks": round(fides_incremental / attack_count, 4) if attack_count else 0.0,
        "remaining_misses_after_rules_plus_fides": len(fides_allowed_attacks),
        "remaining_miss_rate_after_rules_plus_fides": round(len(fides_allowed_attacks) / attack_count, 4) if attack_count else 0.0,
        "attack_case_denominator": attack_count,
        "regex_miss_denominator": regex_allowed_count,
        "warden_miss_denominator": warden_miss_count,
        "fides_calls": len(fides_called_rows),
        "fides_provider_calls": provider_calls,
        "fides_latency_ms": _latency_summary(latencies),
    }


def _nested_get(mapping: Mapping[str, Any], parts: list[str]) -> Any:
    current: Any = mapping
    for part in parts:
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _present(value: Any) -> bool:
    return value not in (None, "", (), [], {})


def _required_fields(case_result: Mapping[str, Any]) -> tuple[str, ...]:
    direct = case_result.get("required_fields")
    if direct:
        return tuple(str(item) for item in direct)
    ground_truth = case_result.get("ground_truth")
    if isinstance(ground_truth, Mapping):
        labels = ground_truth.get("labels")
        if isinstance(labels, Mapping) and labels.get("required_fields"):
            return tuple(str(item) for item in labels.get("required_fields") or ())
    return ()


def _case_fact_context(case_result: Mapping[str, Any]) -> dict[str, Any]:
    safe_features = dict(case_result.get("safe_features") or {}) if isinstance(case_result.get("safe_features"), Mapping) else {}
    policy_context = dict(case_result.get("policy_context") or {}) if isinstance(case_result.get("policy_context"), Mapping) else {}
    requested = {
        "tool": safe_features.get("requested_tool") or safe_features.get("tool"),
        "capability": safe_features.get("requested_capability") or safe_features.get("capability"),
        "action": safe_features.get("requested_action") or safe_features.get("action"),
        "sink": safe_features.get("requested_sink") or safe_features.get("sink") or safe_features.get("target_sink"),
    }
    requested = {key: value for key, value in requested.items() if _present(value)}
    return {
        "features": safe_features,
        "safe_features": safe_features,
        "policy": policy_context,
        "policy_context": policy_context,
        "requested": requested,
        "ground_truth": case_result.get("ground_truth") or {},
    }


def _missing_prerequisite_summary(run_report: Mapping[str, Any]) -> dict[str, Any]:
    by_field: Counter[str] = Counter()
    by_dataset: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    by_dataset_category: dict[str, Counter[str]] = defaultdict(Counter)
    cases_evaluated = 0
    cases_with_requirements = 0

    for case_result in run_report.get("case_results", []):
        if not isinstance(case_result, Mapping):
            continue
        cases_evaluated += 1
        required = _required_fields(case_result)
        if not required:
            continue
        cases_with_requirements += 1
        context = _case_fact_context(case_result)
        dataset = str(case_result.get("dataset_id") or "unknown")
        category = str(case_result.get("attack_category") or "unknown")
        for field in required:
            value = _nested_get(context, field.split("."))
            if _present(value):
                continue
            by_field[field] += 1
            by_dataset[dataset] += 1
            by_category[category] += 1
            by_dataset_category[dataset][category] += 1

    available = cases_with_requirements > 0
    return {
        "available": available,
        "reason": None if available else "no required_fields metadata present in case results",
        "cases_evaluated": cases_evaluated,
        "cases_with_required_fields": cases_with_requirements,
        "total_missing_prerequisites": sum(by_field.values()),
        "by_field": dict(sorted(by_field.items())),
        "by_dataset": dict(sorted(by_dataset.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_dataset_and_category": _sorted_dict(
            {dataset: dict(sorted(categories.items())) for dataset, categories in by_dataset_category.items()}
        ),
        "case_level_rows_included": False,
    }


def _expected_rule_ids(case_result: Mapping[str, Any]) -> tuple[str, ...]:
    ground_truth = case_result.get("ground_truth")
    if isinstance(ground_truth, Mapping):
        return tuple(
            str(rule_id)
            for rule_id in ground_truth.get("expected_rule_ids") or ()
            if str(rule_id).startswith("cwfr-")
        )
    return ()


def _observed_warden_rule_ids(case_result: Mapping[str, Any]) -> set[str]:
    observed: set[str] = set()
    for decision in case_result.get("decisions", []) or []:
        if not isinstance(decision, Mapping):
            continue
        if decision.get("stack") not in {"yara_rules", "rules_plus_fides"}:
            continue
        for rule_id in decision.get("rule_ids", []) or []:
            rule_text = str(rule_id)
            if rule_text.startswith("cwfr-"):
                observed.add(rule_text)
    return observed


def _empty_expected_rule_entry() -> dict[str, Any]:
    return {
        "total_cases": 0,
        "cases_with_expected_rules": 0,
        "cases_without_expected_rules": 0,
        "expected_rule_hits": 0,
        "expected_rule_misses": 0,
        "expected_rule_hit_rate": 0.0,
        "unique_expected_rule_ids": [],
        "unique_hit_rule_ids": [],
        "unique_missed_rule_ids": [],
    }


def _finalize_expected_rule_entry(entry: dict[str, Any]) -> dict[str, Any]:
    denominator = int(entry["cases_with_expected_rules"])
    entry["expected_rule_hit_rate"] = round(int(entry["expected_rule_hits"]) / denominator, 4) if denominator else 0.0
    for key in ("unique_expected_rule_ids", "unique_hit_rule_ids", "unique_missed_rule_ids"):
        entry[key] = sorted(entry[key])
    return entry


def _record_expected_rule_entry(entry: dict[str, Any], expected: tuple[str, ...], observed: set[str]) -> None:
    entry["total_cases"] += 1
    if not expected:
        entry["cases_without_expected_rules"] += 1
        return
    expected_set = set(expected)
    hit_ids = expected_set & observed
    missed_ids = expected_set - observed
    entry["cases_with_expected_rules"] += 1
    entry["unique_expected_rule_ids"] = set(entry["unique_expected_rule_ids"]) | expected_set
    if hit_ids:
        entry["expected_rule_hits"] += 1
        entry["unique_hit_rule_ids"] = set(entry["unique_hit_rule_ids"]) | hit_ids
    else:
        entry["expected_rule_misses"] += 1
    if missed_ids:
        entry["unique_missed_rule_ids"] = set(entry["unique_missed_rule_ids"]) | missed_ids


def _expected_rule_evidence(run_report: Mapping[str, Any]) -> dict[str, Any]:
    overall = _empty_expected_rule_entry()
    by_dataset: dict[str, dict[str, Any]] = defaultdict(_empty_expected_rule_entry)
    by_category: dict[str, dict[str, Any]] = defaultdict(_empty_expected_rule_entry)
    by_dataset_category: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_empty_expected_rule_entry))

    for case_result in run_report.get("case_results", []):
        if not isinstance(case_result, Mapping):
            continue
        expected = _expected_rule_ids(case_result)
        observed = _observed_warden_rule_ids(case_result)
        dataset = str(case_result.get("dataset_id") or "unknown")
        category = str(case_result.get("attack_category") or "unknown")
        _record_expected_rule_entry(overall, expected, observed)
        _record_expected_rule_entry(by_dataset[dataset], expected, observed)
        _record_expected_rule_entry(by_category[category], expected, observed)
        _record_expected_rule_entry(by_dataset_category[dataset][category], expected, observed)

    available = int(overall["cases_with_expected_rules"]) > 0
    return {
        "available": available,
        "reason": None if available else "no expected_rule_ids metadata present in case results",
        **_finalize_expected_rule_entry(overall),
        "by_dataset": _sorted_dict({key: _finalize_expected_rule_entry(value) for key, value in by_dataset.items()}),
        "by_category": _sorted_dict({key: _finalize_expected_rule_entry(value) for key, value in by_category.items()}),
        "by_dataset_and_category": _sorted_dict(
            {
                dataset: _sorted_dict({category: _finalize_expected_rule_entry(value) for category, value in categories.items()})
                for dataset, categories in by_dataset_category.items()
            }
        ),
        "case_level_rows_included": False,
    }


_FACT_FLAG_KEYS = (
    "command_execution_shape",
    "instruction_shape",
    "credential_or_secret_shape",
    "exfiltration_shape",
    "path_boundary_shape",
    "network_request_shape",
    "memory_poisoning_shape",
    "approval_bypass_shape",
    "protected_context_extraction_shape",
    "destructive_action_shape",
    "social_engineering_shape",
    "deception_shape",
    "tool_plan_shape",
    "obfuscated",
)


def _empty_fact_entry() -> dict[str, Any]:
    entry: dict[str, Any] = {
        "total_cases": 0,
        "requested_capability_present_count": 0,
        "requested_capability_present_ratio": 0.0,
        "requested_sink_present_count": 0,
        "requested_sink_present_ratio": 0.0,
        "mapped_category_count": 0,
        "mapped_category_ratio": 0.0,
        "dataset_native_fallback_count": 0,
        "dataset_native_fallback_ratio": 0.0,
    }
    for key in _FACT_FLAG_KEYS:
        entry[f"{key}_count"] = 0
        entry[f"{key}_ratio"] = 0.0
    return entry


def _record_fact_entry(entry: dict[str, Any], case_result: Mapping[str, Any]) -> None:
    raw_safe_features = case_result.get("safe_features")
    safe_features = raw_safe_features if isinstance(raw_safe_features, Mapping) else {}
    category = str(case_result.get("attack_category") or "unknown")
    entry["total_cases"] += 1
    for key in _FACT_FLAG_KEYS:
        if bool(safe_features.get(key, False)):
            entry[f"{key}_count"] += 1
    if _present(safe_features.get("requested_capability") or safe_features.get("capability") or safe_features.get("requested_tool")):
        entry["requested_capability_present_count"] += 1
    if _present(safe_features.get("requested_sink") or safe_features.get("sink") or safe_features.get("target_sink")):
        entry["requested_sink_present_count"] += 1
    if category in {"dataset_native", "unknown"}:
        entry["dataset_native_fallback_count"] += 1
    else:
        entry["mapped_category_count"] += 1


def _finalize_fact_entry(entry: dict[str, Any]) -> dict[str, Any]:
    total = int(entry["total_cases"])
    for key in _FACT_FLAG_KEYS:
        entry[f"{key}_ratio"] = round(int(entry[f"{key}_count"]) / total, 4) if total else 0.0
    for key in ("requested_capability_present", "requested_sink_present", "mapped_category", "dataset_native_fallback"):
        entry[f"{key}_ratio"] = round(int(entry[f"{key}_count"]) / total, 4) if total else 0.0
    return entry


def _safe_fact_completeness(run_report: Mapping[str, Any]) -> dict[str, Any]:
    overall = _empty_fact_entry()
    by_dataset: dict[str, dict[str, Any]] = defaultdict(_empty_fact_entry)
    by_category: dict[str, dict[str, Any]] = defaultdict(_empty_fact_entry)
    by_dataset_category: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_empty_fact_entry))

    for case_result in run_report.get("case_results", []):
        if not isinstance(case_result, Mapping):
            continue
        dataset = str(case_result.get("dataset_id") or "unknown")
        category = str(case_result.get("attack_category") or "unknown")
        _record_fact_entry(overall, case_result)
        _record_fact_entry(by_dataset[dataset], case_result)
        _record_fact_entry(by_category[category], case_result)
        _record_fact_entry(by_dataset_category[dataset][category], case_result)

    return {
        **_finalize_fact_entry(overall),
        "by_dataset": _sorted_dict({key: _finalize_fact_entry(value) for key, value in by_dataset.items()}),
        "by_category": _sorted_dict({key: _finalize_fact_entry(value) for key, value in by_category.items()}),
        "by_dataset_and_category": _sorted_dict(
            {
                dataset: _sorted_dict({category: _finalize_fact_entry(value) for category, value in categories.items()})
                for dataset, categories in by_dataset_category.items()
            }
        ),
        "case_level_rows_included": False,
    }


def _empty_false_positive_entry() -> dict[str, Any]:
    return {
        "total_benign_decisions": 0,
        "false_positive_decisions": 0,
        "false_positive_rate": 0.0,
    }


def _record_benign_decision(entry: dict[str, Any], *, is_false_positive: bool) -> None:
    entry["total_benign_decisions"] += 1
    if is_false_positive:
        entry["false_positive_decisions"] += 1


def _finalize_false_positive_entry(entry: dict[str, Any]) -> dict[str, Any]:
    total = int(entry["total_benign_decisions"])
    entry["false_positive_rate"] = round(int(entry["false_positive_decisions"]) / total, 4) if total else 0.0
    return entry


def _false_positive_diagnostics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    overall = _empty_false_positive_entry()
    by_stack: dict[str, dict[str, Any]] = defaultdict(_empty_false_positive_entry)
    by_dataset: dict[str, dict[str, Any]] = defaultdict(_empty_false_positive_entry)
    by_category: dict[str, dict[str, Any]] = defaultdict(_empty_false_positive_entry)
    by_dataset_category: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(_empty_false_positive_entry))
    by_rule: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "false_positive_decisions": 0,
            "affected_stacks": set(),
            "affected_datasets": set(),
            "affected_categories": set(),
        }
    )

    for row in rows:
        if row.get("case_kind") != "benign":
            continue
        stack = str(row.get("stack") or "unknown")
        dataset = str(row.get("dataset_id") or "unknown")
        category = str(row.get("attack_category") or "unknown")
        is_false_positive = row.get("decision") in _BLOCKING_DECISIONS

        _record_benign_decision(overall, is_false_positive=is_false_positive)
        _record_benign_decision(by_stack[stack], is_false_positive=is_false_positive)
        _record_benign_decision(by_dataset[dataset], is_false_positive=is_false_positive)
        _record_benign_decision(by_category[category], is_false_positive=is_false_positive)
        _record_benign_decision(by_dataset_category[dataset][category], is_false_positive=is_false_positive)

        if not is_false_positive:
            continue
        for rule_id in row.get("rule_ids", []) or []:
            rule_text = str(rule_id)
            if not rule_text.startswith("cwfr-"):
                continue
            by_rule[rule_text]["false_positive_decisions"] += 1
            by_rule[rule_text]["affected_stacks"].add(stack)
            by_rule[rule_text]["affected_datasets"].add(dataset)
            by_rule[rule_text]["affected_categories"].add(category)

    available = int(overall["total_benign_decisions"]) > 0
    return {
        "available": available,
        "reason": None if available else "no benign decisions present in run report",
        "total_benign_decisions": overall["total_benign_decisions"],
        "total_false_positive_decisions": overall["false_positive_decisions"],
        "false_positive_rate": _finalize_false_positive_entry(overall)["false_positive_rate"],
        "by_stack": _sorted_dict({key: _finalize_false_positive_entry(value) for key, value in by_stack.items()}),
        "by_dataset": _sorted_dict({key: _finalize_false_positive_entry(value) for key, value in by_dataset.items()}),
        "by_category": _sorted_dict({key: _finalize_false_positive_entry(value) for key, value in by_category.items()}),
        "by_dataset_and_category": _sorted_dict(
            {
                dataset: _sorted_dict({category: _finalize_false_positive_entry(value) for category, value in categories.items()})
                for dataset, categories in by_dataset_category.items()
            }
        ),
        "by_rule": _sorted_dict(
            {
                rule_id: {
                    "false_positive_decisions": value["false_positive_decisions"],
                    "affected_stacks": sorted(value["affected_stacks"]),
                    "affected_datasets": sorted(value["affected_datasets"]),
                    "affected_categories": sorted(value["affected_categories"]),
                }
                for rule_id, value in by_rule.items()
            }
        ),
        "case_level_rows_included": False,
    }


def build_public_report(run_report: Mapping[str, Any], *, all_rule_ids: Iterable[str] | None = None) -> dict[str, Any]:
    rows = _decision_rows(run_report)
    metrics = {stack: _security_metrics_for_stack(rows, stack) for stack in _STACKS}
    regex_asr = float(metrics["regex_baseline"]["asr"])
    no_guard_asr = float(metrics["no_guard"]["asr"])
    for stack in _STACKS:
        stack_asr = float(metrics[stack]["asr"])
        metrics[stack]["asr_reduction_vs_regex"] = round(regex_asr - stack_asr, 4)
        metrics[stack]["asr_reduction_vs_no_guard"] = round(no_guard_asr - stack_asr, 4)

    known_rule_ids = {str(rule_id) for rule_id in all_rule_ids} if all_rule_ids is not None else _default_rule_ids()
    coverage = _rule_coverage(rows, known_rule_ids)

    return {
        "schema_version": "canaryweave_fides.public_report.v1",
        "source_schema_version": run_report.get("schema_version"),
        "iterations": run_report.get("iterations"),
        "total_cases": run_report.get("total_cases"),
        "total_iterations": run_report.get("total_iterations"),
        "security_metrics": metrics,
        "incremental_metrics": _incremental_metrics(rows),
        "disagreement_matrix": _disagreement_matrix(rows),
        "maintainability_metrics": {
            "rule_engine_codename": "WARDEN",
            "unique_rule_ids": coverage["unique_rule_ids"],
            "rule_count": coverage["covered_rule_count"],
            "covered_rule_count": coverage["covered_rule_count"],
            "total_rule_count": coverage["total_rule_count"],
            "rules_with_no_coverage": coverage["rules_with_no_coverage"],
            "rules_with_no_coverage_count": coverage["rules_with_no_coverage_count"],
            "dataset_rule_coverage": coverage["dataset_rule_coverage"],
            "rule_coverage_by_dataset": coverage["rule_coverage_by_dataset"],
            "rule_coverage_by_category": coverage["rule_coverage_by_category"],
            "rule_coverage_by_surface": coverage["rule_coverage_by_surface"],
            "rule_coverage_by_dataset_and_category": coverage["rule_coverage_by_dataset_and_category"],
        },
        "missing_prerequisite_summary": _missing_prerequisite_summary(run_report),
        "expected_rule_evidence": _expected_rule_evidence(run_report),
        "safe_fact_completeness": _safe_fact_completeness(run_report),
        "false_positive_diagnostics": _false_positive_diagnostics(rows),
        "groups": {
            "by_dataset": _group_counts(rows, "dataset_id"),
            "by_category": _group_counts(rows, "attack_category"),
            "by_surface": _group_counts(rows, "surface"),
        },
        "safety": {
            "public_safe": True,
            "case_level_rows_included": False,
            "source_material_included": False,
            "model_outputs_included": False,
            "judge_transcripts_included": False,
        },
        "adapter_results": [
            {
                "dataset_id": result.get("dataset_id"),
                "status": result.get("status"),
                "case_count": result.get("case_count"),
                "message": result.get("message"),
                "safe_metadata": result.get("safe_metadata", {}),
            }
            for result in run_report.get("adapter_results", [])
            if isinstance(result, Mapping)
        ],
        "provider_calls": run_report.get("provider_calls", 0),
    }
