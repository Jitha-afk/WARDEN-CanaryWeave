from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from .cases_dsl import CasesParseError, case_example_to_attack_case, parse_cases
from .decisions import Decision, StackName
from .fides import FidesIFCLayer
from .facts import NormalizedFacts
from .fixtures import smoke_cases
from .gate import (
    FidesJudgeMode,
    FidesJudgeResult,
    StaticFidesJudge,
    build_fides_judge,
    evaluate_case,
    evaluate_stack,
)
from .metrics import summarize_smoke
from .providers import (
    CopilotSdkJudgeProvider,
    JudgeProviderConfig,
    default_copilot_home,
)
from .resources import rules_root
from .rich_report import render_warden_rule_check, run_loading_step
from .rule_engine import RuleEngine
from .rule_loader import load_rules


def run_smoke(output: Path | str | None = None) -> dict:
    engine = RuleEngine(load_rules(rules_root()))
    report = summarize_smoke(smoke_cases(), engine, FidesIFCLayer(enabled=True))
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return report


def _write_json(path: Path | None, payload: Mapping[str, Any]) -> None:
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps(payload, indent=2, sort_keys=True))


def _safe_prompt_flags(text: str) -> dict[str, Any]:
    lowered = text.lower()
    return {
        "length": len(text),
        "schema_shape": "plain_text",
        "instruction_shape": any(
            term in lowered
            for term in (
                "policy",
                "instruction",
                "override",
                "developer",
                "system",
                "role",
                "jailbreak",
            )
        ),
        "command_execution_shape": any(
            term in lowered
            for term in (
                "shell",
                "command",
                "execute",
                "script",
                "python",
                "bash",
                "terminal",
            )
        ),
        "credential_or_secret_shape": any(
            term in lowered
            for term in (
                "credential",
                "secret",
                "token",
                "password",
                "private key",
                "api key",
            )
        ),
        "network_request_shape": any(
            term in lowered
            for term in ("http", "url", "network", "webhook", "endpoint", "ssrf")
        ),
        "path_boundary_shape": any(
            term in lowered
            for term in ("path", "file", "directory", "traversal", "workspace")
        ),
        "protected_context_extraction_shape": any(
            term in lowered
            for term in (
                "system prompt",
                "system policy",
                "developer message",
                "protected context",
                "hidden policy",
                "tool schema",
                "extract protected",
                "reveal protected",
            )
        ),
        "destructive_action_shape": any(
            term in lowered
            for term in (
                "delete",
                "wipe",
                "reset",
                "destroy",
                "destructive",
                "remove all",
                "erase",
            )
        ),
        "social_engineering_shape": any(
            term in lowered
            for term in (
                "target profile",
                "victim profile",
                "impersonation",
                "lure",
                "phishing",
                "outbound contact",
            )
        ),
        "deception_shape": any(
            term in lowered
            for term in (
                "deception",
                "deceptive",
                "impersonation",
                "lure",
                "phishing",
                "spoof",
            )
        ),
        "tool_plan_shape": False,
        "security_tool_extension_shape": all(
            term in lowered for term in ("develop", "extension", "metasploit")
        )
        or ("metasploit" in lowered and "extension" in lowered),
        "obfuscated": any(
            term in lowered for term in ("base64", "unicode", "encoded", "hidden")
        ),
    }


def _facts_from_prompt(
    text: str,
    *,
    case_id: str = "prompt.case",
    origin: str = "user",
    trust: str = "trusted",
    surface: str = "prompt",
) -> NormalizedFacts:
    flags = _safe_prompt_flags(text)
    flags["origin_labels"] = [origin]
    flags["trust_labels"] = [trust]
    requested: dict[str, str] = {}
    if flags.get("destructive_action_shape"):
        requested = {
            "tool": "admin_action",
            "capability": "admin_action",
            "action": "destructive_update",
        }
    elif flags.get("command_execution_shape"):
        requested = {
            "tool": "execute_code",
            "capability": "execute_code",
            "action": "execute",
        }
    elif flags.get("network_request_shape"):
        requested = {
            "tool": "network_request",
            "capability": "network_request",
            "action": "external_request",
        }
    elif flags.get("path_boundary_shape"):
        requested = {
            "tool": "read_file",
            "capability": "read_file",
            "action": "read_resource",
        }
    return NormalizedFacts(
        case_id=case_id,
        dataset_id="prompt_file" if case_id != "prompt.case" else "prompt",
        split="adhoc",
        surface=surface,
        text=text or None,
        origin_labels=(origin,),
        trust_labels=(trust,),
        features=flags,
        requested=requested,
        policy={
            "allowed_tools": ("read_task", "summarize_note"),
            "allowed_capabilities": ("read_task", "summarize_note"),
            "allowed_sinks": ("local_audit", "user_response"),
            "trusted_origins": ("user", "host_policy"),
        },
    )


def _prompt_from_args(args: argparse.Namespace) -> str:
    if getattr(args, "prompt_file", None):
        return Path(args.prompt_file).read_text(encoding="utf-8")
    return str(getattr(args, "prompt", "") or "")


def _provider_status(args: argparse.Namespace) -> int:
    sdk_available = (
        CopilotSdkJudgeProvider.import_available()
        if args.provider == "copilot_sdk"
        else False
    )
    payload = {
        "provider": args.provider,
        "sdk_available": sdk_available,
        "copilot_home": str(args.copilot_home or default_copilot_home()),
        "auth": "use GitHub Copilot CLI or gh authenticated session; credentials are never printed",
        "provider_calls_enabled": bool(args.provider_calls_enabled),
        "live_call_attempted": False,
    }
    if sdk_available and args.provider_calls_enabled:
        payload["live_call_attempted"] = True
        try:
            payload["status"] = CopilotSdkJudgeProvider.auth_status(
                copilot_home=args.copilot_home
            )
        except Exception as exc:
            payload["status_error"] = str(exc)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"provider={payload['provider']} sdk_available={payload['sdk_available']} copilot_home={payload['copilot_home']}"
        )
    return 0


def _provider_models(args: argparse.Namespace) -> int:
    sdk_available = CopilotSdkJudgeProvider.import_available()
    models: list[dict[str, Any]] = []
    live_call_attempted = False
    if args.provider == "copilot_sdk" and sdk_available and args.provider_calls_enabled:
        live_call_attempted = True
        try:
            models = CopilotSdkJudgeProvider.list_models(copilot_home=args.copilot_home)
        except Exception as exc:
            models = [{"error": str(exc)}]
    payload = {
        "provider": args.provider,
        "sdk_available": sdk_available,
        "provider_calls_enabled": bool(args.provider_calls_enabled),
        "live_call_attempted": live_call_attempted,
        "models": models,
        "note": "Model availability depends on GitHub Copilot auth and org policy.",
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _provider_doctor(args: argparse.Namespace) -> int:
    sdk_available = (
        CopilotSdkJudgeProvider.import_available()
        if args.provider == "copilot_sdk"
        else False
    )
    payload: dict[str, Any] = {
        "provider": args.provider,
        "sdk_available": sdk_available,
        "model_configured": bool(args.model),
        "provider_calls_enabled": bool(args.provider_calls_enabled),
        "copilot_home": str(args.copilot_home or default_copilot_home()),
        "live_call_attempted": False,
        "quarantine": {
            "mode": "empty",
            "tools": "none",
            "permission_policy": "reject_all",
            "public_safe_prompt_only": True,
        },
    }
    if args.live_call:
        payload["live_call_attempted"] = True
        if not args.provider_calls_enabled:
            payload["live_call_error"] = "--live-call requires --provider-calls-enabled"
        elif not args.model:
            payload["live_call_error"] = "--live-call requires --model"
        else:
            try:
                from .gate import build_fides_judge

                facts = _facts_from_prompt(
                    "provider doctor public-safe synthetic check",
                    case_id="provider.doctor",
                    origin="user",
                    trust="trusted",
                )
                config = JudgeProviderConfig(
                    provider="copilot_sdk",
                    model=args.model,
                    copilot_home=args.copilot_home,
                    provider_calls_enabled=True,
                )
                result = build_fides_judge("copilot_sdk", provider_config=config).judge(
                    facts
                )
                payload["live_call_result"] = result.to_dict()
            except Exception as exc:
                payload["live_call_error"] = str(exc)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _rule_engine_for_ids(rule_ids: list[str] | None) -> RuleEngine | None:
    if not rule_ids:
        return None
    selected = set(rule_ids)
    rules = tuple(
        rule
        for rule in load_rules(rules_root())
        if rule.id in selected or rule.name in selected
    )
    missing = selected - {rule.id for rule in rules} - {rule.name for rule in rules}
    if missing:
        raise ValueError(f"unknown WARDEN rule id/name: {', '.join(sorted(missing))}")
    return RuleEngine(rules)


def _rule_engine_for_check(args: argparse.Namespace) -> RuleEngine | None:
    if getattr(args, "rule_file", None) is not None:
        from .rule_loader import load_rule_file

        return RuleEngine(load_rule_file(args.rule_file))
    return _rule_engine_for_ids(args.rule_id)


def _warden_check(args: argparse.Namespace) -> int:
    prompt = _prompt_from_args(args)
    facts = _facts_from_prompt(
        prompt, origin=args.origin, trust=args.trust, surface=args.surface
    )
    rule_engine = _rule_engine_for_check(args)
    if getattr(args, "format", "json") == "rich":
        run_loading_step(
            "Evaluating WARDEN .war rule",
            enabled=not getattr(args, "no_animation", False),
        )
    decision = evaluate_stack(facts, StackName.YARA_RULES, rule_engine=rule_engine)
    payload = {
        "schema_version": "canaryweave_fides.warden_check.v1",
        "prompt_included": True,
        "prompt_length": len(prompt),
        "facts": facts.to_dict(),
        "decision": decision.to_dict(),
    }
    if getattr(args, "format", "json") == "rich":
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        render_warden_rule_check(
            prompt=prompt,
            facts=facts,
            decision=decision.to_dict(),
            rule_engine=rule_engine,
            rule_path=args.rule_file,
            prompt_included=bool(args.include_prompt),
            llm_verdict=args.llm_verdict,
        )
    else:
        _write_json(args.output, payload)
    return 0


def _judge_for_args(args: argparse.Namespace, case_ids: list[str] | None = None):
    if getattr(args, "fides_mode", "disabled") == "test_double":
        ids = case_ids or ["prompt.case"]
        return StaticFidesJudge(
            {
                case_id: FidesJudgeResult(
                    verdict=args.test_verdict,
                    reason_codes=("fides.test_double.cli",),
                )
                for case_id in ids
            }
        )
    if getattr(args, "fides_mode", "disabled") == "copilot_sdk":
        config = JudgeProviderConfig(
            provider="copilot_sdk",
            model=args.model,
            copilot_home=args.copilot_home,
            provider_calls_enabled=args.provider_calls_enabled,
        )
        from .gate import build_fides_judge

        return build_fides_judge("copilot_sdk", provider_config=config)
    return None


def _judge_one(args: argparse.Namespace) -> int:
    prompt = _prompt_from_args(args)
    facts = _facts_from_prompt(
        prompt, origin=args.origin, trust=args.trust, surface=args.surface
    )
    rule_engine = _rule_engine_for_ids(args.rule_id)
    warden = evaluate_stack(facts, StackName.YARA_RULES, rule_engine=rule_engine)
    judge = _judge_for_args(args, [facts.case_id])
    fides_decision = evaluate_stack(
        facts, StackName.RULES_PLUS_FIDES, fides_judge=judge, rule_engine=rule_engine
    )
    payload = {
        "schema_version": "canaryweave_fides.judge_one.v1",
        "prompt_included": False,
        "prompt_length": len(prompt),
        "warden_decision": warden.to_dict(),
        "fides_decision": fides_decision.to_dict(),
    }
    if getattr(args, "format", "json") == "rich":
        from .rich_report import render_warden_rule_check

        run_loading_step(
            "Evaluating WARDEN + FIDES gate...",
            enabled=not getattr(args, "no_animation", False),
        )
        # Show the FIDES decision (the full stack) in rich format
        render_warden_rule_check(
            prompt=prompt,
            facts=facts,
            decision=fides_decision.to_dict(),
            rule_engine=rule_engine,
            prompt_included=getattr(args, "include_prompt", False),
            llm_verdict=f"{'1 malicious' if fides_decision.fides_verdict.value in ('unsafe',) else '0.5 uncertain' if fides_decision.fides_verdict.value in ('uncertain',) else '0 benign'}",
        )
        # Print FIDES-specific summary
        from rich.console import Console
        from rich.panel import Panel
        from rich import box

        console = Console()
        from rich.table import Table

        fides_table = Table.grid(padding=(0, 2))
        fides_table.add_column(style="bold yellow", no_wrap=True)
        fides_table.add_column(style="white")
        fides_table.add_row("FIDES Verdict", fides_decision.fides_verdict.value.upper())
        fides_table.add_row("Decision", fides_decision.decision.value.upper())
        fides_table.add_row("Blocked By", fides_decision.blocked_by.value)
        if fides_decision.latency_ms is not None:
            fides_table.add_row("Latency", f"{fides_decision.latency_ms:.0f}ms")
        fides_table.add_row("Provider Calls", str(fides_decision.provider_calls))
        console.print(
            Panel(
                fides_table,
                title="FIDES IFC Gate",
                box=box.ROUNDED,
                border_style="yellow",
            )
        )
    else:
        _write_json(args.output, payload)
    return 0


def _bench_scan(args: argparse.Namespace) -> int:
    rows: list[dict[str, Any]] = []
    path = Path(args.input)
    if args.input_format == "jsonl":
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = json.loads(line)
                rows.append(
                    {
                        "id": str(item.get(args.id_field, len(rows))),
                        "text": str(item.get(args.text_field, "")),
                    }
                )
    elif args.input_format == "csv":
        with path.open(newline="", encoding="utf-8") as handle:
            for item in csv.DictReader(handle):
                rows.append(
                    {
                        "id": str(item.get(args.id_field, len(rows))),
                        "text": str(item.get(args.text_field, "")),
                    }
                )
    else:
        rows = [
            {"id": str(i), "text": text}
            for i, text in enumerate(path.read_text(encoding="utf-8").splitlines())
            if text.strip()
        ]
    if args.max_cases is not None:
        rows = rows[: int(args.max_cases)]
    results = []
    counts = {"allow": 0, "quarantine": 0, "block": 0}
    rule_engine = _rule_engine_for_ids(args.rule_id)
    judge = (
        _judge_for_args(args, [f"prompt.{row['id']}" for row in rows])
        if args.mode == "warden-plus-fides"
        else None
    )
    for row in rows:
        facts = _facts_from_prompt(
            row["text"],
            case_id=f"prompt.{row['id']}",
            origin=args.origin,
            trust=args.trust,
            surface=args.surface,
        )
        stack = (
            StackName.RULES_PLUS_FIDES
            if args.mode == "warden-plus-fides"
            else StackName.YARA_RULES
        )
        decision = evaluate_stack(
            facts, stack, fides_judge=judge, rule_engine=rule_engine
        )
        counts[decision.decision.value] += 1
        results.append(
            {
                "id": row["id"],
                "prompt_included": False,
                "prompt_length": len(row["text"]),
                "decision": decision.to_dict(),
            }
        )
    payload = {
        "schema_version": "canaryweave_fides.bench_scan.v1",
        "prompt_rows_included": False,
        "total_prompts": len(rows),
        "decision_counts": counts,
        "results": results,
    }
    _write_json(args.output, payload)
    return 0


_WARDEN_TEST_STACKS = (
    StackName.NO_GUARD,
    StackName.REGEX_BASELINE,
    StackName.YARA_RULES,
    StackName.RULES_PLUS_FIDES,
)


def _stack_outcome(decision: Any) -> str:
    """Collapse a GateDecision to the binary oracle: allow vs. block (block|quarantine)."""
    return "allow" if decision.decision == Decision.ALLOW else "block"


def _summarize_cases(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    passed = sum(1 for row in rows if row["pass"])
    attacks = [row for row in rows if row["expected"] == "block"]
    benign = [row for row in rows if row["expected"] == "allow"]
    per_stack: dict[str, Any] = {}
    for stack in _WARDEN_TEST_STACKS:
        name = stack.value
        asr = (
            (sum(1 for row in attacks if row["stacks"][name] == "allow") / len(attacks))
            if attacks
            else 0.0
        )
        fpr = (
            (sum(1 for row in benign if row["stacks"][name] == "block") / len(benign))
            if benign
            else 0.0
        )
        per_stack[name] = {
            "attack_success_rate": round(asr, 4),
            "false_positive_rate": round(fpr, 4),
        }
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "attacks": len(attacks),
        "benign": len(benign),
        "per_stack": per_stack,
    }


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _write_cases_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stack_names = [stack.value for stack in _WARDEN_TEST_STACKS]
    fieldnames = [
        "attack_type",
        "detail",
        "expected",
        "actual",
        "pass",
        "oracle_decision",
        "rule_ids",
        *stack_names,
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            record = {
                "attack_type": row["attack_type"],
                "detail": row["detail"],
                "expected": row["expected"],
                "actual": row["actual"],
                "pass": row["pass"],
                "oracle_decision": row["oracle_decision"],
                "rule_ids": ";".join(row["rule_ids"]),
            }
            for name in stack_names:
                record[name] = row["stacks"][name]
            writer.writerow(record)


def _render_cases_table(
    rows: list[dict[str, Any]], summary: dict[str, Any], oracle: StackName
) -> None:
    def _truncate(text: str, width: int = 48) -> str:
        flat = text.replace("\n", "\\n")
        return flat if len(flat) <= width else flat[: width - 3] + "..."

    header = f"{'attack_type':28s} {'detail':50s} {'expected':9s} {'actual':7s} result"
    print(header)
    print("-" * len(header))
    for row in rows:
        result = "pass" if row["pass"] else "FAIL"
        print(
            f"{row['attack_type'][:28]:28s} {_truncate(row['detail']):50s} {row['expected']:9s} {row['actual']:7s} {result}"
        )
    print()
    print(
        f"oracle stack: {oracle.value}  |  {summary['passed']}/{summary['total']} passed, {summary['failed']} failed"
    )
    print(f"{'stack':18s} {'ASR':>8s} {'FPR':>8s}")
    for name, metrics in summary["per_stack"].items():
        print(
            f"{name:18s} {metrics['attack_success_rate']:>8.2f} {metrics['false_positive_rate']:>8.2f}"
        )


def _warden_test(args: argparse.Namespace) -> int:
    path = Path(args.input)
    try:
        examples = parse_cases(path.read_text(encoding="utf-8"))
    except CasesParseError as exc:
        print(json.dumps({"error": "cases_parse_error", "detail": str(exc)}, indent=2))
        return 2
    oracle = StackName.coerce(args.stack)
    rows: list[dict[str, Any]] = []
    for index, example in enumerate(examples):
        case = case_example_to_attack_case(example, index=index)
        decisions = evaluate_case(case, _WARDEN_TEST_STACKS)
        by_stack = {decision.stack: decision for decision in decisions}
        oracle_decision = by_stack[oracle]
        actual = _stack_outcome(oracle_decision)
        rows.append(
            {
                "attack_type": example.attack_type,
                "detail": example.detail,
                "expected": example.expected,
                "actual": actual,
                "pass": actual == example.expected,
                "oracle_stack": oracle.value,
                "oracle_decision": oracle_decision.decision.value,
                "rule_ids": list(oracle_decision.rule_ids),
                "stacks": {
                    stack.value: _stack_outcome(by_stack[stack])
                    for stack in _WARDEN_TEST_STACKS
                },
            }
        )

    summary = _summarize_cases(rows)
    if args.jsonl is not None:
        _write_jsonl(args.jsonl, rows)
    if args.csv is not None:
        _write_cases_csv(args.csv, rows)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "schema_version": "canaryweave_fides.warden_test.v1",
                    "oracle_stack": oracle.value,
                    "summary": summary,
                    "results": rows,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        _render_cases_table(rows, summary, oracle)
    return 0 if summary["failed"] == 0 else 1


def _scan(args: argparse.Namespace) -> int:
    """Simplified scan command with sensible defaults."""
    trust = "trusted" if args.trusted else "untrusted"
    origin = "user" if args.trusted else "tool_output"
    fmt = "json" if args.json else "rich"

    if args.file:
        lines = args.file.read_text(encoding="utf-8").splitlines()
        prompts = [line.strip() for line in lines if line.strip()]
        results = []
        for i, prompt_text in enumerate(prompts):
            facts = _facts_from_prompt(
                prompt_text, case_id=f"scan.{i}", origin=origin, trust=trust
            )
            decision = evaluate_stack(facts, StackName.YARA_RULES)
            results.append(
                {
                    "index": i,
                    "prompt": prompt_text[:80],
                    "decision": decision.decision.value,
                    "rule_ids": list(decision.rule_ids),
                }
            )
        if fmt == "json":
            print(json.dumps(results, indent=2))
        else:
            from rich.console import Console as RichConsole
            from rich.table import Table as RichTable

            console = RichConsole()
            table = RichTable(title=f"WARDEN Batch Scan ({len(prompts)} prompts)")
            table.add_column("#", style="dim")
            table.add_column("Prompt", max_width=60)
            table.add_column("Decision", justify="center")
            table.add_column("Rules")
            for r in results:
                from rich.text import Text as RichText

                style = (
                    "bold red" if r["decision"] in ("block", "quarantine") else "green"
                )
                table.add_row(
                    str(r["index"]),
                    r["prompt"],
                    RichText(r["decision"].upper(), style=style),
                    ", ".join(r["rule_ids"]) or "-",
                )
            console.print(table)
        return 0

    if not args.prompt:
        print("Usage: warden scan 'prompt text' or warden scan -f prompts.txt")
        return 1

    facts = _facts_from_prompt(args.prompt, origin=origin, trust=trust)

    if args.fides or args.fides_live:
        rule_engine = RuleEngine(load_rules(rules_root()))
        if args.fides_live:
            config = JudgeProviderConfig(
                provider="copilot_sdk", provider_calls_enabled=True
            )
            judge = build_fides_judge("copilot_sdk", provider_config=config)
        else:
            judge = StaticFidesJudge(
                {
                    facts.case_id: FidesJudgeResult(
                        verdict="unsafe", reason_codes=("fides.test_double.scan",)
                    )
                }
            )
        fides_decision = evaluate_stack(
            facts,
            StackName.RULES_PLUS_FIDES,
            fides_judge=judge,
            rule_engine=rule_engine,
        )
        if fmt == "rich":
            run_loading_step("Evaluating WARDEN + FIDES gate...", enabled=True)
            render_warden_rule_check(
                prompt=args.prompt,
                facts=facts,
                decision=fides_decision.to_dict(),
                rule_engine=rule_engine,
                prompt_included=True,
            )
            from rich.console import Console as RichConsole
            from rich.panel import Panel as RichPanel
            from rich import box as rich_box
            from rich.table import Table as RichTable

            console = RichConsole()
            ft = RichTable.grid(padding=(0, 2))
            ft.add_column(style="bold yellow", no_wrap=True)
            ft.add_column(style="white")
            ft.add_row("FIDES Verdict", fides_decision.fides_verdict.value.upper())
            ft.add_row("Decision", fides_decision.decision.value.upper())
            ft.add_row("Blocked By", fides_decision.blocked_by.value)
            if fides_decision.latency_ms is not None:
                ft.add_row("Latency", f"{fides_decision.latency_ms:.0f}ms")
            ft.add_row("Provider Calls", str(fides_decision.provider_calls))
            console.print(
                RichPanel(
                    ft,
                    title="FIDES IFC Gate",
                    box=rich_box.ROUNDED,
                    border_style="yellow",
                )
            )
        else:
            print(json.dumps(fides_decision.to_dict(), indent=2))
        return 0

    decision = evaluate_stack(facts, StackName.YARA_RULES)
    if fmt == "rich":
        run_loading_step("Evaluating WARDEN rules...", enabled=True)
        render_warden_rule_check(
            prompt=args.prompt,
            facts=facts,
            decision=decision.to_dict(),
            prompt_included=True,
        )
    else:
        print(json.dumps(decision.to_dict(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        description="CanaryWeave FIDES controlled smoke/eval runner"
    )
    subparsers = parser.add_subparsers(dest="command")

    smoke = subparsers.add_parser("smoke", help="Run legacy smoke report")
    smoke.add_argument("--fixture-set", default="smoke", choices=["smoke"])
    smoke.add_argument(
        "--output", type=Path, default=Path("artifacts/smoke_report.json")
    )

    provider = subparsers.add_parser(
        "provider", help="Inspect optional FIDES provider integrations"
    )
    provider_sub = provider.add_subparsers(dest="provider_command", required=True)
    status = provider_sub.add_parser("status")
    status.add_argument("--provider", default="copilot_sdk", choices=["copilot_sdk"])
    status.add_argument("--copilot-home", type=Path, default=None)
    status.add_argument("--provider-calls-enabled", action="store_true")
    status.add_argument("--json", action="store_true")
    models = provider_sub.add_parser("models")
    models.add_argument("--provider", default="copilot_sdk", choices=["copilot_sdk"])
    models.add_argument("--copilot-home", type=Path, default=None)
    models.add_argument("--provider-calls-enabled", action="store_true")
    models.add_argument("--json", action="store_true")
    doctor = provider_sub.add_parser("doctor")
    doctor.add_argument("--provider", default="copilot_sdk", choices=["copilot_sdk"])
    doctor.add_argument("--copilot-home", type=Path, default=None)
    doctor.add_argument("--model", default=None)
    doctor.add_argument("--provider-calls-enabled", action="store_true")
    doctor.add_argument("--live-call", action="store_true")
    doctor.add_argument("--json", action="store_true")

    warden = subparsers.add_parser("warden", help="Run WARDEN against one prompt")
    warden_sub = warden.add_subparsers(dest="warden_command", required=True)
    check = warden_sub.add_parser("check")
    check.add_argument("--prompt", default="")
    check.add_argument("--prompt-file", type=Path, default=None)
    check.add_argument("--origin", default="user")
    check.add_argument("--trust", default="trusted", choices=["trusted", "untrusted"])
    check.add_argument("--surface", default="prompt")
    check.add_argument(
        "--rule-id",
        action="append",
        default=None,
        help="Limit WARDEN to one or more rule IDs/names",
    )
    check.add_argument(
        "--rule-file", type=Path, default=None, help="Run exactly one .war rule file"
    )
    check.add_argument(
        "--format", choices=["json", "rich"], default="json", help="Output format"
    )
    check.add_argument(
        "--include-prompt",
        action="store_true",
        help="Show prompt text in the rich terminal output (the JSON report always carries the raw prompt under facts.text)",
    )
    check.add_argument(
        "--llm-verdict",
        default=None,
        help="Optional FIDES rich-output verdict label, e.g. '1 malicious' or '0 benign'",
    )
    check.add_argument(
        "--no-animation",
        action="store_true",
        help="Disable rich unicode loading animation",
    )
    check.add_argument("--output", type=Path, default=None)

    test = warden_sub.add_parser(
        "test", help="Run a .cases corpus across all four stacks"
    )
    test.add_argument("--input", required=True, type=Path, help=".cases corpus file")
    test.add_argument(
        "--stack",
        default="yara_rules",
        choices=["no_guard", "regex_baseline", "yara_rules", "rules_plus_fides"],
        help="Oracle stack used for the pass/fail column and exit code",
    )
    test.add_argument("--format", choices=["table", "json"], default="table")
    test.add_argument(
        "--jsonl", type=Path, default=None, help="Write per-case JSONL for CI"
    )
    test.add_argument(
        "--csv", type=Path, default=None, help="Write per-case CSV for CI"
    )

    judge = subparsers.add_parser(
        "judge", help="Run WARDEN plus optional FIDES on one prompt"
    )
    judge_sub = judge.add_subparsers(dest="judge_command", required=True)
    one = judge_sub.add_parser("one")
    one.add_argument("--prompt", default="")
    one.add_argument("--prompt-file", type=Path, default=None)
    one.add_argument("--origin", default="user")
    one.add_argument("--trust", default="trusted", choices=["trusted", "untrusted"])
    one.add_argument("--surface", default="prompt")
    one.add_argument(
        "--rule-id",
        action="append",
        default=None,
        help="Limit WARDEN to one or more rule IDs/names",
    )
    one.add_argument(
        "--fides-mode",
        default="disabled",
        choices=["disabled", "test_double", "copilot_sdk"],
    )
    one.add_argument(
        "--test-verdict", default="unsafe", choices=["safe", "unsafe", "uncertain"]
    )
    one.add_argument("--provider-calls-enabled", action="store_true")
    one.add_argument("--model", default=None)
    one.add_argument("--copilot-home", type=Path, default=None)
    one.add_argument("--format", default="json", choices=["json", "rich"])
    one.add_argument("--include-prompt", action="store_true")
    one.add_argument("--no-animation", action="store_true")
    one.add_argument("--output", type=Path, default=None)

    bench = subparsers.add_parser("bench", help="Run prompt-file scans")
    bench_sub = bench.add_subparsers(dest="bench_command", required=True)
    scan = bench_sub.add_parser("scan")
    scan.add_argument("--input", required=True)
    scan.add_argument(
        "--input-format", default="jsonl", choices=["jsonl", "csv", "txt"]
    )
    scan.add_argument("--text-field", default="prompt")
    scan.add_argument("--id-field", default="id")
    scan.add_argument("--origin", default="user")
    scan.add_argument("--trust", default="trusted", choices=["trusted", "untrusted"])
    scan.add_argument("--surface", default="prompt")
    scan.add_argument(
        "--rule-id",
        action="append",
        default=None,
        help="Limit WARDEN to one or more rule IDs/names",
    )
    scan.add_argument(
        "--mode", default="warden", choices=["warden", "warden-plus-fides"]
    )
    scan.add_argument("--max-cases", type=int, default=None)
    scan.add_argument("--output", type=Path, default=None)

    eval_parser = subparsers.add_parser(
        "eval", help="Run WARDEN/FIDES pre-context gate evaluation"
    )
    eval_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Eval YAML config (default: packaged data/evals/smoke.yaml)",
    )
    eval_parser.add_argument(
        "--datasets-config",
        type=Path,
        default=None,
        help="Dataset catalog YAML (default: packaged conf/datasets.yaml)",
    )
    eval_parser.add_argument(
        "--stacks-config",
        type=Path,
        default=None,
        help="Stack catalog YAML (default: packaged conf/stacks.yaml)",
    )
    eval_parser.add_argument(
        "--dataset",
        action="append",
        default=None,
        help="Limit run to one or more configured dataset IDs",
    )
    eval_parser.add_argument("--iterations", type=int, default=50)
    eval_parser.add_argument(
        "--output", type=Path, default=Path("artifacts/evals/gate_eval_report.json")
    )
    eval_parser.add_argument(
        "--private-review-csv",
        type=Path,
        default=None,
        help="Optional reviewer CSV with raw input/output fields; keep under a git-ignored review path",
    )
    eval_parser.add_argument(
        "--fides-mode",
        choices=["disabled", "test_double", "provider_placeholder", "copilot_sdk"],
        default=None,
        help="Override configured FIDES judge mode",
    )
    eval_parser.add_argument(
        "--provider-calls-enabled",
        action="store_true",
        help="Explicitly allow provider-backed FIDES calls",
    )
    eval_parser.add_argument(
        "--model",
        default=None,
        help="Provider model id for quarantined FIDES judge mode",
    )
    eval_parser.add_argument(
        "--copilot-home",
        type=Path,
        default=None,
        help="Private Copilot SDK home for quarantined FIDES judge",
    )
    eval_parser.add_argument(
        "--public-report",
        action="store_true",
        help="Write aggregate public-safe report",
    )
    eval_parser.add_argument(
        "--fail-on-missing-optional-dataset",
        action="store_true",
        help="Treat skipped optional datasets as an eval error instead of reporting an explicit skip",
    )

    parser.add_argument(
        "--fixture-set", default="smoke", choices=["smoke"], help=argparse.SUPPRESS
    )
    parser.add_argument("--output", type=Path, default=None, help=argparse.SUPPRESS)

    # --- Simplified 'scan' command ---
    scan_parser = subparsers.add_parser(
        "scan", help="Quick scan: warden scan 'prompt' or warden scan -f prompts.txt"
    )
    scan_parser.add_argument(
        "prompt", nargs="?", default=None, help="Prompt text to scan"
    )
    scan_parser.add_argument(
        "-f", "--file", type=Path, default=None, help="File of prompts (one per line)"
    )
    scan_parser.add_argument(
        "--fides", action="store_true", help="Enable FIDES judge (test double)"
    )
    scan_parser.add_argument(
        "--fides-live",
        action="store_true",
        help="Enable FIDES judge (real Copilot SDK)",
    )
    scan_parser.add_argument(
        "--json", action="store_true", help="Output JSON instead of rich"
    )
    scan_parser.add_argument(
        "--trusted",
        action="store_true",
        help="Mark input as trusted (default: untrusted)",
    )
    scan_parser.add_argument("--output", type=Path, default=None)

    args = parser.parse_args(effective_argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "provider":
        if args.provider_command == "status":
            return _provider_status(args)
        if args.provider_command == "models":
            return _provider_models(args)
        if args.provider_command == "doctor":
            return _provider_doctor(args)
    if args.command == "warden" and args.warden_command == "check":
        return _warden_check(args)
    if args.command == "warden" and args.warden_command == "test":
        return _warden_test(args)
    if args.command == "judge" and args.judge_command == "one":
        return _judge_one(args)
    if args.command == "bench" and args.bench_command == "scan":
        return _bench_scan(args)
    if args.command == "eval":
        from .runner import EvaluationRunConfig, run_evaluation

        adapters = ()
        stacks = None
        iterations = args.iterations
        default_output = None
        use_public_report = args.public_report
        loaded = None
        if args.config is not None:
            from .config import load_eval_config

            loaded = load_eval_config(
                args.config,
                datasets_config=args.datasets_config,
                stacks_config=args.stacks_config,
            )
            adapters = loaded.adapters
            if args.dataset:
                selected = {str(dataset_id) for dataset_id in args.dataset}
                adapters = tuple(
                    adapter for adapter in adapters if adapter.dataset_id in selected
                )
            stacks = loaded.stacks
            iterations_overridden = any(
                arg == "--iterations" or arg.startswith("--iterations=")
                for arg in effective_argv
            )
            iterations = args.iterations if iterations_overridden else loaded.iterations
            default_output = loaded.default_output
            if not args.public_report and loaded.public_report is not None:
                use_public_report = loaded.public_report

        configured_mode = args.fides_mode or (
            str(getattr(loaded, "fides_mode", FidesJudgeMode.DISABLED).value)
            if loaded
            else FidesJudgeMode.DISABLED.value
        )
        fides_rules = (
            getattr(loaded, "fides_test_double_evidence_rules", ())
            if loaded is not None
            else ()
        )
        if stacks is None:
            run_config = EvaluationRunConfig(
                adapters=adapters, iterations=iterations, fides_mode=configured_mode
            )
        else:
            run_config = EvaluationRunConfig(
                adapters=adapters,
                iterations=iterations,
                stacks=stacks,
                fides_mode=configured_mode,
                fides_test_double_evidence_rules=fides_rules,
            )
        fides_judge = None
        if configured_mode == FidesJudgeMode.COPILOT_SDK.value:
            from .gate import build_fides_judge

            provider_config = JudgeProviderConfig(
                provider="copilot_sdk",
                model=args.model,
                copilot_home=args.copilot_home,
                provider_calls_enabled=args.provider_calls_enabled,
            )
            fides_judge = build_fides_judge(
                "copilot_sdk", provider_config=provider_config
            )
        report = run_evaluation(
            run_config,
            fides_judge=fides_judge,
            private_review_csv=args.private_review_csv,
        )
        missing = [
            result
            for result in report.get("adapter_results", [])
            if result.get("status") == "skipped_missing_local_path"
        ]
        if args.fail_on_missing_optional_dataset and missing:
            print(
                json.dumps(
                    {"error": "missing_optional_dataset", "adapter_results": missing},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 2
        if use_public_report:
            from .reporting import build_public_report

            report = build_public_report(report)
        output_path = args.output
        if (
            args.output == Path("artifacts/evals/gate_eval_report.json")
            and default_output is not None
        ):
            output_path = default_output
        _write_json(output_path, report)
        return 0

    output = args.output or Path("artifacts/smoke_report.json")
    report = run_smoke(output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
