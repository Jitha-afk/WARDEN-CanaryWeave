from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Mapping

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .decisions import Decision
from .facts import NormalizedFacts
from .lattice import ConfidentialityLattice, IntegrityLattice
from .rule_engine import RuleEngine, build_evaluation_record
from .rule_loader import load_rule_file, load_rules
from .rule_schema import RuleDefinition
from .resources import rules_root
from .variable_store import VariableStore, store_if_untrusted
from .fides import _event_integrity, _event_confidentiality


def run_loading_step(message: str, *, enabled: bool = True) -> None:
    """Render a short unicode spinner for demo/operator ergonomics."""
    if not enabled:
        return
    console = Console()
    with Progress(
        SpinnerColumn("dots", style="bold cyan"),
        TextColumn("[cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(message, total=None)
        time.sleep(0.45)


def render_warden_rule_check(
    *,
    prompt: str,
    facts: NormalizedFacts,
    decision: Mapping[str, Any],
    rule_engine: RuleEngine | None = None,
    rule_path: Path | None = None,
    prompt_included: bool = True,
    llm_verdict: str | None = None,
) -> None:
    """Render a reference-style WARDEN rule check using Rich panels and clean boxes."""
    console = Console()
    selected_rules = _selected_rules(rule_engine=rule_engine, rule_path=rule_path)
    matched_ids = set(str(rule_id) for rule_id in decision.get("rule_ids", ()))
    matched_rules = [rule for rule in selected_rules if rule.id in matched_ids]
    display_rules = matched_rules or selected_rules[:1]
    rule = display_rules[0] if display_rules else None
    result = (
        "MATCHED"
        if Decision.coerce(decision.get("decision", Decision.ALLOW)) != Decision.ALLOW
        else "NO MATCH"
    )
    result_style = "bold green" if result == "MATCHED" else "bold red"

    title = Text("WARDEN RULE CHECK", style="bold white")
    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(
        "Deterministic .war policy evaluation", Text(result, style=result_style)
    )
    console.print(
        Panel(
            header,
            title=title,
            box=box.DOUBLE_EDGE,
            border_style="cyan",
            padding=(1, 2),
        )
    )

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="bold cyan", no_wrap=True)
    meta.add_column(style="white")
    if rule_path is not None:
        meta.add_row("Rule File", str(rule_path))
    if rule is not None:
        meta.add_row("Rule ID", rule.id)
        meta.add_row("Rule Name", rule.name)
        meta.add_row("Description", rule.description)
        meta.add_row("Author", str(rule.meta.get("author", "Project Open Hand Monk")))
        meta.add_row("Severity", rule.severity)
        meta.add_row("Action", rule.action)
    if prompt_included:
        meta.add_row("Prompt", f'"{prompt}"')
    else:
        meta.add_row("Prompt", f"withheld ({len(prompt)} chars)")
    meta.add_row("Result", Text(result, style=result_style))
    console.print(
        Panel(meta, title="Rule Metadata", box=box.ROUNDED, border_style="blue")
    )

    patterns = Table.grid(padding=(0, 2))
    patterns.add_column(style="bold magenta", no_wrap=True)
    patterns.add_column(style="white")
    patterns.add_row("Signals", _bullet_list(_matched_or_all_signals(rule, decision)))
    patterns.add_row(
        "Patterns",
        _bullet_list([f"${item.name}" for item in (rule.patterns if rule else ())]),
    )
    patterns.add_row(
        "Semantics",
        _bullet_list([f"${item.name}" for item in (rule.semantics if rule else ())]),
    )
    fides_items = [f"${item.name}" for item in (rule.judge_checks if rule else ())]
    fides_items.append(_llm_verdict_label(llm_verdict, result))
    patterns.add_row("FIDES", _bullet_list(fides_items))
    console.print(
        Panel(
            patterns, title="Matching Patterns", box=box.ROUNDED, border_style="magenta"
        )
    )

    # --- IFC Facts (6 frozen booleans) ---
    trace_and_policy = _build_trace_for_facts(facts)
    if trace_and_policy:
        trace, policy = trace_and_policy
        record = build_evaluation_record(trace, policy)
        ifc_table = Table(
            title="IFC Facts (6 Frozen Booleans)",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
        )
        ifc_table.add_column("Fact", style="white")
        ifc_table.add_column("Value", justify="center")
        for fact_name in sorted(record.facts):
            val = record.facts[fact_name]
            marker = (
                Text("YES", style="bold green") if val else Text("no", style="dim red")
            )
            ifc_table.add_row(f"${fact_name}", marker)
        if trace:
            evt = trace[0]
            integrity = _event_integrity(evt)
            conf = _event_confidentiality(evt)
            ifc_table.add_row("", "")
            ifc_table.add_row(
                "integrity",
                Text(
                    repr(integrity),
                    style=(
                        "bold red"
                        if integrity == IntegrityLattice.untrusted()
                        else "bold green"
                    ),
                ),
            )
            ifc_table.add_row(
                "confidentiality",
                Text(
                    repr(conf),
                    style=(
                        "bold red"
                        if conf == ConfidentialityLattice.secret()
                        else "bold green"
                    ),
                ),
            )
        console.print(ifc_table)
    else:
        facts_table = Table(
            title="Normalized Facts",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
        )
        facts_table.add_column("Feature")
        facts_table.add_column("Value")
        for key in sorted(facts.features):
            value = facts.features[key]
            if isinstance(value, bool) and value:
                facts_table.add_row(key, "true")
        console.print(facts_table)

    # --- Variable Memory Gate ---
    store = VariableStore()
    from .lattice import security_label

    is_untrusted = "untrusted" in (facts.trust_labels or ())
    label = security_label(
        IntegrityLattice.untrusted() if is_untrusted else IntegrityLattice.trusted(),
        ConfidentialityLattice.public(),
    )
    hidden_view = store_if_untrusted(store, prompt, label, source="prompt")
    var_table = Table.grid(padding=(0, 2))
    var_table.add_column(style="bold green", no_wrap=True)
    var_table.add_column(style="white")
    if store.count > 0:
        var = store.retrieve(store.list_variables()[0])
        var_table.add_row("Status", Text("HIDDEN", style="bold red"))
        var_table.add_row("Handle", var.variable_id)
        var_table.add_row("Integrity", repr(label.integrity))
        var_table.add_row("Reason", "Untrusted origin - hidden behind opaque handle")
        var_table.add_row("Planner Sees", hidden_view[:80])
    else:
        var_table.add_row("Status", Text("PASSTHROUGH", style="bold green"))
        var_table.add_row("Integrity", repr(label.integrity))
        var_table.add_row("Reason", "Trusted origin - visible to planner")
    console.print(
        Panel(
            var_table,
            title="FIDES Variable Memory Gate",
            box=box.ROUNDED,
            border_style="green",
        )
    )


def _selected_rules(
    *, rule_engine: RuleEngine | None, rule_path: Path | None
) -> list[RuleDefinition]:
    if rule_path is not None:
        return list(load_rule_file(rule_path))
    if rule_engine is not None:
        return list(rule_engine.rules)
    return list(load_rules(rules_root()))


def _matched_or_all_signals(
    rule: RuleDefinition | None, decision: Mapping[str, Any]
) -> list[str]:
    if rule is None:
        return []
    matched = {str(item) for item in decision.get("reason_codes", ())}
    names = list(rule.facts)
    selected = [name for name in names if name in matched]
    if not selected:
        selected = names
    return [f"${name}" for name in selected]


def _llm_verdict_label(llm_verdict: str | None, result: str) -> str:
    if llm_verdict is None:
        llm_verdict = "1 malicious" if result == "MATCHED" else "0 benign"
    return f"llm_judge_verdict={llm_verdict}"


def _bullet_list(values: list[str]) -> str:
    if not values:
        return "• none"
    return "\n".join(f"• {value}" for value in values)


def _build_trace_for_facts(facts: NormalizedFacts):
    """Build a TraceEvent+PolicyContext from NormalizedFacts for fact computation."""
    try:
        from .gate import _facts_to_trace_and_policy

        return _facts_to_trace_and_policy(facts)
    except Exception:
        return None
