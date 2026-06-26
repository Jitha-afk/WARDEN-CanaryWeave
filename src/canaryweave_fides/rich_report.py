from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Mapping, Sequence

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .decisions import Decision
from .facts import NormalizedFacts
from .lattice import ConfidentialityLattice
from .rule_engine import RuleEngine, build_evaluation_record
from .rule_loader import load_rule_file, load_rules
from .rule_schema import RuleDefinition
from .resources import rules_root
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


def render_gate_report(
    *,
    prompt: str,
    facts: NormalizedFacts,
    warden_decision: Mapping[str, Any],
    fides_decision: Mapping[str, Any] | None = None,
    rule_engine: RuleEngine | None = None,
    rule_path: Path | None = None,
    prompt_included: bool = False,
    explain: bool = False,
    expected: str | None = None,
    model: str | None = None,
    ladder: Sequence[tuple[str, str]] | None = None,
    planner: Mapping[str, Any] | None = None,
) -> None:
    """Render the three-section gate report (Pattern A).

    Section (1) WARDEN, (2) FIDES/IFC, (3) Evaluator + gateway action. Every value
    is read from the already-computed decision; nothing is recomputed except the
    WARDEN rule evidence, which is the *same* engine result the gate used.
    """
    console = Console()
    console.print(
        _warden_section_panel(
            prompt=prompt,
            facts=facts,
            decision=warden_decision,
            rule_engine=rule_engine,
            rule_path=rule_path,
            prompt_included=prompt_included,
            explain=explain,
        )
    )
    if fides_decision is not None:
        console.print(_fides_section_panel(facts=facts, fides=fides_decision))
        console.print(
            _evaluator_section_panel(
                prompt=prompt,
                fides=fides_decision,
                facts=facts,
                prompt_included=prompt_included,
                expected=expected,
                model=model,
                ladder=ladder,
                planner=planner,
            )
        )


def _section_box(name: str, status: Text, body: Any, border: str) -> Panel:
    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(Text(name, style="bold white"), status)
    header_box = Panel(header, box=box.HEAVY, border_style=border, padding=(0, 1))
    return Panel(
        Group(header_box, body),
        box=box.ROUNDED,
        border_style=border,
        padding=(1, 1),
    )


def _status_text(label: str, ok: bool) -> Text:
    return Text(label, style="bold green" if ok else "bold red")


def _warden_section_panel(
    *,
    prompt: str,
    facts: NormalizedFacts,
    decision: Mapping[str, Any],
    rule_engine: RuleEngine | None,
    rule_path: Path | None,
    prompt_included: bool,
    explain: bool,
) -> Panel:
    selected_rules = _selected_rules(rule_engine=rule_engine, rule_path=rule_path)
    by_id = {rule.id: rule for rule in selected_rules}
    matched_ids = [str(rid) for rid in decision.get("rule_ids", ()) if str(rid) in by_id]
    matched_rules = [by_id[rid] for rid in matched_ids]
    blocked = Decision.coerce(decision.get("decision", Decision.ALLOW)) != Decision.ALLOW
    matched = bool(matched_rules) and blocked
    status = _status_text(
        "MATCHED" if matched else "NO POLICY MATCHED", matched
    )

    hits_by_id: dict[str, Any] = {}
    trace_and_policy = _build_trace_for_facts(facts)
    if trace_and_policy is not None:
        trace, policy = trace_and_policy
        record = build_evaluation_record(trace, policy)
        engine = rule_engine or RuleEngine(selected_rules)
        rule_decision = engine.evaluate_record(record)
        hits_by_id = {hit.rule_id: hit for hit in rule_decision.hits}

    if not matched:
        body = Table.grid(padding=(0, 2))
        body.add_column(style="white")
        body.add_row(f"{len(selected_rules)} rules evaluated - 0 fired")
        if prompt_included:
            body.add_row(Text(f'input "{_truncate(prompt)}"', style="dim"))
        return _section_box("1) WARDEN .war policy", status, body, "cyan")

    rule_panels = [
        _warden_rule_panel(rule, hits_by_id.get(rule.id), explain)
        for rule in matched_rules
    ]
    return _section_box(
        "1) WARDEN .war policy", status, Group(*rule_panels), "cyan"
    )


def _warden_rule_panel(rule: RuleDefinition, hit: Any, explain: bool) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(style="white")
    grid.add_row("rule", f"{rule.id}  {rule.name}")
    grid.add_row("severity", rule.severity)
    grid.add_row("tactic", rule.tactic or "-")
    grid.add_row("action", rule.action)
    anchors = _anchor_list(rule.technique)
    if anchors:
        grid.add_row("anchors", anchors)
    grid.add_row("layers", _layer_summary(rule, hit))
    fired = _term_lines(hit)
    if fired:
        grid.add_row("matched", fired)
    if explain:
        if rule.description:
            grid.add_row("description", rule.description)
        if rule.safety:
            grid.add_row("safety", rule.safety)
        defense = _anchor_list(rule.defense)
        if defense:
            grid.add_row("defense", defense)
        author = rule.meta.get("author")
        if author:
            grid.add_row("author", str(author))
        grid.add_row("condition", rule.condition)
    return Panel(grid, title=f"WARDEN {rule.id}", box=box.ROUNDED, border_style="cyan")


def _anchor_list(refs: Sequence[Any]) -> str:
    parts = []
    for ref in refs:
        text = f"{ref.framework} {ref.technique_id}"
        if ref.mapping_strength:
            text += f" ({ref.mapping_strength})"
        parts.append(text)
    return ", ".join(parts)


def _layer_summary(rule: RuleDefinition, hit: Any) -> str:
    matched_patterns = bool(hit.evidence.get("matched_patterns")) if hit else False
    matched_semantics = bool(hit.evidence.get("matched_semantics")) if hit else False
    matched_facts = bool(hit.matched_signals) if hit else False
    segments = []
    if rule.patterns:
        segments.append("patterns " + ("+" if matched_patterns else "-"))
    if rule.facts:
        segments.append("facts " + ("+" if matched_facts else "-"))
    if rule.semantics:
        segments.append("semantics " + ("+" if matched_semantics else "-"))
    if rule.judge_checks:
        segments.append("judge -")
    return "  ".join(segments) if segments else "-"


def _term_lines(hit: Any) -> str:
    if hit is None:
        return ""
    lines = []
    for name in hit.evidence.get("matched_patterns", ()):
        lines.append(f"+ ${name}  pattern")
    for name in hit.matched_signals:
        lines.append(f"+ ${name}  fact")
    for name in hit.evidence.get("matched_semantics", ()):
        lines.append(f"+ ${name}  semantic")
    return "\n".join(lines)


def _fides_section_panel(*, facts: NormalizedFacts, fides: Mapping[str, Any]) -> Panel:
    ifc_verdict = str(fides.get("ifc_verdict", "not_called"))
    ifc_checks = [str(c) for c in fides.get("ifc_policy_checks", ())]
    fides_verdict = str(fides.get("fides_verdict", "not_called"))
    provider_calls = int(fides.get("provider_calls", 0) or 0)
    latency = fides.get("latency_ms")

    ifc_unsafe = ifc_verdict == "unsafe"
    status_label = (
        "UNSAFE"
        if ifc_unsafe
        else ("SAFE" if ifc_verdict == "safe" else ifc_verdict.upper())
    )
    title = _status_text(status_label, not ifc_unsafe)

    integrity_label = "-"
    conf_label = "-"
    consequential = False
    conf_public = True
    trace_and_policy = _build_trace_for_facts(facts)
    if trace_and_policy is not None:
        trace, _policy = trace_and_policy
        if trace:
            event = trace[0]
            integrity = _event_integrity(event)
            conf = _event_confidentiality(event)
            integrity_label = repr(integrity)
            conf_label = repr(conf)
            consequential = bool(event.consequential_action)
            conf_public = conf == ConfidentialityLattice.public()

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold magenta", no_wrap=True)
    grid.add_column(style="white")
    grid.add_row(
        "integrity",
        Text(
            integrity_label,
            style="bold red" if integrity_label == "UNTRUSTED" else "bold green",
        ),
    )
    grid.add_row("confidentiality", conf_label)
    grid.add_row("taint (join)", integrity_label)
    grid.add_row("consequential", "yes" if consequential else "no")
    pt_fail = ifc_unsafe and "trusted_action" in ifc_checks
    grid.add_row(
        "P-T trusted_action",
        Text("FAIL" if pt_fail else "pass", style="bold red" if pt_fail else "green"),
    )
    if conf_public:
        grid.add_row(
            "P-F permitted_flow",
            Text("n/a (confidentiality public)", style="dim"),
        )
    else:
        pf_fail = ifc_unsafe and "permitted_flow" in ifc_checks
        grid.add_row(
            "P-F permitted_flow",
            Text("FAIL" if pf_fail else "pass", style="bold red" if pf_fail else "green"),
        )
    grid.add_row(
        "Structural IFC",
        Text(ifc_verdict, style="bold red" if ifc_unsafe else "white"),
    )
    grid.add_row("Semantic judge", _judge_line(fides_verdict, provider_calls, latency))
    return _section_box("2) FIDES / IFC", title, grid, "magenta")


def _judge_line(fides_verdict: str, provider_calls: int, latency: Any) -> Text:
    if provider_calls > 0:
        suffix = f" | {latency:.0f}ms" if isinstance(latency, (int, float)) else ""
        style = "bold red" if fides_verdict == "unsafe" else "white"
        return Text(f"{fides_verdict}{suffix} | {provider_calls} call", style=style)
    if fides_verdict == "disabled":
        return Text("disabled - judge mode off", style="dim")
    return Text("not_called - judge not reached (WARDEN/IFC decided)", style="dim")


_GATEWAY_ACTION = {
    Decision.BLOCK: ("blocked at gate - Planner never sees it", "bold red"),
    Decision.QUARANTINE: (
        "quarantined as opaque handle - readable only by query_llm",
        "yellow",
    ),
    Decision.ALLOW: ("forwarded to the Planner (main agent)", "green"),
}


def _decision_outcome(decision: Decision | str) -> str:
    return "allow" if Decision.coerce(decision) == Decision.ALLOW else "block"


def _truth_label(expected: str, actual_outcome: str) -> tuple[str, str]:
    expected_norm = expected.strip().lower()
    if expected_norm == "block" and actual_outcome == "block":
        return "TP", "bold green"
    if expected_norm == "allow" and actual_outcome == "allow":
        return "TN", "bold green"
    if expected_norm == "block" and actual_outcome == "allow":
        return "FN", "bold red"
    if expected_norm == "allow" and actual_outcome == "block":
        return "FP", "bold red"
    return "?", "dim"


def _evaluator_section_panel(
    *,
    prompt: str,
    fides: Mapping[str, Any],
    facts: NormalizedFacts,
    prompt_included: bool,
    expected: str | None,
    model: str | None,
    ladder: Sequence[tuple[str, str]] | None,
    planner: Mapping[str, Any] | None,
) -> Panel:
    decision = Decision.coerce(fides.get("decision", Decision.ALLOW))
    blocked_by = str(fides.get("blocked_by", "none"))
    action_text, action_style = _GATEWAY_ACTION[decision]
    status = Text(decision.value.upper(), style=action_style)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold yellow", no_wrap=True)
    grid.add_column(style="white")
    if prompt_included:
        grid.add_row("input", f'"{_truncate(prompt)}"')
    else:
        grid.add_row("input", f"withheld ({len(prompt)} chars)")
    origin = facts.origin_labels[0] if facts.origin_labels else "unknown"
    grid.add_row("origin", origin)
    grid.add_row("model", model or "-")
    grid.add_row("gate", f"{decision.value.upper()} | blocked_by {blocked_by}")
    grid.add_row("action", Text(action_text, style=action_style))
    if expected is not None:
        actual_outcome = _decision_outcome(decision)
        label, label_style = _truth_label(expected, actual_outcome)
        grid.add_row(
            "oracle",
            Text(
                f"expected {expected.lower()} | actual {actual_outcome} | ",
                style="white",
            )
            + Text(label, style=label_style),
        )

    children: list[Any] = [grid]
    if ladder:
        ladder_grid = Table.grid(padding=(0, 2))
        ladder_grid.add_column(style="cyan", no_wrap=True)
        ladder_grid.add_column(style="white")
        for stack_label, stack_decision in ladder:
            coerced = Decision.coerce(stack_decision)
            style = (
                "green"
                if coerced == Decision.ALLOW
                else "yellow"
                if coerced == Decision.QUARANTINE
                else "bold red"
            )
            ladder_grid.add_row(stack_label, Text(coerced.value.upper(), style=style))
        if planner is not None:
            if planner.get("invoked"):
                response = _truncate(str(planner.get("response_text", "")), 100)
                ladder_grid.add_row("planner (unprotected)", Text(response, style="red"))
            else:
                ladder_grid.add_row(
                    "planner (unprotected)",
                    Text(str(planner.get("note", "")), style="dim"),
                )
        children.append(
            Panel(
                ladder_grid,
                title="stack outcomes",
                title_align="left",
                box=box.SIMPLE_HEAVY,
                border_style="yellow",
            )
        )

    return _section_box("3) EVALUATION", status, Group(*children), "yellow")


def _truncate(text: str, width: int = 72) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "..."


def _selected_rules(
    *, rule_engine: RuleEngine | None, rule_path: Path | None
) -> list[RuleDefinition]:
    if rule_path is not None:
        return list(load_rule_file(rule_path))
    if rule_engine is not None:
        return list(rule_engine.rules)
    return list(load_rules(rules_root()))


def _build_trace_for_facts(facts: NormalizedFacts):
    """Build a TraceEvent+PolicyContext from NormalizedFacts for fact computation."""
    try:
        from .gate import _facts_to_trace_and_policy

        return _facts_to_trace_and_policy(facts)
    except Exception:
        return None
