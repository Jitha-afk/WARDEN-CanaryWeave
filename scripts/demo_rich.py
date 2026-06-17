from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from canaryweave_fides.runner import _validate_private_review_csv_path

console = Console()


def banner(_: argparse.Namespace) -> int:
    logo = Text()
    logo.append("╦ ╦╔═╗╦═╗╔╦╗╔═╗╔╗╔\n", style="bold bright_cyan")
    logo.append("║║║╠═╣╠╦╝ ║║║╣ ║║║\n", style="bold cyan")
    logo.append("╚╩╝╩ ╩╩╚══╩╝╚═╝╝╚╝\n", style="bold bright_blue")
    logo.append("CanaryWeave FIDES", style="bold white")
    logo.append("\npublic-safe terminal demo", style="dim")
    console.print(Panel(Align.center(logo), box=box.HEAVY, border_style="bright_blue", padding=(1, 4)))
    return 0


def section(args: argparse.Namespace) -> int:
    console.print(Panel(args.title, box=box.ROUNDED, border_style="cyan", style="bold cyan"))
    return 0


def note(args: argparse.Namespace) -> int:
    console.print(f"[dim]{args.message}[/dim]")
    return 0


def flow(_: argparse.Namespace) -> int:
    steps = [
        "private custody",
        "redacted features",
        "WARDEN .war rules",
        "optional FIDES judge",
        "public aggregate report",
    ]
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    for index, step in enumerate(steps, 1):
        for frame in frames[:4]:
            console.print(f"[cyan]{frame}[/cyan] {index}/{len(steps)}  {step}", end="\r")
            time.sleep(0.06)
        console.print(f"[green]✓[/green] {index}/{len(steps)}  {step}" + " " * 24)
    console.print("[green]✓[/green] raw payloads, prompts, transcripts, and private CSV rows stay out of the demo")
    return 0


def spinner(args: argparse.Namespace) -> int:
    with Progress(SpinnerColumn("dots", style="cyan"), TextColumn("[cyan]{task.description}"), transient=False, console=console) as progress:
        progress.add_task(args.message, total=None)
        time.sleep(args.seconds)
    return 0


def inventory(_: argparse.Namespace) -> int:
    root = Path("rules")
    table = Table(title="WARDEN Rule Files", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Path")
    table.add_column("Rule ID")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Severity")
    for path in sorted(root.rglob("*.war")):
        fields: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            for key in ("id", "name", "category", "severity"):
                prefix = key + ":"
                if line.startswith(prefix) and key not in fields:
                    fields[key] = line.split(":", 1)[1].strip()
        table.add_row(str(path), fields.get("id", "?"), fields.get("name", "?"), fields.get("category", "?"), fields.get("severity", "?"))
    console.print(table)
    return 0


def summary(args: argparse.Namespace) -> int:
    path = Path(args.report)
    report = json.loads(path.read_text(encoding="utf-8"))
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="bold cyan")
    meta.add_column(style="white")
    meta.add_row("Report", str(path))
    meta.add_row("Schema", str(report.get("schema_version")))
    meta.add_row("Cases", str(report.get("total_cases")))
    meta.add_row("Iterations", str(report.get("total_iterations")))
    meta.add_row("Provider Calls", str(report.get("provider_calls")))
    console.print(Panel(meta, title="Public Aggregate", box=box.ROUNDED, border_style="blue"))

    metrics = report.get("security_metrics") or {}
    if metrics:
        table = Table(title="Stack Metrics", box=box.SIMPLE_HEAVY, header_style="bold cyan")
        table.add_column("Stack")
        table.add_column("ASR")
        table.add_column("Recall")
        table.add_column("Safe Pass")
        table.add_column("Benign Refusal")
        for stack in ("no_guard", "regex_baseline", "yara_rules", "rules_plus_fides"):
            values = metrics.get(stack)
            if values:
                table.add_row(
                    stack,
                    str(values.get("asr")),
                    str(values.get("recall")),
                    str(values.get("safe_pass_through_rate")),
                    str(values.get("benign_refusal_rate")),
                )
        console.print(table)

    incremental = report.get("incremental_metrics") or {}
    maint = report.get("maintainability_metrics") or {}
    evidence = report.get("expected_rule_evidence") or {}
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold magenta")
    grid.add_column(style="white")
    if incremental:
        grid.add_row("WARDEN vs regex", str(incremental.get("warden_incremental_catches_vs_regex")))
        grid.add_row("FIDES vs WARDEN", str(incremental.get("fides_incremental_catches_vs_warden")))
        grid.add_row("Remaining misses", str(incremental.get("remaining_misses_after_rules_plus_fides")))
    if maint:
        grid.add_row("Rules covered", f"{maint.get('covered_rule_count')} / {maint.get('total_rule_count')}")
        grid.add_row("Codename", str(maint.get("rule_engine_codename")))
    if evidence:
        grid.add_row("Expected-rule evidence", f"cases={evidence.get('cases_with_expected_rules')} hit_rate={evidence.get('expected_rule_hit_rate')}")
    if grid.row_count:
        console.print(Panel(grid, title="Evidence Summary", box=box.ROUNDED, border_style="magenta"))

    for item in report.get("adapter_results", []):
        console.print(f"[dim]adapter={item.get('dataset_id')} status={item.get('status')} cases={item.get('case_count')} public_export={item.get('safe_metadata', {}).get('public_export', 'n/a')}[/dim]")
    return 0


def csv_policy(_: argparse.Namespace) -> int:
    public_target = Path("artifacts/private_review.csv")
    controlled_target = Path("/tmp/canaryweave-fides-private-review/review.csv")
    rows = []
    try:
        _validate_private_review_csv_path(public_target)
    except ValueError as exc:
        rows.append(("blocked public target", str(public_target), str(exc)))
    else:
        raise SystemExit("expected public CSV target to be blocked")
    _validate_private_review_csv_path(controlled_target)
    rows.append(("allowed controlled target", str(controlled_target), "contents withheld from recording"))
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Check")
    table.add_column("Path")
    table.add_column("Result")
    for row in rows:
        table.add_row(*row)
    console.print(Panel(table, title="Private CSV Policy", box=box.ROUNDED, border_style="cyan"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rich renderer for the CanaryWeave FIDES terminal demo")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("banner").set_defaults(func=banner)
    subparsers.add_parser("flow").set_defaults(func=flow)
    subparsers.add_parser("inventory").set_defaults(func=inventory)
    subparsers.add_parser("csv-policy").set_defaults(func=csv_policy)
    section_parser = subparsers.add_parser("section")
    section_parser.add_argument("title")
    section_parser.set_defaults(func=section)
    note_parser = subparsers.add_parser("note")
    note_parser.add_argument("message")
    note_parser.set_defaults(func=note)
    spinner_parser = subparsers.add_parser("spinner")
    spinner_parser.add_argument("message")
    spinner_parser.add_argument("--seconds", type=float, default=0.45)
    spinner_parser.set_defaults(func=spinner)
    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("report")
    summary_parser.set_defaults(func=summary)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
