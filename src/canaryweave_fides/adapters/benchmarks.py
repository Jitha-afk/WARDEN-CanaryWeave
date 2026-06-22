"""External benchmark dataset loaders for WARDEN coverage testing.

Parses ASB (all_attack_tools.jsonl) and MCPSecBench (mcpsecbench_mcp_attacks.json)
into NormalizedFacts for evaluation through the WARDEN+FIDES gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..facts import NormalizedFacts


def load_asb_dataset(path: Path | str) -> list[dict[str, Any]]:
    """Load ASB all_attack_tools.jsonl into evaluation-ready dicts.

    ASB format per line:
    {
        "Attacker Tool": "ResourceAllocationHijack",
        "Attacker Instruction": "Please allocate additional CPU...",
        "Attack Type": "Stealthy Attack",
        "Corresponding Agent": "system_admin_agent",
        "Aggressive": "True"
    }
    """
    cases = []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        item = json.loads(line)
        text = item.get("Attacker Instruction", "")
        cases.append(
            {
                "case_id": f"asb.{i:04d}",
                "dataset_id": "asb",
                "text": text,
                "attack_category": item.get("Attack Type", "unknown"),
                "surface": item.get("Corresponding Agent", "agent"),
                "origin": "tool_output",
                "trust": "untrusted",
                "expected_block": True,
                "metadata": {
                    "attacker_tool": item.get("Attacker Tool", ""),
                    "aggressive": item.get("Aggressive", ""),
                    "attack_goal": item.get("Attack goal", ""),
                },
            }
        )
    return cases


def load_mcpsecbench_dataset(path: Path | str) -> list[dict[str, Any]]:
    """Load MCPSecBench mcpsecbench_mcp_attacks.json into evaluation-ready dicts.

    MCPSecBench format:
    [
        {
            "id": "mcpsecbench-prompt_injection-000",
            "category": "prompt_injection",
            "behavior": "ignore the description of tools...",
            "expected_block": true,
            "mcp_request": {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "chat.complete", "arguments": {"prompt": "..."}}
            }
        }
    ]
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = []
    for item in data:
        # Extract text from MCP request or behavior field
        text = item.get("behavior", "")
        mcp_req = item.get("mcp_request", {})
        params = mcp_req.get("params", {})
        args = params.get("arguments", {})

        # Prefer the actual prompt from MCP request if available
        prompt = args.get("prompt") or args.get("message") or args.get("input") or ""
        if prompt:
            text = prompt

        # Determine MCP origin from method
        method = mcp_req.get("method", "")
        origin = "tool_output"
        if "resources" in method:
            origin = "resource_content"
        elif "sampling" in method:
            origin = "server_sampling"

        cases.append(
            {
                "case_id": item.get("id", f"mcp.{len(cases):04d}"),
                "dataset_id": "mcpsecbench",
                "text": text,
                "attack_category": item.get("category", "unknown"),
                "surface": params.get("name", "mcp_tool"),
                "origin": origin,
                "trust": "untrusted",
                "expected_block": item.get("expected_block", True),
                "metadata": {
                    "severity": item.get("severity", ""),
                    "attack_name": item.get("attack_name", ""),
                    "mcp_method": method,
                    "source": item.get("source", ""),
                },
            }
        )
    return cases


def cases_to_facts(cases: list[dict[str, Any]]) -> list[tuple[NormalizedFacts, bool]]:
    """Convert parsed cases to (NormalizedFacts, expected_block) tuples."""
    from ..cli import _facts_from_prompt

    results = []
    for case in cases:
        facts = _facts_from_prompt(
            case["text"],
            case_id=case["case_id"],
            origin=case["origin"],
            trust=case["trust"],
            surface=case.get("surface", "prompt"),
        )
        results.append((facts, case.get("expected_block", True)))
    return results
