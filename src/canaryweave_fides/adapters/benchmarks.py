"""External benchmark dataset loaders for WARDEN coverage testing.

Parses ASB (all_attack_tools.jsonl) and MCPSecBench (mcpsecbench_mcp_attacks.json)
into NormalizedFacts for evaluation through the WARDEN+FIDES gate.

All datasets are normalized to the WARDEN standard schema internally:
- MCP request context (method, tool name) determines origin and capability facts
- Agent name determines surface and policy context
- See docs/guides/DATASET_SCHEMA.md for the full specification
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..facts import NormalizedFacts

# Agent-specific allowed capabilities (tools an agent would legitimately use)
_AGENT_ALLOWED_CAPABILITIES: dict[str, list[str]] = {
    "system_admin_agent": [
        "monitor_system",
        "check_logs",
        "restart_service",
        "list_processes",
    ],
    "financial_analyst_agent": ["read_report", "calculate_returns", "query_database"],
    "medical_advisor_agent": [
        "lookup_symptoms",
        "check_interactions",
        "read_guidelines",
    ],
    "legal_consultant_agent": ["search_cases", "read_statutes", "draft_document"],
    "ecommerce_manager_agent": ["check_inventory", "process_order", "update_listing"],
    "education_consultant_agent": [
        "search_courses",
        "check_requirements",
        "read_curriculum",
    ],
    "academic_search_agent": ["search_papers", "read_abstract", "check_citations"],
    "aerospace_engineer_agent": [
        "run_simulation",
        "read_telemetry",
        "check_parameters",
    ],
    "autonomous_driving_agent": ["read_sensors", "check_route", "update_map"],
    "psychological_counselor_agent": [
        "read_notes",
        "schedule_session",
        "check_guidelines",
    ],
}


def _origin_from_method(method: str) -> str:
    """Map MCP method to origin label."""
    if "tools" in method:
        return "tool_output"
    if "resources" in method:
        return "resource_content"
    if "sampling" in method:
        return "server_sampling"
    if "prompts" in method:
        return "prompts_get"
    return "tool_output"


def load_asb_dataset(path: Path | str) -> list[dict[str, Any]]:
    """Load ASB all_attack_tools.jsonl with agent-aware context.

    Maps ASB agent-specific format to WARDEN standard:
    - Attacker Tool -> requested capability (triggers $capability_denied)
    - Corresponding Agent -> surface + policy context
    - Description -> tool description (for poisoning checks)
    """
    cases = []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        item = json.loads(line)
        text = item.get("Attacker Instruction", "")
        tool_name = item.get("Attacker Tool", "")
        agent = item.get("Corresponding Agent", "agent")
        allowed = _AGENT_ALLOWED_CAPABILITIES.get(agent, [])
        cases.append(
            {
                "case_id": f"asb.{i:04d}",
                "dataset_id": "asb",
                "text": text,
                "attack_category": item.get("Attack Type", "unknown"),
                "surface": agent,
                "origin": "tool_output",
                "trust": "untrusted",
                "expected_block": True,
                "requested_tool": tool_name,
                "requested_capability": tool_name,
                "allowed_capabilities": allowed,
                "metadata": {
                    "attacker_tool": tool_name,
                    "description": item.get("Description", ""),
                    "aggressive": item.get("Aggressive", ""),
                    "attack_goal": item.get("Attack goal", ""),
                    "agent": agent,
                },
            }
        )
    return cases


def load_mcpsecbench_dataset(path: Path | str) -> list[dict[str, Any]]:
    """Load MCPSecBench mcpsecbench_mcp_attacks.json with MCP request context.

    Uses the mcp_request field to determine:
    - method -> origin (tools/call = tool_output)
    - params.name -> requested capability
    - params.arguments.prompt -> attack text
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = []
    for item in data:
        text = item.get("behavior", "")
        mcp_req = item.get("mcp_request", {})
        params = mcp_req.get("params", {})
        args = params.get("arguments", {})

        prompt = args.get("prompt") or args.get("message") or args.get("input") or ""
        if prompt:
            text = prompt

        method = mcp_req.get("method", "tools/call")
        origin = _origin_from_method(method)
        tool_name = params.get("name", "")

        cases.append(
            {
                "case_id": item.get("id", f"mcp.{len(cases):04d}"),
                "dataset_id": "mcpsecbench",
                "text": text,
                "attack_category": item.get("category", "unknown"),
                "surface": tool_name or "mcp_tool",
                "origin": origin,
                "trust": "untrusted",
                "expected_block": item.get("expected_block", True),
                "requested_tool": tool_name,
                "requested_capability": tool_name,
                "allowed_capabilities": [],
                "metadata": {
                    "severity": item.get("severity", ""),
                    "attack_name": item.get("attack_name", ""),
                    "mcp_method": method,
                    "source": item.get("source", ""),
                },
            }
        )
    return cases


def load_auto_dataset(path: Path | str) -> list[dict[str, Any]]:
    """Auto-detect dataset format and load."""
    text = Path(path).read_text(encoding="utf-8")
    if text.strip().startswith("["):
        return load_mcpsecbench_dataset(path)

    first_line = text.strip().split("\n")[0]
    try:
        item = json.loads(first_line)
        if "Attacker Instruction" in item:
            return load_asb_dataset(path)
        # WARDEN standard format
        cases = []
        for i, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            row = json.loads(line)
            mcp_req = row.get("mcp_request", {})
            params = mcp_req.get("params", {})
            args = params.get("arguments", {})
            prompt = args.get("prompt", "") or row.get("text", "")
            method = mcp_req.get("method", "tools/call")
            tool_name = params.get("name", "")
            cases.append(
                {
                    "case_id": row.get("id", f"custom.{i:04d}"),
                    "dataset_id": row.get("source", "custom"),
                    "text": prompt,
                    "attack_category": row.get("category", "unknown"),
                    "surface": row.get("agent", tool_name or "prompt"),
                    "origin": _origin_from_method(method),
                    "trust": "untrusted",
                    "expected_block": row.get("expected_block", True),
                    "requested_tool": tool_name,
                    "requested_capability": tool_name,
                    "allowed_capabilities": [],
                    "metadata": row.get("metadata", {}),
                }
            )
        return cases
    except json.JSONDecodeError:
        # Plain text: one prompt per line
        return [
            {
                "case_id": f"txt.{i:04d}",
                "dataset_id": "text",
                "text": line.strip(),
                "attack_category": "unknown",
                "surface": "prompt",
                "origin": "tool_output",
                "trust": "untrusted",
                "expected_block": True,
                "requested_tool": "",
                "requested_capability": "",
                "allowed_capabilities": [],
                "metadata": {},
            }
            for i, line in enumerate(text.splitlines())
            if line.strip()
        ]


def cases_to_facts(cases: list[dict[str, Any]]) -> list[tuple[NormalizedFacts, bool]]:
    """Convert parsed cases to (NormalizedFacts, expected_block) tuples.

    Uses agent/tool context for richer fact computation:
    - requested_tool -> capability check ($capability_denied)
    - allowed_capabilities -> policy context
    """
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
        # Enrich with tool/capability context if available
        tool = case.get("requested_tool", "")
        cap = case.get("requested_capability", "")
        allowed = case.get("allowed_capabilities", [])
        if tool or cap:
            facts = NormalizedFacts(
                case_id=facts.case_id,
                dataset_id=facts.dataset_id,
                split=facts.split,
                surface=facts.surface,
                origin_labels=facts.origin_labels,
                trust_labels=facts.trust_labels,
                role_labels=facts.role_labels,
                features=facts.features,
                requested={
                    **dict(facts.requested),
                    "tool": tool or cap,
                    "capability": cap or tool,
                },
                policy={
                    **dict(facts.policy),
                    "allowed_capabilities": tuple(allowed),
                },
                capability=facts.capability,
                flow=facts.flow,
                text=facts.text,
            )
        results.append((facts, case.get("expected_block", True)))
    return results
