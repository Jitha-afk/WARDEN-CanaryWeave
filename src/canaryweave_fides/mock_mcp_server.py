"""Mock MCP Server that serves attack datasets as tool call responses.

Wraps ASB/MCPSecBench data as a stdio MCP server so `warden crawl` can
connect to it and test the full pipeline end-to-end.

Usage:
  # Start as mock server (warden crawl connects to this)
  python -m canaryweave_fides.mock_mcp_server --dataset mcp --path attacks.json

  # Or use directly with warden crawl:
  warden crawl --endpoint "python -m canaryweave_fides.mock_mcp_server --dataset mcp --path attacks.json"
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _load_tools(dataset: str, path: str) -> list[dict[str, Any]]:
    """Load dataset and convert to MCP tool schemas."""
    from .adapters.benchmarks import load_asb_dataset, load_mcpsecbench_dataset

    if dataset == "mcp":
        cases = load_mcpsecbench_dataset(path)
    else:
        cases = load_asb_dataset(path)

    # Group by category as "tools"
    categories: dict[str, list[dict]] = {}
    for case in cases:
        cat = case["attack_category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(case)

    tools = []
    for cat, cat_cases in categories.items():
        tools.append(
            {
                "name": f"test_{cat.replace(' ', '_').lower()}",
                "description": f"Mock tool serving {len(cat_cases)} {cat} attack cases",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "case_index": {
                            "type": "integer",
                            "description": f"Case index (0-{len(cat_cases) - 1})",
                        }
                    },
                },
                "_cases": cat_cases,
            }
        )
    return tools


def _handle_message(msg: dict, tools: list[dict]) -> dict | None:
    """Handle one JSON-RPC message and return response."""
    method = msg.get("method", "")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "warden-mock-mcp",
                    "version": "1.0.0",
                },
            },
        }

    if method == "notifications/initialized":
        return None  # No response for notifications

    if method == "tools/list":
        tool_list = [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["inputSchema"],
            }
            for t in tools
        ]
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tool_list}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        case_index = arguments.get("case_index", 0)

        # Find the tool and serve the attack case
        for t in tools:
            if t["name"] == tool_name:
                cases = t["_cases"]
                idx = min(case_index, len(cases) - 1)
                case = cases[idx]
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": case["text"]},
                        ],
                        "isError": False,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
        }

    # Unknown method
    if msg_id:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main():
    parser = argparse.ArgumentParser(description="Mock MCP server from attack dataset")
    parser.add_argument(
        "--dataset", required=True, choices=["asb", "mcp"], help="Dataset type"
    )
    parser.add_argument("--path", required=True, help="Path to dataset file")
    parser.add_argument(
        "--max-cases", type=int, default=None, help="Limit cases per category"
    )
    args = parser.parse_args()

    tools = _load_tools(args.dataset, args.path)
    if args.max_cases:
        for t in tools:
            t["_cases"] = t["_cases"][: args.max_cases]

    # Stdio loop: read JSON-RPC messages, respond
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = _handle_message(msg, tools)
        if response:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
