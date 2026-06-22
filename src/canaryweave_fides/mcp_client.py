"""Lightweight MCP client for WARDEN endpoint crawling.

Connects to MCP servers via stdio, discovers tools and resources,
and returns structured tool schemas for adversarial testing.

Adapted from AgentDefense-Bench mcp_specific/client.py — MCP protocol
only, no LLM provider dependencies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MCPToolSchema:
    """Discovered tool from an MCP server."""

    name: str
    description: str = ""
    parameters: dict[str, Any] | None = None
    server_name: str = ""

    def param_names(self) -> list[str]:
        if not self.parameters:
            return []
        props = self.parameters.get("properties", {})
        return list(props.keys())

    def param_types(self) -> dict[str, str]:
        if not self.parameters:
            return {}
        props = self.parameters.get("properties", {})
        return {k: v.get("type", "string") for k, v in props.items()}


@dataclass
class MCPCrawlResult:
    """Result of crawling an MCP endpoint."""

    server_name: str
    tools: list[MCPToolSchema]
    resources: list[dict[str, Any]]
    error: str | None = None


class MCPStdioClient:
    """MCP client over stdio (local server process)."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None):
        self.command = command
        self.env = env
        self._process: asyncio.subprocess.Process | None = None
        self._msg_id = 0

    async def connect(self) -> None:
        proc_env = os.environ.copy()
        # Ensure src/ is on PYTHONPATH for module discovery
        src_dir = str(Path(__file__).resolve().parent.parent)
        existing = proc_env.get("PYTHONPATH", "")
        proc_env["PYTHONPATH"] = (
            f"{src_dir}{os.pathsep}{existing}" if existing else src_dir
        )
        if self.env:
            proc_env.update(self.env)

        self._process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=proc_env,
        )

        # Initialize
        resp = await self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}, "resources": {}},
                "clientInfo": {"name": "warden-crawl", "version": "1.0.0"},
            },
        )
        if resp and not resp.get("error"):
            await self._notify("notifications/initialized")
        else:
            # Read stderr for diagnostics
            err_msg = ""
            if self._process.stderr:
                try:
                    err = await asyncio.wait_for(
                        self._process.stderr.read(4096), timeout=2
                    )
                    err_msg = err.decode(errors="replace").strip()[:300]
                except asyncio.TimeoutError:
                    pass
            raise RuntimeError(
                f"MCP initialize failed: {resp or 'no response'}"
                + (f"\nServer stderr: {err_msg}" if err_msg else "")
            )

    async def list_tools(self) -> list[MCPToolSchema]:
        resp = await self._request("tools/list")
        if not resp or resp.get("error"):
            return []
        tools_data = resp.get("result", {}).get("tools", [])
        return [
            MCPToolSchema(
                name=t.get("name", ""),
                description=t.get("description", ""),
                parameters=t.get("inputSchema"),
            )
            for t in tools_data
        ]

    async def list_resources(self) -> list[dict[str, Any]]:
        resp = await self._request("resources/list")
        if not resp or resp.get("error"):
            return []
        return resp.get("result", {}).get("resources", [])

    async def disconnect(self) -> None:
        if self._process:
            self._process.stdin.close()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()

    async def _request(self, method: str, params: dict | None = None) -> dict:
        self._msg_id += 1
        msg = {"jsonrpc": "2.0", "id": str(self._msg_id), "method": method}
        if params:
            msg["params"] = params
        return await self._send(msg, expect_response=True)

    async def _notify(self, method: str) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        await self._send(msg, expect_response=False)

    async def _send(self, msg: dict, expect_response: bool) -> dict | None:
        if not self._process or not self._process.stdin:
            raise RuntimeError("Not connected")

        data = json.dumps(msg, separators=(",", ":")) + "\n"
        self._process.stdin.write(data.encode())
        await self._process.stdin.drain()

        if expect_response:
            try:
                line = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=30
                )
                if line:
                    decoded = line.decode().strip()
                    if decoded:
                        return json.loads(decoded)
                # Check stderr for errors
                if self._process.stderr:
                    try:
                        err = await asyncio.wait_for(
                            self._process.stderr.read(4096), timeout=1
                        )
                        if err:
                            logger.warning(
                                f"Server stderr: {err.decode(errors='replace')[:200]}"
                            )
                    except asyncio.TimeoutError:
                        pass
            except asyncio.TimeoutError:
                logger.warning(f"Timeout waiting for response to {msg.get('method')}")
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON response: {e}")
        return None


async def crawl_endpoint(
    command: list[str],
    *,
    server_name: str = "unknown",
    env: dict[str, str] | None = None,
) -> MCPCrawlResult:
    """Crawl an MCP endpoint: connect, discover tools/resources, disconnect."""
    client = MCPStdioClient(command, env=env)
    try:
        await client.connect()
        tools = await client.list_tools()
        for tool in tools:
            tool.server_name = server_name
        resources = await client.list_resources()
        return MCPCrawlResult(server_name=server_name, tools=tools, resources=resources)
    except Exception as e:
        return MCPCrawlResult(
            server_name=server_name, tools=[], resources=[], error=str(e)
        )
    finally:
        await client.disconnect()
