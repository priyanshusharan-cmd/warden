"""An MCP server for the synthetic workspace, so a real AI client (Claude Desktop, Claude Code)
can work in it. Put Warden's proxy in front of it to protect it.

    python3 -m warden.mcp.workspace_server --scenario poisoned_invoice

It serves the tools in data/tools.json over the world in data/world.json, with a scenario's
attack planted on top. Nothing ever leaves the machine: sends and deletes only change this
process's in-memory world.
"""
from __future__ import annotations

import argparse
import json
import sys

from warden import config
from warden.workspace import scenarios
from warden.workspace.tools import ToolError, build_registry, specs
from warden.workspace.world import base_world


def tool_schema(spec: dict, description: str) -> dict:
    optional = set(spec.get("optional_params", []))
    return {"name": spec["name"], "description": description,
            "inputSchema": {"type": "object",
                            "properties": {k: {"type": "string", "description": d} for k, d in spec["params"].items()},
                            "required": [k for k in spec["params"] if k not in optional]}}


class WorldServer:
    def __init__(self, scenario_id: str | None = None) -> None:
        self.world = base_world()
        self.registry = build_registry(self.world)
        sc = scenarios.by_id(scenario_id) if scenario_id else None
        if scenario_id and sc is None:
            raise SystemExit(f"warden.mcp.workspace_server: no scenario {scenario_id!r}")
        if sc:
            sc.setup(self.world, self.registry)
        self.info = config.settings()["mcp_world"]

    def tools(self) -> list[dict]:
        by_name = {s["name"]: s for s in specs()}
        return [tool_schema(by_name[name], t.description) for name, t in self.registry.tools.items()]

    def call(self, name: str, args: dict) -> dict:
        try:
            out, _label = self.registry.invoke(name, {k: str(v) for k, v in (args or {}).items()})
            return {"content": [{"type": "text", "text": out}]}
        except ToolError as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:          # notifications need no reply
            return None
        if method == "initialize":
            version = (msg.get("params") or {}).get("protocolVersion") or self.info["protocol_version"]
            result = {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": self.info["name"], "version": self.info["version"]},
                      "instructions": self.info["instructions"]}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call":
            p = msg.get("params") or {}
            result = self.call(p.get("name"), p.get("arguments") or {})
        elif method in ("resources/list", "prompts/list", "resources/templates/list"):
            result = {method.split("/")[0]: []} if method != "resources/templates/list" else {"resourceTemplates": []}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, stdin=None, stdout=None) -> None:
        stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            reply = self.handle(msg)
            if reply is not None:
                stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
                stdout.flush()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="warden.mcp.workspace_server", description="Synthetic workspace as an MCP server")
    ap.add_argument("--scenario", default=config.settings()["mcp_world"]["default_scenario"],
                    help="scenario id from data/scenarios.json to plant (use 'none' for a clean world)")
    args = ap.parse_args(argv)
    WorldServer(None if args.scenario == "none" else args.scenario).serve()


if __name__ == "__main__":
    main()
