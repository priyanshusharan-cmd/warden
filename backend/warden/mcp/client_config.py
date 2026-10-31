"""Config that connects Claude Code or Claude Desktop to the synthetic workspace through Warden.

The client starts Warden's MCP proxy, which starts the workspace server (warden.mcp.workspace_server).
Shared by scripts/mcp_config.py and the console's Connect Claude panel.
"""
from __future__ import annotations

import sys
from pathlib import Path

from warden import config

ROOT = config.ROOT

DESKTOP_CONFIG = {
    "darwin": "~/Library/Application Support/Claude/claude_desktop_config.json",
    "win32": "%APPDATA%\\Claude\\claude_desktop_config.json",
}


def audit_path() -> Path:
    return (ROOT / config.settings()["live"]["audit_file"]).resolve()


def mcp_config(scenario: str | None = None, task: str | None = None, allow_approvals: bool | None = None) -> dict:
    live, world = config.settings()["live"], config.settings()["mcp_world"]
    scenario = scenario or world["default_scenario"]
    task = task or live["default_task"]
    allow = live["allow_approvals"] if allow_approvals is None else allow_approvals
    proxy = ["-m", "warden.mcp.proxy", "--task", task, "--audit", str(audit_path())]
    if allow:
        proxy.append("--allow-approvals")
    entry = {"command": sys.executable,
             "args": proxy + ["--", sys.executable, "-m", "warden.mcp.workspace_server", "--scenario", scenario],
             "env": {"PYTHONPATH": str(config.BACKEND_DIR)}}
    return {"mcpServers": {live["server_name"]: entry}}


def where(client: str) -> str:
    if client == "desktop":
        return DESKTOP_CONFIG.get(sys.platform, "claude_desktop_config.json")
    return ".mcp.json in the folder you run `claude` from"
