"""Print the config that connects Claude Code or Claude Desktop to the synthetic workspace through Warden.

    python3 scripts/print_mcp_config.py                      # Claude Code: save as .mcp.json in your project
    python3 scripts/print_mcp_config.py --client desktop     # Claude Desktop: merge into claude_desktop_config.json
    python3 scripts/print_mcp_config.py --scenario none      # a clean workspace with no attack planted

Every tool call goes through Warden; blocked calls come back to Claude as errors with the reasons,
and the session's audit log is written to a file you can open in the console's Audit log tab.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from warden import config  # noqa: E402
from warden.mcp import client_config  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp_config", description="Print an MCP client config for Warden")
    ap.add_argument("--client", choices=("code", "desktop"), default="code")
    ap.add_argument("--scenario", default=config.settings()["mcp_world"]["default_scenario"],
                    help="scenario id from data/scenarios.json, or 'none' for a clean workspace")
    ap.add_argument("--task", default=config.settings()["live"]["default_task"],
                    help="what you will ask Claude; it sets which tools and recipients are in scope")
    ap.add_argument("--block-approvals", action="store_true",
                    help="block calls that need approval instead of letting Claude ask you")
    opts = ap.parse_args(argv)

    client_config.audit_path().parent.mkdir(parents=True, exist_ok=True)
    cfg = client_config.mcp_config(opts.scenario, opts.task, False if opts.block_approvals else None)
    print(json.dumps(cfg, indent=2))
    restart = " (then restart Claude Desktop)" if opts.client == "desktop" else ""
    print(f"\nSave this as {client_config.where(opts.client)}{restart}.\nAsk Claude: \"{opts.task}\"\n"
          f"Afterwards, open {client_config.audit_path()} in the console's Audit log tab.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
