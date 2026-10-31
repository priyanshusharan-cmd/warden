"""Real MCP gateway mode: wrap any stdio MCP server and apply the same engine.

    python3 -m warden.mcp.proxy --task "Summarize my inbox and send it to alice@acme.example" -- <server command...>

Shaped like Gateward and Invariant Gateway. It reads line-delimited JSON-RPC from the
client, and:
  - tools/list responses: pins and scans every tool, and adds descriptions to the ledger;
  - tools/call requests: runs the policy; blocked calls never reach the server and get a
    JSON-RPC error with the reasons;
  - tools/call results: added to the ledger as untrusted, so later calls can be traced;
  - initialize, ping and notifications pass through untouched.

By default `require_approval` is treated as blocked (fail closed). With --allow-approvals those
calls go on to the client, and clients like Claude Desktop and Claude Code ask you before running
a tool, so the human in the loop is the client's own permission prompt. Denied calls never reach it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading

from warden.core import contract as contract_mod
from warden import config
from warden.core.audit import AuditLog
from warden.core.tool_pins import ToolPins
from warden.core.labels import Label
from warden.core.policy import PolicyEngine, load_config
from warden.core.provenance import Ledger
from warden.core.signing import Signer
from warden.workspace.tools import Registry, Tool
from warden.workspace.world import World



def _rules() -> dict:
    """Classification patterns from data/mcp.json."""
    return config.load("mcp")


def classify(name: str, description: str, params: dict) -> Tool:
    """Turn an MCP tool definition into a Warden Tool with a capability class and argument roles."""
    r = _rules()
    cap_rx = {k: re.compile(v, re.I) for k, v in r["capability_patterns"].items()}
    head = re.sub(r"[_\-]", " ", name)
    words = head + " " + description
    # The tool's name decides first; its description only if the name says nothing.
    cap = next((c for c in ("destructive", "egress", "write") if cap_rx[c].search(head)), None) \
        or next((c for c in ("destructive", "egress") if cap_rx[c].search(words)), "read")
    names = list(params)
    dest = tuple(p for p in names if re.match(r["destination_param"], p, re.I))
    target = tuple(p for p in names if re.match(r["target_param"], p, re.I)) if cap in ("write", "destructive", "read") else ()
    payload = tuple(p for p in names if re.match(r["payload_param"], p, re.I)) if cap == "egress" else ()
    return Tool(name, description, params, cap, fn=None, destination_params=dest,
                target_params=target, payload_params=payload)


class Warden:
    """The proxy's decision state: same ledger, pins, contract and policy as the gateway."""

    def __init__(self, task: str, config: dict, allow_approvals: bool = False,
                 audit: AuditLog | None = None) -> None:
        self.registry = Registry(World())
        self.ledger = Ledger()
        self.pins = ToolPins(Signer(), config.get("require_signed_tools", False))
        self.contract = contract_mod.derive(task)
        self.engine = PolicyEngine(self.registry, self.ledger, self.contract, self.pins, config)
        self.allow_approvals = allow_approvals
        self.audit = audit or AuditLog()
        self.task_given = bool(task.strip())
        self.ledger.add(task, Label("trusted", "internal", "your request"))

    def on_tools_list(self, tools: list[dict]) -> None:
        manifests = []
        for t in tools:
            params = {k: (v or {}).get("description", "") for k, v in
                      ((t.get("inputSchema") or {}).get("properties") or {}).items()}
            tool = classify(t["name"], t.get("description", ""), params)
            self.registry.add(tool)
            if not self.task_given:   # no task: every listed tool is in scope, provenance still applies
                self.contract.tools.add(tool.name)
            manifests.append(tool.manifest())
            self.ledger.add(tool.description, Label("untrusted", "public", f"tool:{tool.name} description"))
        self.pins.pin_all(manifests)
        for r in self.pins.report(manifests):
            if r["problems"]:
                self.audit.append("tool_flagged", tool=r["name"], problems=[p["kind"] for p in r["problems"]])

    def on_call(self, name: str, args: dict) -> dict:
        flat = {k: v if isinstance(v, str) else json.dumps(v) for k, v in (args or {}).items()}
        d = self.engine.evaluate(name, flat)
        blocked = d.verdict == "deny" or (d.verdict == "require_approval" and not self.allow_approvals)
        self.audit.append("decision", tool=name, args=flat, verdict=d.verdict, risk=d.risk,
                          rules=d.rules, blocked=blocked)
        return {"blocked": blocked, "decision": d}

    def on_result(self, name: str, result: dict) -> None:
        texts = [c.get("text", "") for c in (result or {}).get("content", []) if isinstance(c, dict)]
        text = "\n".join(t for t in texts if t)
        if text:
            self.ledger.add(text, Label("untrusted", "internal", f"tool:{name} result"))


def blocked_error(msg_id, name: str, decision) -> dict:
    lines = [f"{r['rule']} {r['title']}: {r['text']}" for r in decision.reasons if r["verdict"] != "allow"]
    held = " (needs human approval)" if decision.verdict == "require_approval" else ""
    return {"jsonrpc": "2.0", "id": msg_id, "error": {
        "code": _rules()["blocked_error_code"],
        "message": f"Warden blocked {name}{held}: " + " | ".join(lines),
        "data": {"verdict": decision.verdict, "risk": decision.risk, "reasons": decision.reasons}}}


class Proxy:
    def __init__(self, warden: Warden, server_cmd: list[str], client_in=None, client_out=None) -> None:
        self.w = warden
        self.client_in = client_in or sys.stdin
        self.client_out = client_out or sys.stdout
        self.out_lock = threading.Lock()
        self.pending: dict = {}          # request id -> ("list", None) | ("call", tool name)
        self.settled = threading.Condition()
        self.server = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       text=True, bufsize=1)

    def to_client(self, msg: dict) -> None:
        with self.out_lock:
            self.client_out.write(json.dumps(msg) + "\n")
            self.client_out.flush()

    def to_server(self, line: str) -> None:
        self.server.stdin.write(line if line.endswith("\n") else line + "\n")
        self.server.stdin.flush()

    def pump_server(self) -> None:
        for line in self.server.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self.settled:
                kind = self.pending.get(msg.get("id")) if "id" in msg and "method" not in msg else None
                if kind and "result" in msg:
                    if kind[0] == "list":
                        self.w.on_tools_list(msg["result"].get("tools", []))
                    elif kind[0] == "call":
                        self.w.on_result(kind[1], msg["result"])
                if kind:
                    del self.pending[msg["id"]]
                    self.settled.notify_all()
            self.to_client(msg)

    def run(self) -> int:
        t = threading.Thread(target=self.pump_server, daemon=True)
        t.start()
        for line in self.client_in:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.to_client({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            method = msg.get("method")
            if method == "tools/list" and "id" in msg:
                with self.settled:
                    self.pending[msg["id"]] = ("list", None)
            elif method == "tools/call" and "id" in msg:
                # Provenance needs every earlier tool list and result in the ledger before judging this call.
                with self.settled:
                    self.settled.wait_for(lambda: not self.pending, timeout=30)
                p = msg.get("params") or {}
                name, args = p.get("name"), p.get("arguments") or {}
                verdict = self.w.on_call(name, args)
                if verdict["blocked"]:
                    self.to_client(blocked_error(msg["id"], name, verdict["decision"]))
                    continue
                with self.settled:
                    self.pending[msg["id"]] = ("call", name)
            self.to_server(line)
        self.server.stdin.close()
        self.server.wait(timeout=5)
        t.join(timeout=2)
        return self.server.returncode or 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: python3 -m warden.mcp.proxy [--task TEXT] [--allow-approvals] [--audit FILE] -- <server command>",
              file=sys.stderr)
        return 2
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="warden.mcp.proxy")
    ap.add_argument("--task", default="", help="the user's request; sets the least-privilege contract")
    ap.add_argument("--allow-approvals", action="store_true", help="pass calls that need approval on to the client, which asks you (Claude Desktop/Code do)")
    ap.add_argument("--audit", help="write the audit log here as JSON lines (open it in the console's Audit log tab)")
    ap.add_argument("--policy", help="path to policy.json")
    opts = ap.parse_args(argv[:i])
    server_cmd = argv[i + 1:]
    if not server_cmd:
        print("warden.mcp.proxy: no server command after --", file=sys.stderr)
        return 2
    if opts.audit:
        os.makedirs(os.path.dirname(os.path.abspath(opts.audit)), exist_ok=True)
        open(opts.audit, "w").close()      # one file per session; entries are appended as they happen
    warden = Warden(opts.task, load_config(opts.policy), opts.allow_approvals,
                    AuditLog(opts.audit) if opts.audit else None)
    return Proxy(warden, server_cmd).run()


if __name__ == "__main__":
    sys.exit(main())
