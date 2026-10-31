"""Signed tool metadata: approve a tool's definition once, refuse it if it changes later.

Pins (tool_pins.ToolPins) catch a tool that changes during one session. Signatures last across
sessions: when you sign a tool, Warden stores an HMAC-SHA256 of its name, description and
parameters, keyed with a local secret. If the server later serves a different definition, the
signature no longer matches and every call to that tool is denied (R1). With
"require_signed_tools" in policy.json, tools that were never signed are denied too.

    python3 -m warden.core.signing sign -- python3 -m warden.mcp.workspace_server     # sign what a server offers now
    python3 -m warden.core.signing list

The key comes from WARDEN_SIGNING_KEY, or a file created on first use (readable only by you).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from warden import config

ROOT = config.ROOT


def _cfg() -> dict:
    return config.settings()["signing"]


def _path(key: str) -> Path:
    p = Path(_cfg()[key])
    return p if p.is_absolute() else ROOT / p


def canonical(manifest: dict) -> bytes:
    return json.dumps({"n": manifest["name"], "d": manifest.get("description", ""),
                       "p": manifest.get("params", {})}, sort_keys=True, ensure_ascii=False).encode()


class Signer:
    def __init__(self, key: bytes | None = None, store: Path | None = None) -> None:
        self.key = key if key is not None else self._load_key()
        self.store = store if store is not None else _path("signatures_file")
        self.sigs: dict[str, str] = json.loads(self.store.read_text()) if self.store.exists() else {}

    @staticmethod
    def _load_key() -> bytes:
        env = os.environ.get(_cfg()["key_env"])
        if env:
            return env.encode()
        path = _path("key_file")
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        return path.read_text().strip().encode()

    def signature(self, manifest: dict) -> str:
        return hmac.new(self.key, canonical(manifest), hashlib.sha256).hexdigest()

    def sign(self, manifests: list[dict]) -> list[str]:
        for m in manifests:
            self.sigs[m["name"]] = self.signature(m)
        self.store.parent.mkdir(parents=True, exist_ok=True)
        self.store.write_text(json.dumps(self.sigs, indent=2, sort_keys=True) + "\n")
        return [m["name"] for m in manifests]

    def status(self, manifest: dict) -> str:
        """signed | unsigned | changed"""
        sig = self.sigs.get(manifest["name"])
        if sig is None:
            return "unsigned"
        return "signed" if hmac.compare_digest(sig, self.signature(manifest)) else "changed"

    def problems(self, manifest: dict, required: bool) -> list[dict]:
        st = self.status(manifest)
        if st == "changed":
            return [{"kind": "signature_mismatch",
                     "detail": "tool definition no longer matches the version you signed",
                     "quote": manifest.get("description", "")[:240]}]
        if st == "unsigned" and required:
            return [{"kind": "unsigned",
                     "detail": "policy requires signed tools and this tool was never signed",
                     "quote": manifest.get("description", "")[:240]}]
        return []


def fetch_manifests(server_cmd: list[str], timeout: float = 20) -> list[dict]:
    """Ask an MCP stdio server for its tools, in Warden's manifest shape."""
    reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    proc = subprocess.run(server_cmd, input="".join(json.dumps(r) + "\n" for r in reqs),
                          capture_output=True, text=True, timeout=timeout)
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == 2 and "result" in msg:
            return [manifest_of(t) for t in msg["result"].get("tools", [])]
    raise RuntimeError("the server did not answer tools/list")


def manifest_of(tool: dict) -> dict:
    """An MCP tool definition in the same shape Tool.manifest() gives."""
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    return {"name": tool["name"], "description": tool.get("description", ""),
            "params": {k: (v or {}).get("description", "") for k, v in props.items()}}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["list"]:
        for name, sig in sorted(Signer().sigs.items()):
            print(f"{name:20} {sig[:16]}")
        return 0
    if argv[:1] == ["sign"] and "--" in argv and argv[argv.index("--") + 1:]:
        manifests = fetch_manifests(argv[argv.index("--") + 1:])
        for name in Signer().sign(manifests):
            print(f"signed {name}")
        return 0
    print("usage: python3 -m warden.core.signing sign -- <server command> | list", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
