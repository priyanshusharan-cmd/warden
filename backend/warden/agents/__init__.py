"""Agents choose tool calls; Warden judges them.

Every agent is a generator: it yields (tool, args) calls and receives each call's output, or
None when the call was blocked or failed, and returns its final answer.

    scripted.py  deterministic, always obeys planted instructions (the worst case)
    claude.py    Claude through the Anthropic API (optional)
    ollama.py    a local model through Ollama (optional)
"""
from __future__ import annotations

import os
import sys
from typing import Callable

from warden import config
from warden.agents.base import AgentGen, AgentUnavailable, Call
from warden.agents.claude import ClaudeAgent, claude_status
from warden.agents.ollama import OllamaAgent, ollama_status
from warden.agents.scripted import ScriptedAgent

__all__ = ["AgentGen", "AgentUnavailable", "Call", "ClaudeAgent", "OllamaAgent", "ScriptedAgent",
           "claude_status", "ollama_status", "make_agent"]


def make_agent(prompt: str, manifests: Callable[[], list[dict]], files: dict[str, str] | None = None,
               kind: str | None = None):
    """kind: "scripted" or "llm". Without one, WARDEN_AGENT or settings decide, and llm falls back quietly."""
    explicit = kind is not None
    kind = (kind or os.environ.get("WARDEN_AGENT", config.settings()["agent"]["default"])).lower()
    if kind == "ollama":
        status = ollama_status()
        if status["available"]:
            return OllamaAgent(prompt, manifests)
        if explicit:
            raise AgentUnavailable(status["reason"])
        print(f"warden: WARDEN_AGENT=ollama unavailable ({status['reason']}); using the scripted agent.", file=sys.stderr)
    if kind == "llm":
        status = claude_status()
        if status["available"]:
            return ClaudeAgent(prompt, manifests)
        if explicit:
            raise AgentUnavailable(status["reason"])
        print(f"warden: WARDEN_AGENT=llm unavailable ({status['reason']}); using the scripted agent.", file=sys.stderr)
    return ScriptedAgent(prompt, manifests, files)
