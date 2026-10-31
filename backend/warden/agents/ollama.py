"""A local model choosing the tool calls, through Ollama's chat API. Optional: needs Ollama running."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable

from warden import config
from warden.workspace import tools as tools_mod
from warden.agents.base import AgentGen


class OllamaAgent:
    """A local model through Ollama's /api/chat with tool calling. Same generator interface as ScriptedAgent."""

    def __init__(self, prompt: str, manifests: Callable[[], list[dict]]) -> None:
        self.prompt, self.manifests = prompt, manifests
        self.cfg = config.settings()["ollama"]
        self.model = ollama_model()
        self.optional = {p for t in tools_mod.specs() for p in t.get("optional_params", [])}

    def _tools(self) -> list[dict]:
        return [{"type": "function", "function": {
                    "name": m["name"], "description": m["description"],
                    "parameters": {"type": "object",
                                   "properties": {k: {"type": "string", "description": d} for k, d in m["params"].items()},
                                   "required": [k for k in m["params"] if k not in self.optional]}}}
                for m in self.manifests()]

    def _chat(self, messages: list[dict]) -> dict:
        body = json.dumps({"model": self.model, "messages": messages, "tools": self._tools(), "stream": False}).encode()
        req = urllib.request.Request(self.cfg["url"].rstrip("/") + "/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.cfg["timeout_seconds"]) as r:
            return json.loads(r.read())["message"]

    def run(self) -> AgentGen:
        llm = config.settings()["llm"]
        messages = [{"role": "system", "content": llm["system"]}, {"role": "user", "content": self.prompt}]
        for _ in range(self.cfg["max_turns"]):
            msg = self._chat(messages)
            messages.append(msg)
            calls = msg.get("tool_calls") or []
            if not calls:
                return msg.get("content") or "Done."
            for call in calls:
                fn = call.get("function") or {}
                raw = fn.get("arguments") or {}
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except json.JSONDecodeError:
                        raw = {}
                out = yield (fn.get("name", ""), {k: str(v) for k, v in raw.items()})
                messages.append({"role": "tool", "tool_name": fn.get("name", ""),
                                 "content": llm["blocked_result"] if out is None else out})
        return "Stopped after too many steps."


def ollama_model() -> str:
    c = config.settings()["ollama"]
    return os.environ.get(c["model_env"], c["model"])


def ollama_status() -> dict:
    """Whether Ollama is running here and has the configured model pulled."""
    c = config.settings()["ollama"]
    model = ollama_model()
    try:
        with urllib.request.urlopen(c["url"].rstrip("/") + "/api/tags", timeout=c["check_timeout_seconds"]) as r:
            names = {m.get("name", "") for m in json.loads(r.read()).get("models", [])}
    except (OSError, ValueError):
        return {"available": False, "reason": "Start Ollama first (open the Ollama app, or run: ollama serve)."}
    if model not in names and f"{model}:latest" not in names:
        return {"available": False, "reason": f"Download the model first: ollama pull {model}"}
    return {"available": True, "reason": "", "model": model}
