"""Claude choosing the tool calls, through the Anthropic API. Optional: needs `pip install anthropic`."""
from __future__ import annotations

import os
from typing import Callable

from warden import config
from warden.workspace import tools as tools_mod
from warden.agents.base import AgentGen


class ClaudeAgent:
    """A real model choosing the tool calls (optional). Same generator interface as ScriptedAgent.

    Off by default. Pick "Real Claude" in the console, or set WARDEN_AGENT=llm; it needs
    `pip install anthropic` and ANTHROPIC_API_KEY set in the server's environment. Blocked calls come back
    to the model as error tool results, so it can carry on with the rest of the task.
    """

    def __init__(self, prompt: str, manifests: Callable[[], list[dict]]) -> None:
        import anthropic  # optional dependency, imported only in this mode
        self.client = anthropic.Anthropic()
        self.prompt, self.manifests = prompt, manifests
        self.cfg = config.settings()["llm"]
        self.model = os.environ.get("WARDEN_MODEL", self.cfg["model"])
        self.optional = {p for t in tools_mod.specs() for p in t.get("optional_params", [])}

    def _tools(self) -> list[dict]:
        return [{"name": m["name"], "description": m["description"],
                 "input_schema": {"type": "object",
                                  "properties": {k: {"type": "string", "description": d} for k, d in m["params"].items()},
                                  "required": [k for k in m["params"] if k not in self.optional]}}
                for m in self.manifests()]

    def run(self) -> AgentGen:
        messages = [{"role": "user", "content": self.prompt}]
        c = self.cfg
        for _ in range(c["max_turns"]):
            response = self.client.beta.messages.create(
                model=self.model, max_tokens=c["max_tokens"], system=c["system"], tools=self._tools(),
                messages=messages, output_config={"effort": c["effort"]},
                # On a safety refusal, the server retries on a fallback model chosen by refusal category.
                betas=c["betas"], fallbacks=c["fallbacks"],
            )
            if response.stop_reason == "refusal":
                return "The model declined this request."
            messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason == "pause_turn":
                continue
            calls = [b for b in response.content if b.type == "tool_use"]
            if not calls:
                return "".join(b.text for b in response.content if b.type == "text") or "Done."
            results = []
            for call in calls:
                args = {k: str(v) for k, v in (call.input or {}).items()}
                out = yield (call.name, args)
                if out is None:
                    results.append({"type": "tool_result", "tool_use_id": call.id, "is_error": True,
                                    "content": c["blocked_result"]})
                else:
                    results.append({"type": "tool_result", "tool_use_id": call.id, "content": out})
            messages.append({"role": "user", "content": results})
        return "Stopped after too many steps."


def claude_status() -> dict:
    """Whether the real-model agent can run here. Checks that a key is set, never what it is."""
    import importlib.util
    if importlib.util.find_spec("anthropic") is None:
        return {"available": False, "reason": "Install the SDK first: pip install anthropic"}
    if not any(os.environ.get(k) for k in config.settings()["llm"]["key_env"]):
        return {"available": False,
                "reason": "Set ANTHROPIC_API_KEY in the terminal that starts the server, then restart it."}
    return {"available": True, "reason": "", "model": os.environ.get("WARDEN_MODEL", config.settings()["llm"]["model"])}
