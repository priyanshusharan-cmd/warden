"""A run: one agent doing one task through a gateway. It can pause on an approval and resume."""
from __future__ import annotations

import itertools
from dataclasses import dataclass

from warden.agents import ClaudeAgent, OllamaAgent, make_agent
from warden.agents.base import AgentGen
from warden.core.gateway import Gateway, Step
from warden.workspace.tools import Registry
from warden.workspace.world import World, leaks


_run_ids = itertools.count(1)


@dataclass
class Run:
    prompt: str
    world: World
    gateway: Gateway
    agent_gen: AgentGen
    id: str = ""
    status: str = "running"       # running | waiting | done
    answer: str = ""
    baseline: World | None = None
    _waiting_on: str | None = None
    agent_kind: str = "scripted"

    @classmethod
    def start(cls, prompt: str, world: World, registry: Registry, protected: bool,
              agent: str | None = None, **gw_kwargs) -> "Run":
        baseline = world.clone()
        rid = f"r{next(_run_ids)}"
        gateway = Gateway(world, registry, prompt, protected=protected, run_id=rid, **gw_kwargs)
        agent = make_agent(prompt, registry.manifests, {p: f.sensitivity for p, f in world.files.items()}, agent)
        kind = {ClaudeAgent: "llm", OllamaAgent: "ollama"}.get(type(agent), "scripted")
        return cls(prompt, world, gateway, agent.run(), id=rid, baseline=baseline, agent_kind=kind)

    def _drive(self, value) -> None:
        while True:
            try:
                tool, args = self.agent_gen.send(value)
            except StopIteration as stop:
                self.status, self.answer = "done", stop.value or ""
                return
            step = self.gateway.call(tool, args)
            if step.status == "waiting":
                self.status, self._waiting_on = "waiting", step.approval_id
                return
            value = step.output if step.status in ("done", "approved") else None

    def advance(self) -> "Run":
        if self.status == "running":
            self._drive(None)
        return self

    def resume(self, approval_id: str, approved: bool, by: str = "you") -> "Run":
        if self.status != "waiting" or approval_id != self._waiting_on:
            raise KeyError(f"run {self.id} is not waiting on {approval_id!r}")
        step: Step = self.gateway.resolve(approval_id, approved, by=by)
        self.status, self._waiting_on = "running", None
        self._drive(step.output if step.status == "approved" else None)
        return self

    @property
    def waiting_step(self) -> Step | None:
        return self.gateway.pending.get(self._waiting_on) if self._waiting_on else None

    def state(self) -> dict:
        return {"id": self.id, "protected": self.gateway.protected, "status": self.status,
                "prompt": self.prompt, "answer": self.answer,
                "agent": self.agent_kind,
                "steps": [s.to_dict() for s in self.gateway.steps],
                "waiting_on": self._waiting_on,
                "contract": self.gateway.contract.to_dict(),
                "leaks": leaks(self.world, self.baseline) if self.baseline else []}
