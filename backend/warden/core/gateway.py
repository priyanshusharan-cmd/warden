"""The enforcement point: every tool call goes through `Gateway.call`.

Shaped like Gateward's proxy (inspect both directions) and Enkrypt's input/output
guardrails: calls are checked before they run, and outputs are labeled and scanned on the
way back so later calls can be traced to them.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from warden.core import contract as contract_mod
from warden.core.audit import AuditLog
from warden.core.tool_pins import ToolPins
from warden.core.labels import Label
from warden.core.policy import Decision, PolicyEngine
from warden.core.provenance import Ledger
from warden.workspace.tools import Registry, ToolError
from warden.workspace.world import World

_approval_ids = itertools.count(1)


def _preview(text: str | None, n: int = 600) -> str | None:
    if text is None:
        return None
    return text if len(text) <= n else text[:n] + "…"


@dataclass
class Step:
    seq: int
    tool: str
    args: dict
    verdict: str            # allow | deny | require_approval | unprotected
    risk: int = 0
    reasons: list[dict] = field(default_factory=list)
    output: str | None = None
    label: dict | None = None
    status: str = "done"    # done | blocked | waiting | approved | rejected | error
    approval_id: str | None = None
    decided_by: str = "warden"   # warden | human

    def to_dict(self) -> dict:
        return {"seq": self.seq, "tool": self.tool, "args": self.args, "verdict": self.verdict,
                "risk": self.risk, "reasons": self.reasons, "output_preview": _preview(self.output),
                "label": self.label, "status": self.status, "approval_id": self.approval_id,
                "decided_by": self.decided_by}


class Gateway:
    def __init__(self, world: World, registry: Registry, prompt: str, protected: bool = True,
                 config: dict | None = None, audit: AuditLog | None = None, run_id: str = "") -> None:
        self.world, self.registry, self.prompt, self.protected = world, registry, prompt, protected
        self.run_id = run_id
        self.audit = audit if audit is not None else AuditLog()
        self.ledger = Ledger()
        self.pins = ToolPins()
        self.contract = contract_mod.derive(prompt)
        self.policy = PolicyEngine(registry, self.ledger, self.contract, self.pins, config)
        self.steps: list[Step] = []
        self.pending: dict[str, Step] = {}
        self._seen_descriptions: dict[str, str] = {}

        self.ledger.add(prompt, Label("trusted", "internal", "your request"))
        self.pins.pin_all(registry.manifests())
        self._record_descriptions()
        if protected:
            self.audit.append("run_started", run=run_id, prompt=prompt, contract=self.contract.to_dict())

    def _record_descriptions(self) -> None:
        """Tool descriptions are untrusted text the model reads. New or changed ones go in the ledger."""
        for m in self.registry.manifests():
            if self._seen_descriptions.get(m["name"]) != m["description"]:
                self._seen_descriptions[m["name"]] = m["description"]
                self.ledger.add(m["description"], Label("untrusted", "public", f"tool:{m['name']} description"))

    def _execute(self, step: Step) -> None:
        try:
            output, label = self.registry.invoke(step.tool, step.args)
        except ToolError as e:
            step.status, step.output = "error", f"Error: {e}"
            return
        step.output, step.label = output, label.to_dict()
        self.ledger.add(output, label)
        self._record_descriptions()
        if self.protected:
            self.audit.append("executed", run=self.run_id, seq=step.seq, tool=step.tool,
                              origin=label.origin, sensitivity=label.sensitivity)

    def call(self, tool: str, args: dict) -> Step:
        step = Step(len(self.steps) + 1, tool, dict(args), "unprotected")
        self.steps.append(step)
        if not self.protected:
            self._execute(step)
            return step

        decision: Decision = self.policy.evaluate(tool, args)
        step.verdict, step.risk, step.reasons = decision.verdict, decision.risk, decision.reasons
        self.audit.append("decision", run=self.run_id, seq=step.seq, tool=tool, args=step.args,
                          verdict=decision.verdict, risk=decision.risk, rules=decision.rules)
        if decision.verdict == "allow":
            self._execute(step)
        elif decision.verdict == "deny":
            step.status = "blocked"
        else:
            step.status = "waiting"
            step.approval_id = f"a{next(_approval_ids)}"
            self.pending[step.approval_id] = step
        return step

    def resolve(self, approval_id: str, approved: bool, by: str = "you") -> Step:
        step = self.pending.pop(approval_id, None)
        if step is None:
            raise KeyError(f"no pending approval {approval_id!r}")
        step.decided_by = "human"
        self.audit.append("human_decision", run=self.run_id, seq=step.seq, tool=step.tool,
                          approved=approved, by=by)
        if approved:
            step.status = "approved"
            self._execute(step)   # sets status to "error" if the tool fails
        else:
            step.status = "rejected"
        return step
