"""Policy engine: ordered rules turn one tool call into a Decision with cited evidence.

Modeled on CaMeL's SecurityPolicyEngine (per-tool policies, read vs. side-effect tools,
default deny) and Gateward's Decision object. Every rule is a small function that reads a
context and calls `decision.add(...)`; the strictest verdict wins and every reason is kept.
Any exception while evaluating means deny (fail closed).
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from warden import config
from warden.core.contract import Contract
from warden.core.tool_pins import ToolPins
from warden.core.provenance import Ledger, _norm
from warden.workspace.tools import Registry, Tool, domain_of, split_addresses

VERDICT_RANK = {"allow": 0, "require_approval": 1, "deny": 2}
DEFAULT_CONFIG_PATH = config.POLICY_PATH
REQUIRED_KEYS = {"internal_domain", "blocklisted_domains", "high_impact_tools",
                 "internal_send_needs_approval", "risk_base", "risk_per_deny", "risk_per_approval"}



def rule_info() -> dict[str, dict]:
    """Rule names and plain-English help, from data/rules.json."""
    return {r["id"]: r for r in config.load("rules")["rules"]}


class ConfigError(Exception):
    pass


def load_config(path: str | os.PathLike | None = None) -> dict:
    """Load policy.json. A missing or invalid file is an error: Warden refuses to start."""
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    try:
        cfg = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"cannot load policy config {p}: {e}") from e
    missing = REQUIRED_KEYS - set(cfg)
    if missing:
        raise ConfigError(f"policy config {p} is missing {sorted(missing)}")
    return cfg


@dataclass
class Decision:
    verdict: str = "allow"
    risk: int = 0
    reasons: list[dict] = field(default_factory=list)

    def add(self, rule: str, verdict: str, text: str, evidence: list[dict] | None = None) -> None:
        self.reasons.append({"rule": rule, "title": rule_info().get(rule, {}).get("title", rule), "verdict": verdict,
                             "text": text, "evidence": evidence or []})
        if VERDICT_RANK[verdict] > VERDICT_RANK[self.verdict]:
            self.verdict = verdict

    @property
    def rules(self) -> list[str]:
        return [r["rule"] for r in self.reasons]

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "risk": self.risk, "reasons": self.reasons}


@dataclass
class Ctx:
    tool: Tool
    args: dict
    engine: "PolicyEngine"
    decision: Decision

    @property
    def contract(self) -> Contract:
        return self.engine.contract

    @property
    def ledger(self) -> Ledger:
        return self.engine.ledger

    @property
    def cfg(self) -> dict:
        return self.engine.config

    def destinations(self) -> list[str]:
        """Every destination separately: to, cc and bcc lists are split (CaMeL merges them the same way)."""
        out = []
        for p in self.tool.destination_params:
            v = self.args.get(p)
            if not v:
                continue
            out.extend(split_addresses(v) if "@" in v and "://" not in v else [v])
        return out

    def targets(self) -> list[str]:
        return [self.args[p] for p in self.tool.target_params if self.args.get(p)]

    def payload(self) -> str:
        return "\n".join(str(self.args[p]) for p in self.tool.payload_params if self.args.get(p))

    def is_internal(self, domain: str) -> bool:
        internal = self.cfg["internal_domain"]
        return domain == internal or domain.endswith("." + internal)

    def user_named(self, value: str) -> bool:
        v = value.strip().lower()
        return v in self.contract.recipients or value.strip() in self.contract.urls


def _ev(hits: list[dict]) -> list[dict]:
    return [{"origin": h["origin"], "line": h["line"], "quote": h["quote"]} for h in hits[:3]]


def _injected(origin: dict) -> bool:
    return any(h["injection"] for h in origin["evidence"])


# --- rules ----------------------------------------------------------------

def r1_integrity(c: Ctx) -> None:
    for p in c.engine.pins.check(c.tool.manifest()):
        c.decision.add("R1", "deny", p["detail"], [{"origin": f"tool:{c.tool.name} description",
                                                     "line": None, "quote": p["quote"]}])


def r2_beyond_task(c: Ctx) -> None:
    if c.tool.name not in c.contract.tools:
        allowed = ", ".join(sorted(c.contract.tools)) or "nothing"
        c.decision.add("R2", "deny", f"Your request does not need {c.tool.name}. "
                       f"This task only allows: {allowed}.")


def r3_secrets_leaving(c: Ctx) -> None:
    if not c.tool.payload_params:  # egress tools, plus browse (a URL can carry data out)
        return
    hits = [h for h in c.ledger.sensitive_in(c.payload()) if h["sensitivity"] == "secret"]
    if hits:
        how = ", ".join(sorted({h["encoding"] for h in hits}))
        c.decision.add("R3", "deny", f"The outgoing data contains a secret ({how}).",
                       [{"origin": h["origin"], "line": None, "quote": h["preview"]} for h in hits[:3]])


def dest_origin(c: Ctx, value: str) -> dict:
    o = c.ledger.origin_of(value)
    if o["status"] == "unknown" and "://" in value:
        base = value.split("?", 1)[0].split("#", 1)[0]
        o = c.ledger.origin_of(base)
        if o["status"] == "unknown":
            host = urlparse(value).hostname or ""
            if host:
                ho = c.ledger.origin_of(host)
                if ho["status"] == "tainted":
                    o = ho
    return o


def r4_untrusted_destination(c: Ctx) -> None:
    for dest in c.destinations():
        o = dest_origin(c, dest)
        if o["status"] != "tainted":
            continue
        src = o["evidence"][0]
        where = f"{src['origin']}" + (f", line {src['line']}" if src["line"] else "")
        if c.tool.capability == "read":
            if _injected(o):
                c.decision.add("R4", "deny", f"You never asked to open {dest}. It came from {where}, "
                               "which contains instructions aimed at the AI.", _ev(o["evidence"]))
            continue
        if _injected(o):
            c.decision.add("R4", "deny", f"You never named {dest}. It came from {where}, "
                           "which contains instructions aimed at the AI.", _ev(o["evidence"]))
        elif c.is_internal(domain_of(dest)):
            c.decision.add("R4", "require_approval", f"You never named {dest}. It came from {where}.",
                           _ev(o["evidence"]))
        else:
            c.decision.add("R4", "deny", f"You never named {dest}, an outside address. It came from {where}.",
                           _ev(o["evidence"]))


def r5_untrusted_target(c: Ctx) -> None:
    if c.tool.capability not in ("write", "destructive"):
        return
    for tgt in c.targets():
        o = c.ledger.origin_of(tgt)
        if o["status"] == "trusted":
            continue
        if o["status"] == "tainted":
            src = o["evidence"][0]
            where = f"{src['origin']}" + (f", line {src['line']}" if src["line"] else "")
            verdict = "deny" if _injected(o) else "require_approval"
            c.decision.add("R5", verdict, f"You never named {tgt}. The request to change it came from {where}.",
                           _ev(o["evidence"]))
        else:
            c.decision.add("R5", "require_approval", f"Nobody named {tgt}; the agent made it up.")


def r6_secret_read(c: Ctx) -> None:
    if c.tool.name != "read_file":
        return
    path = c.args.get("path", "")
    if path_sensitivity(path, c.engine.registry.world, c.cfg) != "secret":
        return
    if path in c.contract.paths:
        c.decision.add("R6", "require_approval", f"{path} holds secrets. You named it, so confirm the read.")
    else:
        o = c.ledger.origin_of(path)
        c.decision.add("R6", "deny", f"{path} holds secrets and you never asked for it.", _ev(o["evidence"]))


def path_sensitivity(path: str, world, cfg: dict) -> str:
    """A file's label: from the world when known, else from policy path patterns (real files aren't pre-labelled)."""
    f = world.files.get(path) if world else None
    if f is not None:
        return f.sensitivity
    if any(fnmatch.fnmatch(path, p) for p in cfg.get("secret_path_patterns", [])):
        return "secret"
    if any(fnmatch.fnmatch(path, p) for p in cfg.get("confidential_path_patterns", [])):
        return "confidential"
    return "internal"


def r7_confidential_out(c: Ctx) -> None:
    if c.tool.capability != "egress":
        return
    hits = [h for h in c.ledger.sensitive_in(c.payload()) if h["sensitivity"] == "confidential"]
    if not hits:
        return
    dests = c.destinations()
    external = [d for d in dests if not c.is_internal(domain_of(d))] or (["a third-party tool"] if not dests else [])
    ev = [{"origin": h["origin"], "line": None, "quote": h["preview"]} for h in hits[:3]]
    for d in external:
        if d in dests and c.user_named(d):
            c.decision.add("R7", "require_approval",
                           f"The message carries confidential lines to {d}. You named this address, so confirm.", ev)
        else:
            c.decision.add("R7", "deny", f"Confidential lines would leave to {d}.", ev)




def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(domain: str, internal: str, homoglyphs=None, min_len: int | None = None) -> bool:
    if domain == internal or domain.endswith("." + internal):
        return False
    name, iname = domain.split(".")[0], internal.split(".")[0]
    folded = name
    cfg = load_config() if homoglyphs is None or min_len is None else {}
    for a, b in (homoglyphs if homoglyphs is not None else cfg.get("lookalike_homoglyphs", [])):
        folded = folded.replace(a, b)
    if folded == iname or re.search(rf"(?:^|-){re.escape(iname)}(?:-|$)", name):
        return True
    min_len = min_len if min_len is not None else cfg.get("lookalike_min_name_length", 4)
    return len(iname) >= min_len and _edit_distance(folded, iname) == 1


def r8_bad_domain(c: Ctx) -> None:
    internal = c.cfg["internal_domain"]
    for dest in c.destinations():
        d = domain_of(dest)
        if d in c.cfg["blocklisted_domains"]:
            c.decision.add("R8", "deny", f"{d} is on the blocklist.")
        elif lookalike(d, internal, c.cfg.get("lookalike_homoglyphs", []), c.cfg.get("lookalike_min_name_length", 4)):
            c.decision.add("R8", "deny", f"{d} imitates the company domain {internal}.")


def r9_unknown_destination(c: Ctx) -> None:
    if c.tool.capability not in ("egress", "destructive"):
        return
    for dest in c.destinations():
        if dest_origin(c, dest)["status"] == "unknown":
            c.decision.add("R9", "require_approval", f"Nobody mentioned {dest}: not you, not any content read.")


def r10_high_impact(c: Ctx) -> None:
    if c.tool.name not in c.cfg["high_impact_tools"]:
        return
    if c.tool.capability == "destructive":
        c.decision.add("R10", "require_approval", f"{c.tool.name} cannot be undone.")
        return
    for dest in c.destinations():
        if not c.is_internal(domain_of(dest)):
            c.decision.add("R10", "require_approval", f"Data leaves the company to {domain_of(dest)}.")
        elif c.cfg["internal_send_needs_approval"]:
            c.decision.add("R10", "require_approval", "Internal sends need approval under current policy.")


def r11_echoes_flagged(c: Ctx) -> None:
    payload = _norm(c.payload())
    if not payload:
        return
    ev = []
    for seg in c.ledger.segments:
        for f in seg.findings:
            q = f.get("quote") or ""
            if len(q) >= 12 and _norm(q) in payload:
                ev.append({"origin": seg.label.origin, "line": f.get("line"), "quote": q})
    if ev:
        c.decision.add("R11", "require_approval", "The outgoing text repeats an instruction that was aimed at the AI.",
                       ev[:3])


RULES = [r1_integrity, r2_beyond_task, r3_secrets_leaving, r4_untrusted_destination, r5_untrusted_target,
         r6_secret_read, r7_confidential_out, r8_bad_domain, r9_unknown_destination, r10_high_impact,
         r11_echoes_flagged]


class PolicyEngine:
    def __init__(self, registry: Registry, ledger: Ledger, contract: Contract, pins: ToolPins,
                 config: dict | None = None) -> None:
        self.registry, self.ledger, self.contract, self.pins = registry, ledger, contract, pins
        self.config = config if config is not None else load_config()

    def evaluate(self, tool_name: str, args: dict) -> Decision:
        d = Decision()
        try:
            tool = self.registry.get(tool_name) if isinstance(tool_name, str) else None
            if tool is None:
                d.add("R0", "deny", f"There is no tool called {tool_name!r}.")
            elif not isinstance(args, dict) or set(args) - set(tool.params) \
                    or any(not isinstance(v, str) for v in args.values()):
                d.add("R0", "deny", f"The call to {tool_name} has unexpected or malformed arguments.")
            else:
                ctx = Ctx(tool, args, self, d)
                for rule in RULES:
                    rule(ctx)
            d.risk = self._risk(tool, d)
        except Exception as e:  # fail closed: a bug in Warden never lets a call through
            d = Decision()
            d.add("R0", "deny", f"Warden hit an internal error and blocked the call to be safe ({type(e).__name__}).")
            d.risk = 100
        return d

    def _risk(self, tool: Tool | None, d: Decision) -> int:
        base = self.config["risk_base"].get(tool.capability, 50) if tool else 50
        n_deny = sum(r["verdict"] == "deny" for r in d.reasons)
        n_appr = sum(r["verdict"] == "require_approval" for r in d.reasons)
        return min(100, base + self.config["risk_per_deny"] * n_deny + self.config["risk_per_approval"] * n_appr)
