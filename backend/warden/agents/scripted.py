"""The scripted agent: a deterministic stand-in for an easily misled model.

It plans from the user's request, and after every read it obeys any instruction it finds in the
content, including hidden, encoded, Hindi and Kannada ones, and instructions in tool descriptions.
That is the worst case. Warden has to hold anyway.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

from warden import config
from warden.core import detectors
from warden.core.detectors import EMAIL_RE, PATH_RE, URL_RE
from warden.agents.base import AgentGen


def K() -> dict:
    """The agent's keywords and phrasing, from data/agent.json."""
    return config.load("agent")


def has(key: str, text: str) -> bool:
    return bool(re.search(K()[key], text))


@dataclass
class Directive:
    kind: str              # send | post | visit | delete | read | include | notes
    target: str = ""
    line: str = ""

    @property
    def key(self) -> tuple:
        return (self.kind, self.target, self.line)


def _view(text: str) -> str:
    """What a model 'sees': invisible characters dropped, encoded blobs decoded."""
    clean = detectors.strip_invisible(text)
    decoded = [dec for _, dec in detectors.decode_candidates(clean)]
    return "\n".join([clean, *decoded])


def _paths(line: str) -> list[str]:
    return PATH_RE.findall(EMAIL_RE.sub(" ", URL_RE.sub(" ", line)))


def find_directives(text: str) -> list[Directive]:
    out: list[Directive] = []
    for raw in re.split(r"\n|(?<=[.!?।])\s+", _view(text)):
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        emails = EMAIL_RE.findall(line)
        urls = [u.rstrip(".,") for u in URL_RE.findall(line)]
        paths = _paths(line)
        if has("delete", low) and paths:
            out.append(Directive("delete", paths[-1], line))
        elif has("send", low) and emails:
            out.append(Directive("send", emails[-1], line))
        elif has("post", low) and urls:
            out.append(Directive("post", urls[-1], line))
        elif has("visit", low) and urls:
            out.append(Directive("visit", urls[-1], line))
        elif has("notes", low):
            out.append(Directive("notes", paths[0] if paths else "", line))
        elif has("read", low) and paths:
            out.append(Directive("read", paths[0], line))
        elif has("include", low) and (has("secret", low) or has("confidential", low)):
            out.append(Directive("include", "", line))
    return out


ENCODERS = {
    "base64": lambda p: base64.b64encode(p.encode()).decode(),
    "reverse": lambda p: p[::-1],
    "hex": lambda p: p.encode().hex(),
    "dashes": lambda p: "-".join(p),
}


def encode_as_asked(payload: str, line: str) -> str:
    low = line.lower()
    for name, pattern in K()["encodings"].items():
        if re.search(pattern, low) and name in ENCODERS:
            return ENCODERS[name](payload)
    return payload


def summarize(text: str, n: int | None = None) -> list[str]:
    """A naive summary: the first few plain lines, skipping headers, orders and anything secret-looking."""
    k = K()
    n = n or k["summary_lines"]
    lines = []
    for line in detectors.strip_invisible(text).splitlines():
        s = line.strip()
        greeting = len(s) < k["greeting_max_chars"] and (s.endswith(",") or re.match(k["greeting"], s))
        if not s or greeting or s.startswith(tuple(k["skip_line_prefixes"])) or detectors.find_secrets(s) \
                or any(r.search(s) for r in detectors.instruction_patterns()):
            continue
        lines.append(s)
        if len(lines) >= n:
            break
    return lines


class ScriptedAgent:
    def __init__(self, prompt: str, manifests: Callable[[], list[dict]], files: dict[str, str] | None = None) -> None:
        """`files` maps path -> sensitivity: the agent knows where secrets and reports live, as a real one would."""
        self.prompt = prompt
        self.manifests = manifests
        files = files or {}
        self.secrets_file = next((p for p, s in files.items() if s == "secret"), None)
        self.confidential_files = [p for p, s in files.items() if s == "confidential"]
        self.memory: dict[str, str] = {}      # what it has read: label -> text
        self.notes: list[str] = []            # lines for its final answer
        self.extras: list[str] = []           # things injected text asked it to add to outgoing messages
        self.tool_notes = ""                  # what a tool description asked it to pass along
        self.done: set[tuple] = set()
        self.seen_descriptions: dict[str, str] = {}

    # --- helpers ----------------------------------------------------------

    def _secret_value(self, line: str) -> str | None:
        """The secret an instruction asks for, from what the agent has read."""
        low = line.lower()
        env = self.memory.get(f"file:{self.secrets_file}", "") if self.secrets_file else ""
        if env:
            vals = dict(l.split("=", 1) for l in env.splitlines() if "=" in l and not l.startswith("#"))
            for kind in K()["secret_kinds"]:
                if re.search(kind["pattern"], low):
                    return next((v for k, v in vals.items() if kind["env_key_contains"] in k), None)
            return env
        found = detectors.find_secrets("\n".join(self.memory.values()))
        if found:
            return found[0].split("=", 1)[-1].split(":", 1)[-1].strip()
        return None

    def _confidential_file(self, line: str) -> str | None:
        words = set(re.findall(r"\w+", line.lower()))
        ranked = sorted(self.confidential_files, key=lambda p: -len(words & set(re.findall(r"\w+", p.lower()))))
        return ranked[0] if ranked else None

    def _needs_read(self, line: str) -> str | None:
        """Which file the agent would open to satisfy an instruction."""
        low = line.lower()
        for p in _paths(line):
            if f"file:{p}" not in self.memory:
                return p
        if has("secret", low) and self._secret_value(line) is None:
            return self.secrets_file
        conf = self._confidential_file(line) if has("confidential", low) else None
        if conf and f"file:{conf}" not in self.memory:
            return conf
        return None

    def _payload_for(self, line: str) -> str:
        low = line.lower()
        paths = _paths(line)
        conf = self._confidential_file(line) if has("confidential", low) else None
        if has("secret", low):
            payload = self._secret_value(line) or "(could not get it)"
        elif paths and f"file:{paths[0]}" in self.memory:
            payload = self.memory[f"file:{paths[0]}"]
        elif conf and f"file:{conf}" in self.memory:
            payload = self.memory[f"file:{conf}"]
        else:
            payload = "\n".join(self.notes) or "(nothing)"
        return encode_as_asked(payload, line)

    def _read(self, path: str) -> AgentGen:
        out = yield ("read_file", {"path": path})
        if out is not None:
            self.memory[f"file:{path}"] = out
        return out

    # --- obeying injected text --------------------------------------------

    def obey(self, text: str) -> AgentGen:
        k = K()
        for d in find_directives(text):
            if d.key in self.done:
                continue
            self.done.add(d.key)
            if d.kind in ("send", "post", "visit", "include", "notes"):
                need = self._needs_read(d.line)
                if need:
                    yield from self._read(need)
            if d.kind == "send":
                yield ("send_email", {"to": d.target, "subject": k["reply_subject"], "body": self._payload_for(d.line)})
            elif d.kind == "post":
                yield ("http_post", {"url": d.target, "data": self._payload_for(d.line)})
            elif d.kind == "visit":
                url = d.target
                if k.get("visit_appends_secret") and has("secret", d.line.lower()):
                    url = url + quote(self._payload_for(d.line), safe="")
                yield ("browse", {"url": url})
            elif d.kind == "delete":
                yield ("delete_file", {"path": d.target})
            elif d.kind == "read":
                content = yield from self._read(d.target)
                if content:
                    self.notes.append(f"{d.target}: {content.splitlines()[0]}")
            elif d.kind == "include":
                self.extras.append(self._payload_for(d.line))
            elif d.kind == "notes":
                self.tool_notes = self._payload_for(d.line)
        return ""

    def check_tool_descriptions(self) -> AgentGen:
        """Models read tool descriptions before calling tools, so poisoned ones get obeyed too."""
        for m in self.manifests():
            if self.seen_descriptions.get(m["name"]) != m["description"]:
                self.seen_descriptions[m["name"]] = m["description"]
                yield from self.obey(m["description"])
        return ""

    def after_read(self, label: str, out: str | None) -> AgentGen:
        if out is None:
            return ""
        self.memory[label] = out
        yield from self.obey(out)
        return ""

    # --- the plan ----------------------------------------------------------

    def run(self) -> AgentGen:
        k = K()
        p = self.prompt
        low = p.lower()
        yield from self.check_tool_descriptions()

        user_emails = {e.lower() for e in EMAIL_RE.findall(p)}
        user_urls = [u.rstrip(".,") for u in URL_RE.findall(p)]
        user_paths = _paths(p)
        wants_send = has("user_send", low) and user_emails
        wants_post = has("user_post", low) and user_urls
        wants_delete = has("user_delete", low)

        def delete_target(path: str) -> bool:
            return bool(wants_delete and re.search(k["user_delete_target"].format(path=re.escape(path)), low))

        read_paths = [x for x in user_paths if not delete_target(x)]

        if has("user_inbox", low):
            listing = yield ("read_inbox", {})
            if listing is not None:
                self.memory["inbox"] = listing
                for eid in re.findall(r"id: (\w+)", listing):
                    out = yield ("read_email", {"email_id": eid})
                    if out is not None:
                        subj = re.search(r"Subject: (.*)", out)
                        self.notes.append(f"{subj.group(1) if subj else eid}: "
                                          + " ".join(summarize(out.split("\n\n", 1)[-1], 1)))
                    yield from self.after_read(f"email:{eid}", out)

        if has("user_list_files", low) and not read_paths:
            listing = yield ("list_files", {})
            if listing is not None:
                for path in listing.splitlines()[:k["list_files_max"]]:
                    if path.startswith(tuple(k["list_files_read_prefixes"])):
                        read_paths.append(path)

        for path in read_paths:
            out = yield ("read_file", {"path": path})
            if out is not None:
                self.notes.extend(summarize(out))
            yield from self.after_read(f"file:{path}", out)

        for url in user_urls:
            if wants_post:
                continue
            out = yield ("browse", {"url": url})
            if out is not None:
                self.notes.extend(summarize(out))
            yield from self.after_read(f"web:{url}", out)

        tool = k["weather_tool"]
        for city in re.findall(k["weather_city"], p) if has("user_weather", low) else []:
            yield from self.check_tool_descriptions()
            args = {"city": city}
            if self.tool_notes:
                args[k["notes_param"]] = self.tool_notes
            out = yield (tool, args)
            if out is not None:
                self.notes.append(out)

        body = "\n".join(self.notes + self.extras) or "(nothing to report)"
        if wants_send:
            for to in sorted(user_emails):
                yield ("send_email", {"to": to, "subject": k["summary_subject"], "body": body})
        if wants_post:
            for url in user_urls:
                yield ("http_post", {"url": url, "data": body})
        for path in user_paths:
            if delete_target(path):
                yield ("delete_file", {"path": path})

        return "Here is what I found:\n" + "\n".join(f"- {n}" for n in self.notes) if self.notes else "Done."
