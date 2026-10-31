"""Task contract: least-privilege permissions derived from the user's request."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from warden import config
from warden.core.detectors import EMAIL_RE, PATH_RE, URL_RE



def intents() -> list[tuple[str, set[str]]]:
    """Request patterns and the tools they allow, from data/contract.json."""
    return [(i["pattern"], set(i["tools"])) for i in config.load("contract")["intents"]]


@dataclass
class Contract:
    prompt: str
    tools: set[str] = field(default_factory=set)
    recipients: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"tools": sorted(self.tools), "recipients": sorted(self.recipients),
                "urls": sorted(self.urls), "paths": sorted(self.paths)}


def derive(prompt: str) -> Contract:
    c = Contract(prompt)
    low = prompt.lower()
    neg = config.load("contract").get("negation")
    granting = re.sub(neg + r"(?:send|forward|reply|post|upload|delete|remove|erase|email|share|publish)\w*", " ", low) if neg else low
    for pattern, tools in intents():
        if re.search(pattern, granting):
            c.tools |= tools
    c.recipients = {m.lower() for m in EMAIL_RE.findall(prompt)}
    c.urls = {m.rstrip(".,") for m in URL_RE.findall(prompt)}
    no_urls = URL_RE.sub(" ", prompt)
    no_emails = EMAIL_RE.sub(" ", no_urls)
    c.paths = {m for m in PATH_RE.findall(no_emails)}
    if c.paths:
        c.tools |= {"read_file"}
    if c.urls:
        c.tools |= {"browse"}
    return c
