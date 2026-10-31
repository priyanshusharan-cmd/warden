"""Provenance ledger: remembers everything the agent has seen and where it came from.

CaMeL tracks provenance inside its own interpreter. Warden cannot see inside the model,
so it recovers provenance from the outside: when a tool call arrives, each argument is
looked up in the ledger of labeled content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from warden.core import detectors
from warden.core.labels import SENSITIVITY_RANK, Label


def _norm(s: str) -> str:
    return detectors.strip_invisible(s).strip().lower()


def _compact(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _norm(s))


# A value only counts as "seen" when it appears whole: "bob@x" is not inside "jimbob@x", and
# "https://site/api" is not inside "https://site/api/v2". Trailing sentence punctuation is fine.
_VALUE_CHARS = r"[\w%+@/~=&#-]"


def _contains_whole(hay: str, needle: str) -> bool:
    pattern = rf"(?<!{_VALUE_CHARS})(?<![\w-]\.){re.escape(needle)}(?!{_VALUE_CHARS}|\.[\w-])"
    return re.search(pattern, hay) is not None


@dataclass
class Segment:
    id: str
    text: str
    label: Label
    findings: list[dict] = field(default_factory=list)
    decoded: str = ""   # decoded base64 / hex / url-encoded blobs, searched like the text

    @property
    def searchable(self) -> str:
        return self.text + ("\n" + self.decoded if self.decoded else "")

    def to_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "label": self.label.to_dict(), "findings": self.findings}


@dataclass
class SensitiveItem:
    value: str
    sensitivity: str
    segment_id: str
    origin: str


class Ledger:
    def __init__(self) -> None:
        self.segments: list[Segment] = []
        self.sensitive: list[SensitiveItem] = []

    def add(self, text: str, label: Label) -> Segment:
        seg = Segment(f"s{len(self.segments) + 1}", text, label)
        if not label.trusted:
            seg.findings = detectors.scan_content(text)
            seg.decoded = "\n".join(dec for _, dec in detectors.decode_candidates(text))
        self.segments.append(seg)
        self._index_sensitive(seg)
        return seg

    def _index_sensitive(self, seg: Segment) -> None:
        rank = SENSITIVITY_RANK.get(seg.label.sensitivity, 0)
        values: set[str] = set()
        if rank >= SENSITIVITY_RANK["secret"]:
            for line in seg.text.splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    values.add(line.split("=", 1)[1].strip())
        if rank >= SENSITIVITY_RANK["confidential"]:
            values.update(l.strip() for l in seg.text.splitlines() if len(l.strip()) >= 16)
        for s in detectors.find_secrets(seg.text):
            values.add(s.split("=", 1)[-1].strip() if "=" in s else s)
        for v in values:
            if len(v) >= 6:
                sens = seg.label.sensitivity if rank >= 2 else "secret"
                self.sensitive.append(SensitiveItem(v, sens, seg.id, seg.label.origin))

    # --- lookups ----------------------------------------------------------

    def origin_of(self, value: str) -> dict:
        """Classify where an argument value came from: trusted, tainted or unknown."""
        needle = _norm(value)
        if not needle:
            return {"status": "trusted", "evidence": []}
        trusted_hits, tainted_hits = [], []
        for seg in self.segments:
            hay = _norm(seg.searchable)
            if not _contains_whole(hay, needle):
                continue
            hit = self._evidence(seg, needle)
            (trusted_hits if seg.label.trusted else tainted_hits).append(hit)
        if trusted_hits:
            return {"status": "trusted", "evidence": trusted_hits}
        if tainted_hits:
            tainted_hits.sort(key=lambda h: not h["injection"])  # injected sources first
            return {"status": "tainted", "evidence": tainted_hits}
        return {"status": "unknown", "evidence": []}

    def _evidence(self, seg: Segment, needle: str) -> dict:
        line_no, quote = None, ""
        flagged = {f["line"] for f in seg.findings if f.get("line")}
        for i, line in enumerate(detectors.strip_invisible(seg.searchable).splitlines(), 1):
            if _contains_whole(line.lower(), needle):
                if line_no is None or i in flagged:
                    line_no, quote = i, line.strip()[:200]
                if i in flagged:  # prefer the line carrying the injected instruction
                    break
        return {"segment": seg.id, "origin": seg.label.origin, "line": line_no, "quote": quote,
                "injection": bool(seg.findings), "findings": seg.findings[:3]}

    def sensitive_in(self, text: str) -> list[dict]:
        """Find sensitive material inside text, including common obfuscations."""
        variants = {"verbatim": _norm(text), "separators removed": _compact(text),
                    "reversed": _compact(text)[::-1]}
        for enc, dec in detectors.decode_candidates(text):
            variants[f"{enc} decoded"] = _compact(dec)
        hits, seen = [], set()
        for item in self.sensitive:
            raw, comp = _norm(item.value), _compact(item.value)
            for how, hay in variants.items():
                if not hay:
                    continue
                if (how == "verbatim" and raw in hay) or (len(comp) >= 10 and comp in hay):
                    if item.value not in seen:
                        seen.add(item.value)
                        hits.append({"sensitivity": item.sensitivity, "origin": item.origin,
                                     "encoding": how,
                                     # secrets are masked; confidential lines are shown so the reviewer can judge
                                     "preview": item.value[:6] + "…" if item.sensitivity == "secret" else item.value[:120]})
                    break
        return hits

    def to_list(self) -> list[dict]:
        return [s.to_dict() for s in self.segments]
