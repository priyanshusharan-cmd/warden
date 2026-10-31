"""Evidence detectors. These explain *why* content looks dangerous.

They are not the final decision: the policy decides on provenance and sensitivity,
and uses these findings to enrich reasons and risk scores.
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

from warden import config

ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_STYLE = re.compile(r"<[^>]*(?:color:\s*#?fff(?:fff)?\b|display:\s*none|font-size:\s*0)[^>]*>(.*?)</", re.I | re.S)
B64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
PATH_RE = re.compile(r"\b(?:[\w.-]+/)+[\w.-]+\b|\.env\b")



def _flags(f: str) -> int:
    return re.I if "i" in (f or "") else 0


def _patterns() -> dict:
    """Compiled patterns from data/detectors.json, rebuilt only when the file changes."""
    spec = config.load("detectors")
    if _compiled.get("spec") is not spec:
        _compiled.update(
            spec=spec,
            instruction=[re.compile(p, re.I) for p in spec["instruction_cues"]],
            secrets=[re.compile(p) for p in spec["secret_patterns"]],
            flags=[(re.compile(f["pattern"], _flags(f.get("flags"))), f["reason"]) for f in spec["description_red_flags"]],
        )
    return _compiled


_compiled: dict = {}


def instruction_patterns() -> list[re.Pattern]:
    return _patterns()["instruction"]


def poisoned_min_flags() -> int:
    return config.load("detectors").get("poisoned_description_min_flags", 2)


def strip_invisible(text: str) -> str:
    return ZERO_WIDTH.sub("", text)


def decode_candidates(text: str) -> list[tuple[str, str]]:
    """Return (encoding, decoded_text) for every decodable blob in text."""
    out: list[tuple[str, str]] = []
    for m in B64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            dec = raw.decode("utf-8")
            if dec.isprintable() or "\n" in dec:
                out.append(("base64", dec))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    for m in HEX_BLOB.finditer(text):
        try:
            out.append(("hex", bytes.fromhex(m.group(0)).decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            pass
    if "%" in text:
        dec = unquote(unquote(text))
        if dec != text:
            out.append(("url-encoding", dec))
    return out


def scan_content(text: str) -> list[dict]:
    """Findings for a piece of untrusted content, each with a line number and quote."""
    findings: list[dict] = []
    if ZERO_WIDTH.search(text):
        findings.append({"kind": "hidden_text", "detail": "zero-width characters hide text", "line": None, "quote": ""})
    for m in HTML_COMMENT.finditer(text):
        findings.append({"kind": "hidden_text", "detail": "instruction hidden in an HTML comment",
                         "line": text[:m.start()].count("\n") + 1, "quote": m.group(1).strip()[:160]})
    for m in HIDDEN_STYLE.finditer(text):
        findings.append({"kind": "hidden_text", "detail": "text styled to be invisible",
                         "line": text[:m.start()].count("\n") + 1, "quote": m.group(1).strip()[:160]})
    for enc, dec in decode_candidates(text):
        if any(r.search(dec) for r in instruction_patterns()):
            findings.append({"kind": "encoded_instruction", "detail": f"{enc}-encoded instruction",
                             "line": None, "quote": dec.strip()[:160]})
    clean = strip_invisible(text)
    for i, line in enumerate(clean.splitlines(), 1):
        for r in instruction_patterns():
            if r.search(line):
                findings.append({"kind": "instruction", "detail": "text gives orders to the AI",
                                 "line": i, "quote": line.strip()[:160]})
                break
    return findings


def find_secrets(text: str) -> list[str]:
    return [m.group(0) for p in _patterns()["secrets"] for m in p.finditer(text)]


def scan_description(description: str) -> list[str]:
    return [why for rx, why in _patterns()["flags"] if rx.search(description)]
