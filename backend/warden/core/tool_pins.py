"""Tool manifest integrity: pin each tool's definition, flag poisoning and rug pulls."""
from __future__ import annotations

import hashlib
import json

from warden.core.detectors import poisoned_min_flags, scan_description


def fingerprint(manifest: dict) -> str:
    canon = json.dumps({"d": manifest.get("description", ""), "p": manifest.get("params", {})}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


class ToolPins:
    def __init__(self, signer=None, require_signed: bool = False) -> None:
        """signer: a signing.Signer, to also check definitions against the versions you signed."""
        self.pins: dict[str, dict] = {}
        self.signer, self.require_signed = signer, require_signed

    def pin_all(self, manifests: list[dict]) -> None:
        for m in manifests:
            self.pins.setdefault(m["name"], {"hash": fingerprint(m), "description": m.get("description", "")})

    def check(self, manifest: dict) -> list[dict]:
        """Problems with a tool right now: poisoned description or drift from the pin."""
        problems = []
        flags = scan_description(manifest.get("description", ""))
        if len(flags) >= poisoned_min_flags():
            problems.append({"kind": "poisoned_description",
                             "detail": "tool description looks like instructions to the AI: " + "; ".join(flags),
                             "quote": manifest.get("description", "")[:240]})
        pin = self.pins.get(manifest["name"])
        if pin and pin["hash"] != fingerprint(manifest):
            problems.append({"kind": "rug_pull",
                             "detail": f"tool definition changed after it was approved (pinned {pin['hash']}, now {fingerprint(manifest)})",
                             "quote": manifest.get("description", "")[:240]})
        if self.signer is not None:
            problems += self.signer.problems(manifest, self.require_signed)
        return problems

    def report(self, manifests: list[dict]) -> list[dict]:
        out = []
        for m in manifests:
            pin = self.pins.get(m["name"])
            out.append({"name": m["name"], "description": m.get("description", ""),
                        "hash": fingerprint(m), "pinned": pin["hash"] if pin else None,
                        "signature": self.signer.status(m) if self.signer is not None else None,
                        "problems": self.check(m)})
        return out
