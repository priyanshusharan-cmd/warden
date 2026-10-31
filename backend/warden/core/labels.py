"""Labels attached to every piece of content Warden sees."""
from __future__ import annotations

from dataclasses import dataclass

SENSITIVITY_RANK = {"public": 0, "internal": 1, "confidential": 2, "secret": 3}


@dataclass(frozen=True)
class Label:
    trust: str          # "trusted" (typed by the user) or "untrusted"
    sensitivity: str    # public | internal | confidential | secret
    origin: str         # human readable pointer, e.g. "email:e4 from x@y"

    @property
    def trusted(self) -> bool:
        return self.trust == "trusted"

    def to_dict(self) -> dict:
        return {"trust": self.trust, "sensitivity": self.sensitivity, "origin": self.origin}
