"""Shared agent types."""
from __future__ import annotations

from typing import Generator

Call = tuple[str, dict]
AgentGen = Generator[Call, "str | None", str]


class AgentUnavailable(RuntimeError):
    """The chosen agent can't run here (missing SDK, key, or local model)."""
