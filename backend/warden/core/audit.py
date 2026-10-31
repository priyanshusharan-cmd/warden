"""Append-only, hash-chained audit log. Editing any entry breaks every later hash."""
from __future__ import annotations

import hashlib
import json
import threading
import time

GENESIS = "0" * 64
ENTRY_KEYS = ("seq", "ts", "event", "data", "prev_hash", "hash")


def _digest(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        """With a path, every entry is also appended to that file as one JSON line, as it happens."""
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        self.path = path

    @classmethod
    def from_jsonl(cls, text: str) -> "AuditLog":
        """Load a saved log (one entry per line). Raises ValueError on lines that aren't entries."""
        log = cls()
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f"line {n} is not JSON") from None
            if not isinstance(e, dict) or not all(k in e for k in ENTRY_KEYS):
                raise ValueError(f"line {n} is not an audit entry")
            log.entries.append({k: e[k] for k in ENTRY_KEYS})
        return log

    def append(self, event: str, **data) -> dict:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            body = {"seq": len(self.entries) + 1, "ts": round(time.time(), 3), "event": event, "data": data}
            entry = {**body, "prev_hash": prev, "hash": _digest(prev, body)}
            self.entries.append(entry)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return entry

    def verify(self) -> dict:
        prev = GENESIS
        for e in self.entries:
            body = {k: e[k] for k in ("seq", "ts", "event", "data")}
            if e["prev_hash"] != prev or e["hash"] != _digest(prev, body):
                return {"ok": False, "broken_at": e["seq"], "total": len(self.entries)}
            prev = e["hash"]
        return {"ok": True, "broken_at": None, "total": len(self.entries)}

    def tamper(self, seq: int) -> bool:
        """Demo only: silently edit an entry, the way an attacker covering tracks would."""
        for e in self.entries:
            if e["seq"] == seq:
                e["data"] = {**e["data"], "verdict": "allow", "tampered": True}
                return True
        return False
