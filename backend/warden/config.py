"""Project paths, and loading of Warden's data and settings files. Nothing descriptive is hardcoded in the code.

Each `data/<name>.json` can be overridden by `data/<name>.local.json` (written when you
edit your own data in the console). Files are re-read when they change on disk.
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # the project folder (backend/warden/config.py)
BACKEND_DIR = ROOT / "backend"
FRONTEND_DIR = ROOT / "frontend"
CONFIG_DIR = ROOT / "config"
DATA_DIR = Path(os.environ.get("WARDEN_DATA_DIR", ROOT / "data"))
SETTINGS_PATH = Path(os.environ.get("WARDEN_SETTINGS", CONFIG_DIR / "settings.json"))
POLICY_PATH = CONFIG_DIR / "policy.json"

_cache: dict[Path, tuple[float, object]] = {}
_lock = threading.Lock()
_TEMPLATE = re.compile(r"\{(secret|base64|zw):([^{}]*)\}")


class DataError(Exception):
    pass


def _read(path: Path):
    try:
        mtime = path.stat().st_mtime
    except OSError as e:
        raise DataError(f"missing data file {path}") from e
    with _lock:
        hit = _cache.get(path)
        if hit and hit[0] == mtime:
            return hit[1]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise DataError(f"cannot read {path}: {e}") from e
        _cache[path] = (mtime, value)
        return value


def local_path(name: str) -> Path:
    return DATA_DIR / f"{name}.local.json"


def load(name: str):
    """data/<name>.local.json if you've saved your own, else data/<name>.json."""
    local = local_path(name)
    return _read(local if local.exists() else DATA_DIR / f"{name}.json")


def load_default(name: str):
    return _read(DATA_DIR / f"{name}.json")


def save_local(name: str, value) -> None:
    path = local_path(name)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def reset_local(name: str) -> None:
    local_path(name).unlink(missing_ok=True)


def settings() -> dict:
    return _read(SETTINGS_PATH)


def render(text: str, secrets: dict[str, str]) -> str:
    """Fill templates: {secret:KEY}, {base64:text}, {zw:text} (zero-width characters between letters)."""
    def sub(m: re.Match) -> str:
        kind, arg = m.group(1), m.group(2)
        if kind == "secret":
            return secrets.get(arg, m.group(0))
        if kind == "base64":
            return base64.b64encode(arg.encode()).decode()
        return "​".join(arg)
    return _TEMPLATE.sub(sub, text)
