"""TOML configuration loading.

Config is optional: sensible offline-first defaults are used when no file
is present. ``reconweave.toml`` at the repo root is the canonical example.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # Python 3.11+
    import tomllib as _toml  # type: ignore

    def _load(fh):  # bytes
        return _toml.load(fh)
except ModuleNotFoundError:  # pragma: no cover
    import tomli as _toml  # type: ignore

    def _load(fh):
        return _toml.load(fh)


@dataclass
class Config:
    live: bool = False
    cache_path: str = ".reconweave-cache.db"
    rate_limit_per_sec: float = 20.0
    max_concurrency: int = 8
    enabled_collectors: List[str] = field(default_factory=list)  # empty = all
    disabled_collectors: List[str] = field(default_factory=list)
    output_dir: str = "out"
    watch_db: str = "reconweave-watch.db"

    def is_enabled(self, name: str) -> bool:
        if name in self.disabled_collectors:
            return False
        if self.enabled_collectors:
            return name in self.enabled_collectors
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "live": self.live,
            "cache_path": self.cache_path,
            "rate_limit_per_sec": self.rate_limit_per_sec,
            "max_concurrency": self.max_concurrency,
            "enabled_collectors": self.enabled_collectors,
            "disabled_collectors": self.disabled_collectors,
            "output_dir": self.output_dir,
            "watch_db": self.watch_db,
        }


def load_config(path: Optional[str] = None) -> Config:
    cfg = Config()
    candidates = []
    if path:
        candidates.append(Path(path))
    else:
        candidates.append(Path.cwd() / "reconweave.toml")
        env = os.environ.get("RECONWEAVE_CONFIG")
        if env:
            candidates.append(Path(env))
    for candidate in candidates:
        if candidate and candidate.is_file():
            with candidate.open("rb") as fh:
                data = _load(fh)
            section = data.get("reconweave", data)
            for key in cfg.__dataclass_fields__:
                if key in section:
                    setattr(cfg, key, section[key])
            collectors = data.get("collectors", {})
            if "enabled" in collectors:
                cfg.enabled_collectors = list(collectors["enabled"])
            if "disabled" in collectors:
                cfg.disabled_collectors = list(collectors["disabled"])
            break
    return cfg


__all__ = ["Config", "load_config"]
