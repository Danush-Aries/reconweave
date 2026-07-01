"""Pluggable collector registry.

Every collector is a small class registered with :func:`register`. The
engine asks the registry which collectors accept a given seed type and
runs them. Importing this package populates the registry as a side
effect of importing the collector modules below.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .base import Collector, CollectorResult, register, REGISTRY  # noqa: F401

# Import collector modules for their registration side effects.
from . import infra  # noqa: F401,E402
from . import email as email_collectors  # noqa: F401,E402
from . import username as username_collectors  # noqa: F401,E402
from . import people as people_collectors  # noqa: F401,E402
from . import phone as phone_collectors  # noqa: F401,E402
from . import leaks as leaks_collectors  # noqa: F401,E402
from . import crypto as crypto_collectors  # noqa: F401,E402
from . import media as media_collectors  # noqa: F401,E402


def all_collectors() -> List[Collector]:
    """All registered collector instances (sorted by name)."""
    return [REGISTRY[name] for name in sorted(REGISTRY)]


def get_collector(name: str) -> Optional[Collector]:
    return REGISTRY.get(name)


def collectors_for(seed_type, include_live: bool = False) -> List[Collector]:
    """Collectors that accept ``seed_type``.

    ``include_live`` controls whether ``--live`` collectors are eligible;
    by default only offline mock collectors are returned.
    """
    out = []
    for c in all_collectors():
        if not c.supports(seed_type):
            continue
        if c.live and not include_live:
            continue
        out.append(c)
    return out


def catalog() -> List[Dict]:
    """Machine-readable catalog of every collector (for docs / CLI)."""
    rows = []
    for c in all_collectors():
        rows.append(
            {
                "name": c.name,
                "category": c.category,
                "accepts": [s.value for s in c.accepts],
                "live": c.live,
                "description": c.description,
            }
        )
    return rows


__all__ = [
    "Collector",
    "CollectorResult",
    "register",
    "REGISTRY",
    "all_collectors",
    "get_collector",
    "collectors_for",
    "catalog",
]
