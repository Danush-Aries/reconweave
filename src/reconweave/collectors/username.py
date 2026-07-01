"""Username collector (1): enumerates 40+ platforms from a data file."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

_DATA = Path(__file__).resolve().parent.parent / "data" / "usernames.json"


@lru_cache(maxsize=1)
def load_platforms() -> List[Dict[str, str]]:
    with _DATA.open(encoding="utf-8") as fh:
        return json.load(fh)["platforms"]


@register
class UsernameCollector(Collector):
    name = "username_enum"
    category = "username"
    description = "Checks 40+ platforms for a username (Sherlock-style) and links profiles."
    accepts = (SeedType.USERNAME, SeedType.SOCIAL_HANDLE)
    base_confidence = 0.6

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        uname = value.lstrip("@")
        r = _rng.rng(self.name, uname)
        platforms = load_platforms()
        user = Entity(NodeType.USERNAME, uname, confidence=0.9)
        entities = [user]
        rels = []
        hits = 0
        for p in platforms:
            # Deterministic hit/miss per (username, platform).
            pr = _rng.rng(self.name, uname, p["name"])
            if not _rng.chance(pr, 0.42):
                continue
            hits += 1
            url = p["url_template"].format(username=uname)
            prof = Entity(
                NodeType.SOCIAL_PROFILE, f"{p['name'].lower()}:{uname}",
                confidence=_rng.weighted_confidence(pr, self.base_confidence),
                attributes={"platform": p["name"], "category": p["category"],
                            "url": url, "username": uname},
            )
            entities.append(prof)
            rels.append(Relationship(
                user.id, prof.id, EdgeType.SAME_IDENTITY,
                confidence=self.base_confidence,
                attributes={"platform": p["name"], "url": url}))
        user.attributes["platforms_found"] = hits
        user.attributes["platforms_checked"] = len(platforms)
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"hits": hits, "checked": len(platforms)})
