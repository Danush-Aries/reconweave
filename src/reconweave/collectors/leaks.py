"""Leaks collector (1): paste-site / combolist mentions of a seed.

This is the offline stand-in for a real leak/dark-web intel source
(e.g. plug in the author's breachintel / leakradar / darkweb-intel).
"""

from __future__ import annotations

from typing import Any, Dict

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

_SITES = ["pastebin", "ghostbin", "throwbin", "combolist-forum", "telegram-dump"]
_LEAK_KINDS = ["credential-dump", "combolist", "config-leak", "cookie-dump", "paste"]


@register
class LeaksCollector(Collector):
    name = "leaks"
    category = "leaks"
    description = "Paste-site / combolist mentions (offline stand-in for dark-web intel)."
    accepts = (SeedType.EMAIL, SeedType.USERNAME, SeedType.DOMAIN,
               SeedType.CRYPTO_WALLET, SeedType.PHONE)
    base_confidence = 0.5

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        subject_type = {
            SeedType.EMAIL: NodeType.EMAIL,
            SeedType.USERNAME: NodeType.USERNAME,
            SeedType.DOMAIN: NodeType.DOMAIN,
            SeedType.CRYPTO_WALLET: NodeType.CRYPTO_WALLET,
            SeedType.PHONE: NodeType.PHONE,
        }[seed_type]
        subject = Entity(subject_type, value.lstrip("@"), confidence=0.9)
        entities = [subject]
        rels = []
        n = r.randint(0, 3)
        for _ in range(n):
            site = _rng.pick(r, _SITES)
            kind = _rng.pick(r, _LEAK_KINDS)
            date = _rng.iso_date(r, 2020, 2024)
            ref = _rng.fingerprint(f"{value}{site}{date}", 8)
            leak = Entity(NodeType.ORG, f"leak:{site}/{ref}",
                          confidence=self.base_confidence, first_seen=date,
                          attributes={"kind": "leak", "site": site,
                                      "leak_type": kind, "date": date, "ref": ref})
            entities.append(leak)
            rels.append(Relationship(subject.id, leak.id, EdgeType.APPEARS_IN_BREACH,
                                     confidence=self.base_confidence,
                                     attributes={"site": site, "leak_type": kind,
                                                 "date": date}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"mentions": n})
