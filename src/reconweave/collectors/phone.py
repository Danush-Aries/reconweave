"""Phone collector (1): carrier, region, line type, linked identities."""

from __future__ import annotations

import re
from typing import Any, Dict

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

_CARRIERS = ["Verizon", "AT&T", "T-Mobile", "Vodafone", "Airtel", "Orange", "Jio"]
_LINE_TYPES = ["mobile", "fixed-line", "voip"]
_REGIONS = {
    "1": ("US/CA", "North America"), "44": ("GB", "United Kingdom"),
    "49": ("DE", "Germany"), "91": ("IN", "India"), "65": ("SG", "Singapore"),
    "33": ("FR", "France"),
}


@register
class PhoneCollector(Collector):
    name = "phone"
    category = "phone"
    description = "Phone intelligence: carrier, country, line type, linked accounts."
    accepts = (SeedType.PHONE,)
    base_confidence = 0.55

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        digits = re.sub(r"\D", "", value)
        r = _rng.rng(self.name, digits)
        cc = "1"
        for code in ("91", "44", "49", "65", "33", "1"):
            if digits.startswith(code):
                cc = code
                break
        region, region_name = _REGIONS.get(cc, ("??", "Unknown"))
        carrier = _rng.pick(r, _CARRIERS)
        line = _rng.pick(r, _LINE_TYPES)
        phone = Entity(NodeType.PHONE, value, confidence=self.base_confidence,
                       attributes={"country_code": cc, "region": region,
                                   "region_name": region_name, "carrier": carrier,
                                   "line_type": line,
                                   "spam_score": round(r.uniform(0, 1), 2)})
        entities = [phone]
        rels = []
        # Sometimes a phone is linked to a messaging/social profile.
        if _rng.chance(r, 0.5):
            handle = "user" + digits[-4:]
            prof = Entity(NodeType.SOCIAL_PROFILE, f"telegram:{handle}",
                          confidence=0.4,
                          attributes={"platform": "Telegram", "username": handle})
            entities.append(prof)
            rels.append(Relationship(phone.id, prof.id, EdgeType.LINKED_TO,
                                     confidence=0.4, attributes={"platform": "Telegram"}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"carrier": carrier, "line_type": line})
