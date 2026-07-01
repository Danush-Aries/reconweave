"""People collector (1): person -> emails, usernames, employer, location."""

from __future__ import annotations

from typing import Any, Dict

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

_EMPLOYERS = ["Northwind Labs", "Acme Systems", "Blue Harbor Group", "Vertex Analytics",
              "Meridian Technologies", "Quill Software"]
_TITLES = ["Software Engineer", "Security Analyst", "Product Manager",
           "Data Scientist", "DevOps Engineer", "Researcher"]
_LOCATIONS = ["Austin, US", "Berlin, DE", "Bengaluru, IN", "London, GB",
              "Toronto, CA", "Singapore, SG"]


@register
class PeopleCollector(Collector):
    name = "people"
    category = "people"
    description = "Person enrichment: employer, title, location, emails, aliases."
    accepts = (SeedType.PERSON,)
    base_confidence = 0.5

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        parts = value.split()
        first = parts[0].lower()
        last = parts[-1].lower() if len(parts) > 1 else ""
        employer = _rng.pick(r, _EMPLOYERS)
        title = _rng.pick(r, _TITLES)
        location = _rng.pick(r, _LOCATIONS)

        person = Entity(NodeType.PERSON, value, confidence=self.base_confidence,
                        attributes={"title": title, "location": location,
                                    "employer": employer})
        org = Entity(NodeType.ORG, employer, confidence=0.55,
                     attributes={"role": "employer"})
        entities = [person, org]
        rels = [Relationship(person.id, org.id, EdgeType.MEMBER_OF,
                             confidence=0.55, attributes={"title": title})]

        handle = f"{first}{last}" if last else first
        uname = Entity(NodeType.USERNAME, handle, confidence=0.45,
                       attributes={"derived_from": value})
        entities.append(uname)
        rels.append(Relationship(person.id, uname.id, EdgeType.SAME_IDENTITY,
                                 confidence=0.45, attributes={"method": "name-alias"}))

        edomain = employer.split()[0].lower() + ".com"
        email = Entity(NodeType.EMAIL, f"{first}.{last}@{edomain}" if last else f"{first}@{edomain}",
                       confidence=0.4, attributes={"speculative": True, "type": "work"})
        entities.append(email)
        rels.append(Relationship(person.id, email.id, EdgeType.SAME_IDENTITY,
                                 confidence=0.4, attributes={"method": "work-email-guess"}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"employer": employer, "title": title})
