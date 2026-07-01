"""Email collectors (4): breach (HIBP-style), deliverability,
permutation, gravatar."""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

_BREACHES = [
    ("Collection#1", 2019, ["email", "password"]),
    ("LinkedIn", 2016, ["email", "password", "username"]),
    ("Dropbox", 2016, ["email", "password"]),
    ("Adobe", 2013, ["email", "password", "password_hint"]),
    ("Canva", 2019, ["email", "username", "geo"]),
    ("MyFitnessPal", 2018, ["email", "username", "password"]),
    ("Twitter", 2022, ["email", "phone", "username"]),
    ("Wattpad", 2020, ["email", "username", "ip"]),
    ("Deezer", 2019, ["email", "username", "dob"]),
]
_DISPOSABLE = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org"]


def _split(email: str):
    local, _, domain = email.partition("@")
    return local, domain


@register
class BreachCollector(Collector):
    name = "breach"
    category = "email"
    description = "Breach exposure (Have-I-Been-Pwned style) for an email."
    accepts = (SeedType.EMAIL,)
    base_confidence = 0.85

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        email = Entity(NodeType.EMAIL, value, confidence=0.95)
        entities = [email]
        rels = []
        n = r.randint(0, 5)
        chosen = _rng.sample(r, _BREACHES, n)
        for bname, year, classes in chosen:
            # Model a breach as an org node the email appears in.
            b = Entity(NodeType.ORG, f"breach:{bname}",
                       confidence=self.base_confidence,
                       first_seen=f"{year}-01-01",
                       attributes={"kind": "breach", "name": bname, "year": year,
                                   "data_classes": classes})
            entities.append(b)
            rels.append(Relationship(email.id, b.id, EdgeType.APPEARS_IN_BREACH,
                                     confidence=self.base_confidence,
                                     attributes={"breach": bname, "year": year,
                                                 "data_classes": classes}))
        email.attributes["breach_count"] = n
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"breaches": [b for b, _, _ in chosen]})


@register
class DeliverabilityCollector(Collector):
    name = "deliverability"
    category = "email"
    description = "MX / SMTP / disposable / role-account signals for an email."
    accepts = (SeedType.EMAIL,)
    base_confidence = 0.7

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        local, domain = _split(value)
        r = _rng.rng(self.name, value)
        disposable = domain in _DISPOSABLE or _rng.chance(r, 0.05)
        role = local in {"admin", "info", "support", "contact", "sales", "no-reply"}
        email = Entity(NodeType.EMAIL, value, confidence=0.9,
                       attributes={
                           "mx_found": not disposable,
                           "smtp_deliverable": (not disposable) and _rng.chance(r, 0.85),
                           "disposable": disposable,
                           "role_account": role,
                           "mx_host": f"mx1.{domain}",
                       })
        return CollectorResult([email], [], self.name, self.base_confidence,
                               raw={"disposable": disposable, "role": role})


@register
class PermutationCollector(Collector):
    name = "permutation"
    category = "email"
    description = "Generates likely email/username permutations from a seed."
    accepts = (SeedType.EMAIL, SeedType.PERSON, SeedType.USERNAME)
    base_confidence = 0.4

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        entities = []
        rels = []
        if seed_type == SeedType.EMAIL:
            local, domain = _split(value)
            root = Entity(NodeType.EMAIL, value, confidence=0.9)
            seeds = {local, local.replace(".", ""), local.split(".")[0]}
            for cand in sorted(seeds):
                if not cand:
                    continue
                u = Entity(NodeType.USERNAME, cand,
                           confidence=self.base_confidence,
                           attributes={"derived_from": value})
                entities.append(u)
                rels.append(Relationship(root.id, u.id, EdgeType.SAME_IDENTITY,
                                         confidence=self.base_confidence,
                                         attributes={"method": "email-localpart"}))
            entities.insert(0, root)
        else:
            base = value.lower().replace(" ", ".")
            first = value.split()[0].lower() if " " in value else value.lower()
            last = value.split()[-1].lower() if " " in value else ""
            patterns = {base, f"{first}{last}", f"{first[0]}{last}" if last else first}
            for domain in ["gmail.com", "outlook.com"]:
                for p in sorted(patterns):
                    if not p:
                        continue
                    cand = f"{p}@{domain}"
                    e = Entity(NodeType.EMAIL, cand, confidence=self.base_confidence,
                               attributes={"derived_from": value, "speculative": True})
                    entities.append(e)
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"candidates": len(entities)})


@register
class GravatarCollector(Collector):
    name = "gravatar"
    category = "email"
    description = "Gravatar profile + avatar hash for an email."
    accepts = (SeedType.EMAIL,)
    base_confidence = 0.6

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        norm = value.strip().lower()
        ghash = hashlib.md5(norm.encode()).hexdigest()  # noqa: S324 (gravatar spec)
        r = _rng.rng(self.name, value)
        has_profile = _rng.chance(r, 0.45)
        email = Entity(NodeType.EMAIL, value, confidence=0.9,
                       attributes={"gravatar_hash": ghash,
                                   "gravatar_url": f"https://www.gravatar.com/avatar/{ghash}",
                                   "gravatar_profile": has_profile})
        entities = [email]
        rels = []
        if has_profile:
            display = _rng.pick(r, ["nimble.fox", "quiet.harbor", "urban.spark",
                                    "silver.lynx", "brave.otter"])
            prof = Entity(NodeType.SOCIAL_PROFILE, f"gravatar:{display}",
                          confidence=self.base_confidence,
                          attributes={"platform": "gravatar", "display_name": display})
            entities.append(prof)
            rels.append(Relationship(email.id, prof.id, EdgeType.SAME_IDENTITY,
                                     confidence=self.base_confidence,
                                     attributes={"platform": "gravatar"}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"gravatar_hash": ghash, "profile": has_profile})
