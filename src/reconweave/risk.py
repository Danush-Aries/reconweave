"""Explained 0-100 exposure score.

Risk is the sum of weighted, capped factors — each with a human-readable
explanation — normalized to 0-100 and mapped to a band. The point is that
every score is auditable: you can see *why* an entity is exposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .entities import EdgeType, NodeType
from .graph import ReconGraph


@dataclass
class RiskFactor:
    name: str
    points: float
    detail: str
    weight: float

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "points": round(self.points, 1),
                "detail": self.detail, "weight": self.weight}


@dataclass
class RiskScore:
    score: int
    band: str
    factors: List[RiskFactor] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "factors": [f.to_dict() for f in self.factors],
        }


def _band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


# factor -> (weight per unit, cap points)
_WEIGHTS = {
    "breaches": (9.0, 36.0),
    "leaks": (7.0, 21.0),
    "exposed_services": (4.0, 20.0),
    "subdomain_sprawl": (1.2, 12.0),
    "social_footprint": (0.8, 12.0),
    "email_exposure": (3.0, 12.0),
    "geo_pinpoint": (5.0, 5.0),
    "crypto_exposure": (4.0, 8.0),
}


def compute_risk(graph: ReconGraph) -> RiskScore:
    factors: List[RiskFactor] = []
    nodes = graph.nodes()
    edges = graph.edges()

    # Breaches (org nodes tagged kind=breach + appears_in_breach edges).
    breach_nodes = [n for n in nodes
                    if n["type"] == NodeType.ORG.value
                    and n.get("attributes", {}).get("kind") == "breach"]
    if breach_nodes:
        w, cap = _WEIGHTS["breaches"]
        pts = min(cap, w * len(breach_nodes))
        names = ", ".join(sorted(n["attributes"]["name"] for n in breach_nodes)[:5])
        factors.append(RiskFactor("Credential breaches", pts,
                                   f"{len(breach_nodes)} breach(es): {names}", w))

    # Leak-site mentions.
    leak_nodes = [n for n in nodes
                  if n["type"] == NodeType.ORG.value
                  and n.get("attributes", {}).get("kind") == "leak"]
    if leak_nodes:
        w, cap = _WEIGHTS["leaks"]
        pts = min(cap, w * len(leak_nodes))
        factors.append(RiskFactor("Leak / paste mentions", pts,
                                   f"{len(leak_nodes)} paste/combolist mention(s)", w))

    # Exposed services (open ports across IPs).
    total_ports = 0
    risky = []
    for n in nodes:
        if n["type"] == NodeType.IP.value:
            ports = n.get("attributes", {}).get("open_ports", [])
            total_ports += len(ports)
            for p in ports:
                if p.get("service") in ("mysql", "redis", "ftp"):
                    risky.append(f"{p['service']}:{p['port']}")
    if total_ports:
        w, cap = _WEIGHTS["exposed_services"]
        pts = min(cap, w * len(risky) + 1.0 * total_ports)
        pts = min(cap, pts)
        detail = f"{total_ports} open port(s)"
        if risky:
            detail += f"; sensitive: {', '.join(sorted(set(risky)))}"
        factors.append(RiskFactor("Exposed network services", pts, detail, w))

    # Subdomain sprawl.
    subs = [n for n in nodes if n["type"] == NodeType.SUBDOMAIN.value]
    if subs:
        w, cap = _WEIGHTS["subdomain_sprawl"]
        pts = min(cap, w * len(subs))
        factors.append(RiskFactor("Attack surface (subdomains)", pts,
                                   f"{len(subs)} subdomain(s) discovered", w))

    # Social footprint (profiles + usernames).
    profiles = [n for n in nodes if n["type"] == NodeType.SOCIAL_PROFILE.value]
    if profiles:
        w, cap = _WEIGHTS["social_footprint"]
        pts = min(cap, w * len(profiles))
        factors.append(RiskFactor("Social / identity footprint", pts,
                                   f"{len(profiles)} linked profile(s)/artifact(s)", w))

    # Email exposure.
    emails = [n for n in nodes if n["type"] == NodeType.EMAIL.value]
    if emails:
        w, cap = _WEIGHTS["email_exposure"]
        pts = min(cap, w * len(emails))
        factors.append(RiskFactor("Email exposure", pts,
                                   f"{len(emails)} email address(es) in graph", w))

    # Geo pinpoint (any IP with coordinates).
    geo = [n for n in nodes if n["type"] == NodeType.IP.value
           and "latitude" in n.get("attributes", {})]
    if geo:
        w, cap = _WEIGHTS["geo_pinpoint"]
        factors.append(RiskFactor("Geolocation pinpoint", cap,
                                   f"{len(geo)} IP(s) geolocated to city level", w))

    # Crypto exposure.
    wallets = [n for n in nodes if n["type"] == NodeType.CRYPTO_WALLET.value]
    if wallets:
        w, cap = _WEIGHTS["crypto_exposure"]
        pts = min(cap, w * len(wallets))
        factors.append(RiskFactor("Crypto wallet exposure", pts,
                                   f"{len(wallets)} wallet(s) clustered", w))

    raw = sum(f.points for f in factors)
    score = int(round(min(100.0, raw)))
    return RiskScore(score=score, band=_band(score), factors=factors)


__all__ = ["RiskScore", "RiskFactor", "compute_risk"]
