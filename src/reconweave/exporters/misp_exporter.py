"""MISP event exporter — hand-built valid JSON, no third-party dep.

Produces a single MISP Event with Attributes (one per mappable entity)
and a few Objects for richer types. The structure follows the MISP core
format so it imports via the MISP REST API / UI.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List

from ..entities import NodeType, EdgeType

_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "reconweave.misp")
_DATE = "2026-01-01"

# reconweave node type -> (misp category, misp type)
_ATTR_MAP = {
    NodeType.DOMAIN.value: ("Network activity", "domain"),
    NodeType.SUBDOMAIN.value: ("Network activity", "domain"),
    NodeType.IP.value: ("Network activity", "ip-dst"),
    NodeType.CIDR.value: ("Network activity", "ip-dst"),
    NodeType.EMAIL.value: ("Payload delivery", "email-src"),
    NodeType.USERNAME.value: ("Social network", "github-username"),
    NodeType.SOCIAL_PROFILE.value: ("Social network", "text"),
    NodeType.PERSON.value: ("Attribution", "text"),
    NodeType.ORG.value: ("Attribution", "text"),
    NodeType.ASN.value: ("Network activity", "AS"),
    NodeType.PHONE.value: ("Person", "phone-number"),
    NodeType.CRYPTO_WALLET.value: ("Financial fraud", "btc"),
}


def _det_uuid(key: str) -> str:
    return str(uuid.uuid5(_NS, key))


def build_event(result) -> Dict[str, Any]:
    attributes: List[Dict[str, Any]] = []
    for node in result.graph.nodes():
        mapping = _ATTR_MAP.get(node["type"])
        if mapping is None:
            continue
        category, mtype = mapping
        comment_bits = []
        if node.get("sources"):
            comment_bits.append("sources=" + ",".join(node["sources"]))
        if node.get("confidence") is not None:
            comment_bits.append(f"confidence={round(node['confidence'], 3)}")
        attributes.append({
            "uuid": _det_uuid("attr|" + node["id"]),
            "type": mtype,
            "category": category,
            "to_ids": mtype in ("domain", "ip-dst", "btc", "email-src"),
            "value": str(node["value"]),
            "comment": "; ".join(comment_bits),
            "disable_correlation": False,
        })

    tags = [{"name": f'reconweave:seed-type="{result.seed.type.value}"'},
            {"name": f'reconweave:risk-band="{result.risk.band}"'}]

    event = {
        "Event": {
            "uuid": _det_uuid("event|" + result.seed.value),
            "info": f"reconweave OSINT: {result.seed.value}",
            "date": _DATE,
            "threat_level_id": _threat_level(result.risk.score),
            "analysis": "2",
            "distribution": "0",
            "published": False,
            "Orgc": {"name": "reconweave", "uuid": _det_uuid("org|reconweave")},
            "Attribute": attributes,
            "Tag": tags,
        }
    }
    return event


def _threat_level(score: int) -> str:
    # MISP: 1=high, 2=medium, 3=low, 4=undefined
    if score >= 60:
        return "1"
    if score >= 30:
        return "2"
    if score > 0:
        return "3"
    return "4"


def to_misp(result) -> str:
    return json.dumps(build_event(result), indent=2)


__all__ = ["to_misp", "build_event"]
