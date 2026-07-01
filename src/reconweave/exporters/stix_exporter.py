"""STIX 2.1 bundle exporter — hand-built valid JSON, no third-party dep.

Entities map to STIX Cyber-observable Objects (SCOs) / Domain Objects
(SDOs); reconweave edges map to STIX ``relationship`` SROs. Ids are
deterministic (uuid5) so the same graph always yields the same bundle —
important for reproducible examples and tests.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from ..entities import NodeType, EdgeType

# Stable namespace for deterministic STIX ids.
_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "reconweave.osint")

_FIXED_TS = "2026-01-01T00:00:00.000Z"

# reconweave node type -> (stix type, value property)
_NODE_MAP = {
    NodeType.DOMAIN.value: ("domain-name", "value"),
    NodeType.SUBDOMAIN.value: ("domain-name", "value"),
    NodeType.IP.value: ("ipv4-addr", "value"),
    NodeType.CIDR.value: ("ipv4-addr", "value"),
    NodeType.EMAIL.value: ("email-addr", "value"),
    NodeType.USERNAME.value: ("user-account", "account_login"),
    NodeType.SOCIAL_PROFILE.value: ("user-account", "account_login"),
    NodeType.PERSON.value: ("identity", "name"),
    NodeType.ORG.value: ("identity", "name"),
    NodeType.ASN.value: ("autonomous-system", "number"),
    NodeType.PHONE.value: ("user-account", "account_login"),
    NodeType.CRYPTO_WALLET.value: ("x-crypto-wallet", "address"),
}

# reconweave edge type -> STIX relationship_type
_REL_MAP = {
    EdgeType.OWNS.value: "owns",
    EdgeType.RESOLVES_TO.value: "resolves-to",
    EdgeType.SUBDOMAIN_OF.value: "belongs-to",
    EdgeType.MEMBER_OF.value: "member-of",
    EdgeType.APPEARS_IN_BREACH.value: "related-to",
    EdgeType.SAME_IDENTITY.value: "duplicate-of",
    EdgeType.CONTROLS.value: "controls",
    EdgeType.LINKED_TO.value: "related-to",
}


def _det_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(_NS, stix_type + '|' + key)}"


def _sco(stix_type: str, prop: str, node: Dict[str, Any]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": _det_id(stix_type, node["id"]),
    }
    value = node["value"]
    if stix_type == "autonomous-system":
        num = "".join(ch for ch in str(value) if ch.isdigit()) or "0"
        obj["number"] = int(num)
    elif stix_type == "identity":
        obj["name"] = value
        obj["identity_class"] = ("organization"
                                 if node["type"] == NodeType.ORG.value else "individual")
        obj["created"] = _FIXED_TS
        obj["modified"] = _FIXED_TS
    else:
        obj[prop] = value
    labels = node.get("sources", [])
    if labels and stix_type not in ("identity",):
        # SCOs don't take labels in 2.1 core; keep provenance as extension.
        obj["x_reconweave_sources"] = labels
        obj["x_reconweave_confidence"] = round(node.get("confidence", 0.0), 3)
    return obj


def build_bundle(result) -> Dict[str, Any]:
    objects: List[Dict[str, Any]] = []
    id_index: Dict[str, str] = {}

    # Identity representing the tool itself.
    tool_identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _det_id("identity", "reconweave-tool"),
        "created": _FIXED_TS,
        "modified": _FIXED_TS,
        "name": "reconweave",
        "identity_class": "system",
    }
    objects.append(tool_identity)

    for node in result.graph.nodes():
        mapping = _NODE_MAP.get(node["type"])
        if mapping is None:
            continue
        stix_type, prop = mapping
        obj = _sco(stix_type, prop, node)
        objects.append(obj)
        id_index[node["id"]] = obj["id"]

    for edge in result.graph.edges():
        src = id_index.get(edge["source_id"])
        tgt = id_index.get(edge["target_id"])
        if not src or not tgt:
            continue
        rel_type = _REL_MAP.get(edge["type"], "related-to")
        rid = _det_id("relationship",
                      f"{edge['source_id']}|{edge['type']}|{edge['target_id']}")
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rid,
            "created": _FIXED_TS,
            "modified": _FIXED_TS,
            "relationship_type": rel_type,
            "source_ref": src,
            "target_ref": tgt,
            "confidence": int(round(edge.get("confidence", 0.0) * 100)),
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, 'bundle|' + result.seed.value)}",
        "objects": objects,
    }
    return bundle


def to_stix(result) -> str:
    return json.dumps(build_bundle(result), indent=2)


__all__ = ["to_stix", "build_bundle"]
