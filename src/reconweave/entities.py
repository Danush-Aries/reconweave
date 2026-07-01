"""Graph vocabulary: 12 node types and 8 typed edges.

An :class:`Entity` is a node (a domain, ip, email, person …). A
:class:`Relationship` is a typed, directed, attributed edge between two
entity ids. Ids are canonical (``<type>:<normalized-value>``) so that
independent collectors that discover the same thing merge cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class NodeType(str, Enum):
    """The 12 node types in the reconweave graph."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    ORG = "org"
    PHONE = "phone"
    ASN = "asn"
    CRYPTO_WALLET = "crypto_wallet"
    SOCIAL_PROFILE = "social_profile"


class EdgeType(str, Enum):
    """The 8 typed edges in the reconweave graph."""

    OWNS = "owns"
    RESOLVES_TO = "resolves_to"
    SUBDOMAIN_OF = "subdomain_of"
    MEMBER_OF = "member_of"
    APPEARS_IN_BREACH = "appears_in_breach"
    SAME_IDENTITY = "same_identity"
    CONTROLS = "controls"
    LINKED_TO = "linked_to"


def canonical_value(node_type: NodeType, value: str) -> str:
    """Normalize a value for stable ids (case-fold most things)."""
    value = value.strip()
    if node_type in (
        NodeType.DOMAIN,
        NodeType.SUBDOMAIN,
        NodeType.EMAIL,
        NodeType.USERNAME,
        NodeType.SOCIAL_PROFILE,
    ):
        return value.lower()
    if node_type == NodeType.ASN:
        return value.upper().replace("AS", "AS") if value else value
    return value


def make_id(node_type: NodeType, value: str) -> str:
    return f"{node_type.value}:{canonical_value(node_type, value)}"


@dataclass
class Entity:
    """A node in the correlation graph."""

    type: NodeType
    value: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    source: str = "seed"
    confidence: float = 0.5
    first_seen: str = ""

    @property
    def id(self) -> str:
        return make_id(self.type, self.value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "attributes": dict(self.attributes),
            "source": self.source,
            "confidence": round(float(self.confidence), 3),
            "first_seen": self.first_seen,
        }


@dataclass
class Relationship:
    """A typed, directed edge between two entity ids."""

    source_id: str
    target_id: str
    type: EdgeType
    source: str = "seed"
    confidence: float = 0.5
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.source_id}|{self.type.value}|{self.target_id}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type.value,
            "source": self.source,
            "confidence": round(float(self.confidence), 3),
            "attributes": dict(self.attributes),
        }


NODE_TYPES = [t.value for t in NodeType]
EDGE_TYPES = [t.value for t in EdgeType]

__all__ = [
    "NodeType",
    "EdgeType",
    "Entity",
    "Relationship",
    "make_id",
    "canonical_value",
    "NODE_TYPES",
    "EDGE_TYPES",
]
