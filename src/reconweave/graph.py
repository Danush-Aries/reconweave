"""Entity graph: networkx-backed merge / dedup of collector output.

Nodes are keyed by canonical entity id, so two collectors that discover
the same domain/ip/email collapse into one node with merged attributes,
unioned sources, and the maximum observed confidence. Edges are keyed by
(source, type, target) and merged the same way.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

import networkx as nx

from .entities import Entity, EdgeType, NodeType, Relationship


def _merge_attrs(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if k not in dst or dst[k] in (None, "", [], {}):
            dst[k] = v
        elif isinstance(dst[k], list) and isinstance(v, list):
            for item in v:
                if item not in dst[k]:
                    dst[k].append(item)


class ReconGraph:
    """A merging, de-duplicating wrapper around ``networkx.MultiDiGraph``."""

    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()

    # -- ingestion ---------------------------------------------------------
    def add_entity(self, entity: Entity) -> str:
        nid = entity.id
        if self.g.has_node(nid):
            data = self.g.nodes[nid]
            _merge_attrs(data["attributes"], entity.attributes)
            data["confidence"] = max(data["confidence"], entity.confidence)
            sources = set(data["sources"])
            sources.add(entity.source)
            data["sources"] = sorted(sources)
            if entity.first_seen and (
                not data["first_seen"] or entity.first_seen < data["first_seen"]
            ):
                data["first_seen"] = entity.first_seen
        else:
            self.g.add_node(
                nid,
                type=entity.type.value,
                value=entity.value,
                attributes=dict(entity.attributes),
                confidence=float(entity.confidence),
                sources=[entity.source],
                first_seen=entity.first_seen,
            )
        return nid

    def add_relationship(self, rel: Relationship) -> None:
        # Ensure endpoints exist as (possibly stub) nodes.
        for nid in (rel.source_id, rel.target_id):
            if not self.g.has_node(nid):
                node_type, _, value = nid.partition(":")
                self.g.add_node(nid, type=node_type, value=value,
                                attributes={}, confidence=0.3,
                                sources=[rel.source], first_seen="")
        key = rel.type.value
        existing = self.g.get_edge_data(rel.source_id, rel.target_id, key)
        if existing is not None:
            existing["confidence"] = max(existing["confidence"], rel.confidence)
            _merge_attrs(existing["attributes"], rel.attributes)
            sources = set(existing["sources"])
            sources.add(rel.source)
            existing["sources"] = sorted(sources)
        else:
            self.g.add_edge(
                rel.source_id, rel.target_id, key=key,
                type=rel.type.value,
                confidence=float(rel.confidence),
                attributes=dict(rel.attributes),
                sources=[rel.source],
            )

    def merge_result(self, entities: Iterable[Entity], relationships: Iterable[Relationship]) -> None:
        for e in entities:
            self.add_entity(e)
        for r in relationships:
            self.add_relationship(r)

    # -- access ------------------------------------------------------------
    @property
    def node_count(self) -> int:
        return self.g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.g.number_of_edges()

    def nodes(self) -> List[Dict[str, Any]]:
        out = []
        for nid, data in self.g.nodes(data=True):
            out.append({"id": nid, **{k: data[k] for k in
                        ("type", "value", "attributes", "confidence",
                         "sources", "first_seen")}})
        return out

    def edges(self) -> List[Dict[str, Any]]:
        out = []
        for u, v, k, data in self.g.edges(keys=True, data=True):
            out.append({"source_id": u, "target_id": v, "type": data["type"],
                        "confidence": data["confidence"],
                        "attributes": data["attributes"], "sources": data["sources"]})
        return out

    def nodes_of_type(self, node_type: NodeType) -> List[Dict[str, Any]]:
        return [n for n in self.nodes() if n["type"] == node_type.value]

    def edges_of_type(self, edge_type: EdgeType) -> List[Dict[str, Any]]:
        return [e for e in self.edges() if e["type"] == edge_type.value]

    def neighbors(self, nid: str) -> List[str]:
        if not self.g.has_node(nid):
            return []
        return list(set(self.g.successors(nid)) | set(self.g.predecessors(nid)))

    def stats(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for _, data in self.g.nodes(data=True):
            by_type[data["type"]] = by_type.get(data["type"], 0) + 1
        by_edge: Dict[str, int] = {}
        for _, _, data in self.g.edges(data=True):
            by_edge[data["type"]] = by_edge.get(data["type"], 0) + 1
        return {
            "nodes": self.node_count,
            "edges": self.edge_count,
            "nodes_by_type": by_type,
            "edges_by_type": by_edge,
        }

    def to_networkx(self) -> nx.MultiDiGraph:
        return self.g


__all__ = ["ReconGraph"]
