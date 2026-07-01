"""GraphML exporter (Maltego / Gephi / yEd importable).

Uses networkx's GraphML writer with flattened, string-typed attributes so
the output validates against the GraphML schema and imports cleanly.
"""

from __future__ import annotations

import io
import json

import networkx as nx


def _flatten(g_in) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for nid, data in g_in.nodes(data=True):
        g.add_node(
            nid,
            type=str(data.get("type", "")),
            value=str(data.get("value", "")),
            confidence=float(data.get("confidence", 0.0)),
            sources=",".join(data.get("sources", [])),
            first_seen=str(data.get("first_seen", "")),
            attributes=json.dumps(data.get("attributes", {}), default=str),
        )
    for u, v, data in g_in.edges(data=True):
        g.add_edge(
            u, v,
            type=str(data.get("type", "")),
            confidence=float(data.get("confidence", 0.0)),
            sources=",".join(data.get("sources", [])),
            attributes=json.dumps(data.get("attributes", {}), default=str),
        )
    return g


def to_graphml(result) -> str:
    flat = _flatten(result.graph.to_networkx())
    buf = io.BytesIO()
    nx.write_graphml(flat, buf, named_key_ids=True)
    return buf.getvalue().decode("utf-8")


__all__ = ["to_graphml"]
