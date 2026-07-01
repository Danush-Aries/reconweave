"""CSV exporter: nodes + edges as two CSV sections in one string.

Each section is a standalone CSV; a ``# nodes`` / ``# edges`` marker line
separates them so the whole thing round-trips as one file while staying
trivially splittable.
"""

from __future__ import annotations

import csv
import io
import json


def _nodes_csv(result) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "type", "value", "confidence", "sources", "first_seen", "attributes"])
    for n in result.graph.nodes():
        w.writerow([
            n["id"], n["type"], n["value"], round(n["confidence"], 3),
            ";".join(n["sources"]), n["first_seen"],
            json.dumps(n["attributes"], default=str),
        ])
    return buf.getvalue()


def _edges_csv(result) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["source_id", "target_id", "type", "confidence", "sources", "attributes"])
    for e in result.graph.edges():
        w.writerow([
            e["source_id"], e["target_id"], e["type"], round(e["confidence"], 3),
            ";".join(e["sources"]), json.dumps(e["attributes"], default=str),
        ])
    return buf.getvalue()


def to_csv(result) -> str:
    return f"# nodes\n{_nodes_csv(result)}\n# edges\n{_edges_csv(result)}"


def nodes_csv(result) -> str:
    return _nodes_csv(result)


def edges_csv(result) -> str:
    return _edges_csv(result)


__all__ = ["to_csv", "nodes_csv", "edges_csv"]
