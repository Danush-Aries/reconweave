"""Watchlist monitoring with sqlite-backed diff / alerting.

Add a seed to a watchlist, take periodic snapshots, and get a structured
diff (new / removed entities and edges) plus alerts whenever fresh
exposure appears (new breach, new open service, new profile).
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .engine import Engine, ScanResult


@dataclass
class Diff:
    seed: str
    new_nodes: List[str] = field(default_factory=list)
    removed_nodes: List[str] = field(default_factory=list)
    new_edges: List[str] = field(default_factory=list)
    removed_edges: List[str] = field(default_factory=list)
    risk_delta: int = 0
    alerts: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new_nodes or self.removed_nodes or self.new_edges
                    or self.removed_edges or self.risk_delta)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed": self.seed,
            "changed": self.changed,
            "new_nodes": self.new_nodes,
            "removed_nodes": self.removed_nodes,
            "new_edges": self.new_edges,
            "removed_edges": self.removed_edges,
            "risk_delta": self.risk_delta,
            "alerts": self.alerts,
        }


def _edge_key(e: Dict[str, Any]) -> str:
    return f"{e['source_id']}|{e['type']}|{e['target_id']}"


def _snapshot_of(result: ScanResult) -> Dict[str, Any]:
    return {
        "nodes": sorted(n["id"] for n in result.graph.nodes()),
        "edges": sorted(_edge_key(e) for e in result.graph.edges()),
        "risk": result.risk.score,
        "breaches": sorted(
            n["id"] for n in result.graph.nodes()
            if n.get("attributes", {}).get("kind") in ("breach", "leak")),
    }


class WatchStore:
    def __init__(self, db_path: str = "reconweave-watch.db") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS watch "
            "(seed TEXT PRIMARY KEY, seed_type TEXT, added REAL)")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS snapshot "
            "(seed TEXT PRIMARY KEY, data TEXT, ts REAL)")
        self.conn.commit()

    def add(self, seed: str, seed_type: str = "") -> None:
        self.conn.execute("INSERT OR REPLACE INTO watch VALUES (?,?,?)",
                          (seed, seed_type, time.time()))
        self.conn.commit()

    def remove(self, seed: str) -> None:
        self.conn.execute("DELETE FROM watch WHERE seed=?", (seed,))
        self.conn.execute("DELETE FROM snapshot WHERE seed=?", (seed,))
        self.conn.commit()

    def list_watches(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT seed, seed_type, added FROM watch").fetchall()
        return [{"seed": s, "seed_type": t, "added": a} for s, t, a in rows]

    def _load_snapshot(self, seed: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT data FROM snapshot WHERE seed=?",
                               (seed,)).fetchone()
        return json.loads(row[0]) if row else None

    def _save_snapshot(self, seed: str, snap: Dict[str, Any]) -> None:
        self.conn.execute("INSERT OR REPLACE INTO snapshot VALUES (?,?,?)",
                          (seed, json.dumps(snap), time.time()))
        self.conn.commit()

    def check(self, seed: str, engine: Optional[Engine] = None,
              seed_type_hint: Optional[str] = None,
              store: bool = True) -> Diff:
        """Rescan a watched seed and diff against the last snapshot."""
        engine = engine or Engine(use_cache=False)
        result = engine.scan(seed, seed_type_hint)
        current = _snapshot_of(result)
        previous = self._load_snapshot(seed)
        diff = Diff(seed=seed)
        if previous is None:
            diff.alerts.append(f"baseline snapshot created ({len(current['nodes'])} nodes, "
                               f"risk {current['risk']})")
        else:
            prev_nodes, cur_nodes = set(previous["nodes"]), set(current["nodes"])
            prev_edges, cur_edges = set(previous["edges"]), set(current["edges"])
            diff.new_nodes = sorted(cur_nodes - prev_nodes)
            diff.removed_nodes = sorted(prev_nodes - cur_nodes)
            diff.new_edges = sorted(cur_edges - prev_edges)
            diff.removed_edges = sorted(prev_edges - cur_edges)
            diff.risk_delta = current["risk"] - previous["risk"]
            new_breaches = set(current["breaches"]) - set(previous.get("breaches", []))
            for b in sorted(new_breaches):
                diff.alerts.append(f"NEW EXPOSURE: {b}")
            if diff.risk_delta > 0:
                diff.alerts.append(f"risk increased by {diff.risk_delta} "
                                   f"({previous['risk']} -> {current['risk']})")
        if store:
            self._save_snapshot(seed, current)
        return diff

    def close(self) -> None:
        self.conn.close()


__all__ = ["WatchStore", "Diff"]
