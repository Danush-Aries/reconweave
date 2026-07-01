"""Async orchestrator: seed -> collectors -> graph -> correlation -> risk.

The engine picks the collectors that accept a seed, runs them
concurrently (bounded by a semaphore + token-bucket rate limit), caches
raw collector output in sqlite so repeat scans are instant, merges
everything into one graph, correlates, and scores exposure.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import collectors as collectors_pkg
from ._rng import sha256_hex
from .config import Config
from .correlation import Correlation, correlate, summarize
from .entities import Entity, EdgeType, NodeType, Relationship
from .graph import ReconGraph
from .risk import RiskScore, compute_risk
from .seeds import Seed, SeedType, make_seed


@dataclass
class ScanResult:
    seed: Seed
    graph: ReconGraph
    risk: RiskScore
    correlations: List[Correlation] = field(default_factory=list)
    collectors_run: List[str] = field(default_factory=list)
    duration_ms: int = 0
    live: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed": self.seed.to_dict(),
            "meta": {
                "collectors_run": self.collectors_run,
                "duration_ms": self.duration_ms,
                "live": self.live,
                "generator": "reconweave",
            },
            "stats": self.graph.stats(),
            "risk": self.risk.to_dict(),
            "correlations": [c.to_dict() for c in self.correlations],
            "correlation_summary": summarize(self.correlations),
            "nodes": self.graph.nodes(),
            "edges": self.graph.edges(),
        }


class _Cache:
    """Tiny sqlite cache for raw collector payloads."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS collector_cache "
            "(key TEXT PRIMARY KEY, payload TEXT, ts REAL)"
        )
        self.conn.commit()

    def get(self, key: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT payload FROM collector_cache WHERE key=?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, payload: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO collector_cache VALUES (?,?,?)",
            (key, json.dumps(payload), time.time()),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def _result_to_payload(result) -> dict:
    return {
        "entities": [e.to_dict() for e in result.entities],
        "relationships": [r.to_dict() for r in result.relationships],
        "source": result.source,
        "confidence": result.confidence,
        "raw": result.raw,
    }


def _payload_to_graph_parts(payload: dict):
    ents = []
    for e in payload["entities"]:
        ents.append(Entity(NodeType(e["type"]), e["value"], attributes=e["attributes"],
                           source=e["source"], confidence=e["confidence"],
                           first_seen=e.get("first_seen", "")))
    rels = []
    for r in payload["relationships"]:
        rels.append(Relationship(r["source_id"], r["target_id"], EdgeType(r["type"]),
                                 source=r["source"], confidence=r["confidence"],
                                 attributes=r["attributes"]))
    return ents, rels


class Engine:
    def __init__(self, config: Optional[Config] = None,
                 use_cache: bool = True) -> None:
        self.config = config or Config()
        self.use_cache = use_cache
        self._cache: Optional[_Cache] = None
        if use_cache:
            try:
                self._cache = _Cache(self.config.cache_path)
            except Exception:  # pragma: no cover
                self._cache = None
        self._min_interval = (1.0 / self.config.rate_limit_per_sec
                              if self.config.rate_limit_per_sec > 0 else 0.0)
        # Concurrency primitives are created per-run (bound to the active loop).
        self._sem: Optional[asyncio.Semaphore] = None
        self._lock: Optional[asyncio.Lock] = None
        self._last_call = 0.0

    # -- rate limiting -----------------------------------------------------
    async def _throttle(self) -> None:
        if self._min_interval <= 0 or self._lock is None:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._last_call + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()

    async def _run_collector(self, collector, value: str, seed_type: SeedType,
                             ctx: Dict[str, Any]) -> dict:
        key = sha256_hex("collector", collector.name, seed_type.value, value,
                         "live" if ctx.get("live") else "mock")
        if self._cache is not None:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
        async with self._sem:
            await self._throttle()
            result = await asyncio.to_thread(collector.collect, value, seed_type, ctx)
        payload = _result_to_payload(result)
        if self._cache is not None:
            self._cache.put(key, payload)
        return payload

    # -- public API --------------------------------------------------------
    async def scan_async(self, seed_value: str, seed_type_hint: Optional[str] = None,
                         live: Optional[bool] = None,
                         ctx: Optional[Dict[str, Any]] = None) -> ScanResult:
        start = time.monotonic()
        seed = make_seed(seed_value, seed_type_hint)
        live = self.config.live if live is None else live
        ctx = dict(ctx or {})
        ctx["live"] = live
        # Bind concurrency primitives to the currently running loop.
        self._sem = asyncio.Semaphore(max(1, self.config.max_concurrency))
        self._lock = asyncio.Lock()
        self._last_call = 0.0

        chosen = [c for c in collectors_pkg.collectors_for(seed.type, include_live=live)
                  if self.config.is_enabled(c.name)]

        tasks = [self._run_collector(c, seed.value, seed.type, ctx) for c in chosen]
        payloads = await asyncio.gather(*tasks) if tasks else []

        graph = ReconGraph()
        # Always seed the root entity so an isolated seed still yields a node.
        graph.add_entity(_seed_entity(seed))
        for payload in payloads:
            ents, rels = _payload_to_graph_parts(payload)
            graph.merge_result(ents, rels)

        correlations = correlate(graph)
        risk = compute_risk(graph)
        return ScanResult(
            seed=seed, graph=graph, risk=risk, correlations=correlations,
            collectors_run=[c.name for c in chosen],
            duration_ms=int((time.monotonic() - start) * 1000), live=live,
        )

    def scan(self, seed_value: str, seed_type_hint: Optional[str] = None,
             live: Optional[bool] = None,
             ctx: Optional[Dict[str, Any]] = None) -> ScanResult:
        return asyncio.run(self.scan_async(seed_value, seed_type_hint, live, ctx))

    def close(self) -> None:
        if self._cache is not None:
            self._cache.close()


_SEED_TYPE_TO_NODE = {
    SeedType.DOMAIN: NodeType.DOMAIN,
    SeedType.SUBDOMAIN: NodeType.SUBDOMAIN,
    SeedType.EMAIL: NodeType.EMAIL,
    SeedType.USERNAME: NodeType.USERNAME,
    SeedType.SOCIAL_HANDLE: NodeType.USERNAME,
    SeedType.IP: NodeType.IP,
    SeedType.CIDR: NodeType.CIDR,
    SeedType.PHONE: NodeType.PHONE,
    SeedType.ORG: NodeType.ORG,
    SeedType.PERSON: NodeType.PERSON,
    SeedType.ASN: NodeType.ASN,
    SeedType.CRYPTO_WALLET: NodeType.CRYPTO_WALLET,
    SeedType.FILE_HASH: NodeType.SOCIAL_PROFILE,
}


def _seed_entity(seed: Seed) -> Entity:
    node_type = _SEED_TYPE_TO_NODE.get(seed.type, NodeType.USERNAME)
    value = seed.value.lstrip("@") if seed.type == SeedType.SOCIAL_HANDLE else seed.value
    return Entity(node_type, value, confidence=1.0, source="seed",
                  attributes={"is_seed": True, "seed_type": seed.type.value})


__all__ = ["Engine", "ScanResult"]
