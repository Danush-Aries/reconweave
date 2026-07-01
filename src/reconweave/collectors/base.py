"""Collector base class, result contract, and registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Type

from ..entities import Entity, Relationship
from ..seeds import SeedType

REGISTRY: Dict[str, "Collector"] = {}


@dataclass
class CollectorResult:
    """The uniform contract every collector returns.

    entities/relationships are the graph payload; source/confidence are
    provenance carried onto every produced node and edge.
    """

    entities: List[Entity] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    source: str = ""
    confidence: float = 0.5
    raw: Dict[str, Any] = field(default_factory=dict)

    def stamp(self) -> "CollectorResult":
        """Stamp source/confidence onto payload where unset."""
        for e in self.entities:
            if not e.source or e.source == "seed":
                e.source = self.source
        for r in self.relationships:
            if not r.source or r.source == "seed":
                r.source = self.source
        return self


class Collector:
    """Base class for all collectors.

    Subclasses set :attr:`name`, :attr:`category`, :attr:`accepts` and
    implement :meth:`run`. ``live=False`` means fully offline synthetic
    data; ``live=True`` collectors require ``--live`` (network).
    """

    name: str = ""
    category: str = ""
    description: str = ""
    accepts: Tuple[SeedType, ...] = ()
    live: bool = False
    base_confidence: float = 0.6

    def supports(self, seed_type: SeedType) -> bool:
        return seed_type in self.accepts

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:  # noqa: D401
        """Produce entities + relationships for the seed. Override me."""
        raise NotImplementedError

    def collect(self, value: str, seed_type: SeedType, ctx: Dict[str, Any] | None = None) -> CollectorResult:
        ctx = ctx or {}
        result = self.run(value, seed_type, ctx)
        if not result.source:
            result.source = self.name
        result.stamp()
        return result


def register(cls: Type[Collector]) -> Type[Collector]:
    """Class decorator: instantiate and register a collector."""
    instance = cls()
    if not instance.name:
        raise ValueError(f"collector {cls.__name__} has no name")
    if instance.name in REGISTRY:
        raise ValueError(f"duplicate collector name: {instance.name}")
    REGISTRY[instance.name] = instance
    return cls


__all__ = ["Collector", "CollectorResult", "register", "REGISTRY"]
