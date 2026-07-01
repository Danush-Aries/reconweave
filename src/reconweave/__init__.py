"""reconweave — offline-first OSINT correlation platform.

Fuses many mock/real collectors into one entity graph, pivots across
identities, scores exposure, and reports. Runs FULLY OFFLINE by default:
deterministic synthetic data keyed off sha256(seed), zero API keys, zero
network. Real collectors are gated behind ``--live``.

Author: Dhanush Shankar <danushankar3@gmail.com>
License: MIT
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Dhanush Shankar"
__email__ = "danushankar3@gmail.com"
__license__ = "MIT"

from .seeds import Seed, SeedType, detect  # noqa: E402
from .entities import Entity, EdgeType, NodeType, Relationship  # noqa: E402

__all__ = [
    "__version__",
    "Seed",
    "SeedType",
    "detect",
    "Entity",
    "Relationship",
    "NodeType",
    "EdgeType",
]
