"""Deterministic pseudo-random helpers keyed off ``sha256(seed)``.

Everything synthetic in reconweave flows through here so that the same
seed always produces the same graph — offline, reproducible, testable.
"""

from __future__ import annotations

import hashlib
import random
from typing import Iterable, Sequence, TypeVar

T = TypeVar("T")


def sha256_hex(*parts: object) -> str:
    """Stable hex digest for an ordered set of parts."""
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def seed_int(*parts: object) -> int:
    """Derive a stable 64-bit integer seed from parts."""
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def rng(*parts: object) -> random.Random:
    """A deterministic ``random.Random`` seeded from parts."""
    return random.Random(seed_int(*parts))


def pick(r: random.Random, seq: Sequence[T]) -> T:
    return seq[r.randrange(len(seq))]


def sample(r: random.Random, seq: Sequence[T], k: int) -> list[T]:
    k = max(0, min(k, len(seq)))
    return r.sample(list(seq), k)


def chance(r: random.Random, probability: float) -> bool:
    return r.random() < probability


def fingerprint(value: str, length: int = 12) -> str:
    """Short hex fingerprint of a value (stable)."""
    return sha256_hex(value)[:length]


def iso_date(r: random.Random, start_year: int = 2012, end_year: int = 2024) -> str:
    year = r.randint(start_year, end_year)
    month = r.randint(1, 12)
    day = r.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def synthetic_ipv4(r: random.Random) -> str:
    # Avoid reserved ranges for realism; keep deterministic.
    return f"{r.randint(11, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def weighted_confidence(r: random.Random, base: float, spread: float = 0.15) -> float:
    val = base + r.uniform(-spread, spread)
    return round(max(0.05, min(0.99, val)), 3)


def take(seq: Iterable[T], n: int) -> list[T]:
    out: list[T] = []
    for i, item in enumerate(seq):
        if i >= n:
            break
        out.append(item)
    return out
