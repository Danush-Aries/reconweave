"""Crypto collector (1): wallet balance, tx count, linked/counterparty wallets."""

from __future__ import annotations

from typing import Any, Dict

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register


def _chain(addr: str) -> str:
    if addr.startswith("0x"):
        return "ethereum"
    if addr.startswith("bc1") or addr[:1] in "13":
        return "bitcoin"
    return "unknown"


def _synth_addr(r, chain: str) -> str:
    hexchars = "0123456789abcdef"
    if chain == "ethereum":
        return "0x" + "".join(r.choice(hexchars) for _ in range(40))
    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "1" + "".join(r.choice(b58) for _ in range(r.randint(25, 33)))


@register
class CryptoCollector(Collector):
    name = "crypto"
    category = "crypto"
    description = "Wallet balance, tx count, and counterparty wallets it controls / links to."
    accepts = (SeedType.CRYPTO_WALLET,)
    base_confidence = 0.6

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        chain = _chain(value)
        balance = round(r.uniform(0, 42), 6)
        txs = r.randint(0, 5000)
        wallet = Entity(NodeType.CRYPTO_WALLET, value, confidence=0.9,
                        attributes={"chain": chain, "balance": balance,
                                    "tx_count": txs, "symbol": "ETH" if chain == "ethereum" else "BTC",
                                    "first_tx": _rng.iso_date(r, 2015, 2022)})
        entities = [wallet]
        rels = []
        for _ in range(r.randint(1, 4)):
            other = _synth_addr(r, chain)
            counter = Entity(NodeType.CRYPTO_WALLET, other, confidence=0.5,
                             attributes={"chain": chain, "role": "counterparty"})
            entities.append(counter)
            # Same-owner cluster => controls; otherwise linked_to (transacted).
            if _rng.chance(r, 0.4):
                rels.append(Relationship(wallet.id, counter.id, EdgeType.CONTROLS,
                                         confidence=0.55,
                                         attributes={"heuristic": "common-input-ownership"}))
            else:
                rels.append(Relationship(wallet.id, counter.id, EdgeType.LINKED_TO,
                                         confidence=0.45,
                                         attributes={"relation": "transacted"}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"chain": chain, "balance": balance, "tx_count": txs})
