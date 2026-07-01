"""Entity resolution and cross-source pivots.

After collectors have merged into a :class:`ReconGraph`, correlation
adds the *derived* edges that make OSINT valuable: linking an email's
local-part to a username, fusing the same username across platforms into
one identity, chaining identities to the organizations they belong to,
and computing a fused confidence for each correlation. Temporal ordering
is preserved via ``first_seen``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .entities import EdgeType, Entity, NodeType, Relationship, make_id
from .graph import ReconGraph


@dataclass
class Correlation:
    """A derived link discovered during correlation."""

    kind: str
    source_id: str
    target_id: str
    confidence: float
    rationale: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


def fuse_confidence(*values: float) -> float:
    """Combine independent confidences (noisy-OR): 1 - prod(1 - p)."""
    prod = 1.0
    for v in values:
        prod *= (1.0 - max(0.0, min(1.0, v)))
    return round(1.0 - prod, 3)


def _email_localpart(email_value: str) -> str:
    return email_value.split("@", 1)[0].lower()


def correlate(graph: ReconGraph) -> List[Correlation]:
    """Run all pivots against the graph, adding edges in place.

    Returns the list of correlations discovered (also useful for reports).
    """
    correlations: List[Correlation] = []
    nodes = {n["id"]: n for n in graph.nodes()}

    # --- Pivot 1: email local-part -> username -----------------------------
    emails = [n for n in nodes.values() if n["type"] == NodeType.EMAIL.value]
    usernames = {n["value"].lower(): n for n in nodes.values()
                 if n["type"] == NodeType.USERNAME.value}
    for e in emails:
        local = _email_localpart(e["value"])
        variants = {local, local.replace(".", ""), local.split(".")[0],
                    local.split("+")[0]}
        for var in variants:
            if not var:
                continue
            uid = make_id(NodeType.USERNAME, var)
            if uid not in nodes:
                # Materialize the derived username so pivots can chain.
                graph.add_entity(Entity(NodeType.USERNAME, var, confidence=0.45,
                                        source="correlation",
                                        attributes={"derived_from": e["value"]}))
                nodes[uid] = {"id": uid, "type": NodeType.USERNAME.value,
                              "value": var, "confidence": 0.45}
            conf = fuse_confidence(e["confidence"], 0.5)
            graph.add_relationship(Relationship(
                e["id"], uid, EdgeType.SAME_IDENTITY, source="correlation",
                confidence=conf,
                attributes={"method": "email-localpart", "localpart": var}))
            correlations.append(Correlation(
                "email->username", e["id"], uid, conf,
                f"email local-part '{var}' matches username", {"localpart": var}))

    # --- Pivot 2: username -> platform profiles (fuse identity) ------------
    for uid, unode in list(usernames.items()):
        profile_ids = []
        for pid, pnode in nodes.items():
            if pnode["type"] != NodeType.SOCIAL_PROFILE.value:
                continue
            attrs = pnode.get("attributes", {})
            if str(attrs.get("username", "")).lower() == uid:
                profile_ids.append(pid)
        if len(profile_ids) >= 2:
            conf = fuse_confidence(0.6, 0.6, min(0.9, 0.4 + 0.05 * len(profile_ids)))
            for pid in profile_ids:
                correlations.append(Correlation(
                    "username->platform", unode["id"], pid, conf,
                    f"username reused across {len(profile_ids)} platforms",
                    {"platform_count": len(profile_ids)}))

    # --- Pivot 3: identity -> org (person/email/username member_of) --------
    # If a person and an email share an org via existing edges, tie the
    # person's usernames to that org too (linked_to).
    orgs = [n for n in nodes.values() if n["type"] == NodeType.ORG.value
            and n.get("attributes", {}).get("kind") not in ("breach", "leak")]
    persons = [n for n in nodes.values() if n["type"] == NodeType.PERSON.value]
    for p in persons:
        neigh = set(graph.neighbors(p["id"]))
        p_orgs = [o for o in orgs if o["id"] in neigh]
        p_ids = [nid for nid in neigh
                 if nodes.get(nid, {}).get("type") in
                 (NodeType.USERNAME.value, NodeType.EMAIL.value)]
        for o in p_orgs:
            for ident in p_ids:
                conf = fuse_confidence(0.5, 0.5)
                graph.add_relationship(Relationship(
                    ident, o["id"], EdgeType.LINKED_TO, source="correlation",
                    confidence=conf, attributes={"via": p["id"], "relation": "affiliated"}))
                correlations.append(Correlation(
                    "identity->org", ident, o["id"], conf,
                    "identity affiliated with org via shared person",
                    {"via_person": p["value"]}))

    # --- Temporal ordering signal -----------------------------------------
    dated = [(n["first_seen"], n["id"]) for n in graph.nodes() if n["first_seen"]]
    dated.sort()
    for (d0, _), (d1, nid1) in zip(dated, dated[1:]):
        graph.g.nodes[nid1]["attributes"].setdefault("temporal_rank", d1)

    return correlations


def summarize(correlations: List[Correlation]) -> Dict[str, Any]:
    by_kind: Dict[str, int] = {}
    for c in correlations:
        by_kind[c.kind] = by_kind.get(c.kind, 0) + 1
    return {"total": len(correlations), "by_kind": by_kind}


__all__ = ["Correlation", "correlate", "fuse_confidence", "summarize"]
