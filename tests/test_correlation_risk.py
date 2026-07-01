"""Correlation pivots, confidence fusion, and risk math."""

import pytest

from reconweave.correlation import correlate, fuse_confidence, summarize
from reconweave.entities import EdgeType, Entity, NodeType, Relationship
from reconweave.graph import ReconGraph
from reconweave.risk import compute_risk


def test_fuse_confidence_noisy_or():
    # 1 - (1-.5)(1-.5) = .75
    assert fuse_confidence(0.5, 0.5) == 0.75
    assert fuse_confidence(0.9) == 0.9
    assert fuse_confidence() == 0.0
    assert 0.0 <= fuse_confidence(0.3, 0.4, 0.5) <= 1.0


def test_fuse_monotonic():
    assert fuse_confidence(0.5, 0.5) > fuse_confidence(0.5)


def test_email_to_username_pivot():
    g = ReconGraph()
    g.add_entity(Entity(NodeType.EMAIL, "jdoe@example.com", confidence=0.9))
    corrs = correlate(g)
    kinds = {c.kind for c in corrs}
    assert "email->username" in kinds
    # derived username node exists
    assert any(n["type"] == "username" and n["value"] == "jdoe" for n in g.nodes())


def test_username_across_platforms_pivot():
    g = ReconGraph()
    g.add_entity(Entity(NodeType.USERNAME, "neo", confidence=0.9))
    for plat in ("github", "twitter", "reddit"):
        g.add_entity(Entity(NodeType.SOCIAL_PROFILE, f"{plat}:neo",
                            attributes={"username": "neo", "platform": plat}))
    corrs = correlate(g)
    plat_corrs = [c for c in corrs if c.kind == "username->platform"]
    assert plat_corrs
    # fused confidence rises with more platforms
    assert plat_corrs[0].confidence > 0.6


def test_correlation_summary(email_scan):
    summary = summarize(email_scan.correlations)
    assert summary["total"] == len(email_scan.correlations)
    assert isinstance(summary["by_kind"], dict)


def test_risk_score_bounds(domain_scan, email_scan, username_scan):
    for scan in (domain_scan, email_scan, username_scan):
        assert 0 <= scan.risk.score <= 100
        assert scan.risk.band in {"critical", "high", "medium", "low", "minimal"}


def test_risk_breaches_add_points():
    g = ReconGraph()
    email = Entity(NodeType.EMAIL, "victim@example.com")
    g.add_entity(email)
    for name in ("LinkedIn", "Dropbox", "Adobe"):
        b = Entity(NodeType.ORG, f"breach:{name}",
                   attributes={"kind": "breach", "name": name, "year": 2016})
        g.add_entity(b)
        g.add_relationship(Relationship(email.id, b.id, EdgeType.APPEARS_IN_BREACH))
    risk = compute_risk(g)
    names = [f.name for f in risk.factors]
    assert "Credential breaches" in names
    breach_factor = next(f for f in risk.factors if f.name == "Credential breaches")
    assert breach_factor.points > 0
    assert risk.score >= breach_factor.points


def test_risk_is_explained(email_scan):
    assert isinstance(email_scan.risk.factors, list)
    for f in email_scan.risk.factors:
        assert f.detail
        assert f.points >= 0


def test_risk_empty_graph_is_zero():
    risk = compute_risk(ReconGraph())
    assert risk.score == 0
    assert risk.band == "minimal"


def test_exposed_services_raise_risk():
    g = ReconGraph()
    ip = Entity(NodeType.IP, "9.9.9.9",
                attributes={"open_ports": [{"port": 3306, "service": "mysql"},
                                           {"port": 6379, "service": "redis"}]})
    g.add_entity(ip)
    risk = compute_risk(g)
    assert any(f.name == "Exposed network services" for f in risk.factors)
    assert risk.score > 0
