"""Graph merge / dedup semantics."""

from reconweave.entities import EdgeType, Entity, NodeType, Relationship
from reconweave.graph import ReconGraph


def test_add_entity_creates_node():
    g = ReconGraph()
    g.add_entity(Entity(NodeType.DOMAIN, "example.com", source="dns", confidence=0.5))
    assert g.node_count == 1
    assert g.nodes()[0]["value"] == "example.com"


def test_duplicate_entities_merge():
    g = ReconGraph()
    g.add_entity(Entity(NodeType.DOMAIN, "example.com", source="dns",
                        confidence=0.5, attributes={"a": 1}))
    g.add_entity(Entity(NodeType.DOMAIN, "Example.com", source="whois",
                        confidence=0.9, attributes={"b": 2}))
    assert g.node_count == 1
    node = g.nodes()[0]
    assert node["confidence"] == 0.9  # max
    assert set(node["sources"]) == {"dns", "whois"}
    assert node["attributes"] == {"a": 1, "b": 2}  # merged


def test_list_attribute_merge_dedups():
    g = ReconGraph()
    g.add_entity(Entity(NodeType.DOMAIN, "x.com", attributes={"ns": ["ns1"]}))
    g.add_entity(Entity(NodeType.DOMAIN, "x.com", attributes={"ns": ["ns1", "ns2"]}))
    assert g.nodes()[0]["attributes"]["ns"] == ["ns1", "ns2"]


def test_relationship_merge_by_triple():
    g = ReconGraph()
    a = Entity(NodeType.DOMAIN, "x.com")
    b = Entity(NodeType.IP, "1.2.3.4")
    g.add_entity(a)
    g.add_entity(b)
    g.add_relationship(Relationship(a.id, b.id, EdgeType.RESOLVES_TO,
                                    source="dns", confidence=0.5))
    g.add_relationship(Relationship(a.id, b.id, EdgeType.RESOLVES_TO,
                                    source="crtsh", confidence=0.8))
    assert g.edge_count == 1
    edge = g.edges()[0]
    assert edge["confidence"] == 0.8
    assert set(edge["sources"]) == {"dns", "crtsh"}


def test_different_edge_types_not_merged():
    g = ReconGraph()
    a = Entity(NodeType.ORG, "Acme")
    b = Entity(NodeType.DOMAIN, "acme.com")
    g.add_entity(a)
    g.add_entity(b)
    g.add_relationship(Relationship(a.id, b.id, EdgeType.OWNS))
    g.add_relationship(Relationship(a.id, b.id, EdgeType.LINKED_TO))
    assert g.edge_count == 2


def test_relationship_autocreates_stub_nodes():
    g = ReconGraph()
    g.add_relationship(Relationship("domain:x.com", "ip:1.1.1.1",
                                    EdgeType.RESOLVES_TO))
    assert g.node_count == 2


def test_stats_counts_by_type():
    g = ReconGraph()
    g.add_entity(Entity(NodeType.DOMAIN, "x.com"))
    g.add_entity(Entity(NodeType.SUBDOMAIN, "a.x.com"))
    g.add_entity(Entity(NodeType.SUBDOMAIN, "b.x.com"))
    stats = g.stats()
    assert stats["nodes_by_type"]["subdomain"] == 2
    assert stats["nodes_by_type"]["domain"] == 1


def test_scan_graph_merges_shared_domain(domain_scan):
    # whois, dns, subdomain, crtsh all reference example.com -> one node.
    domain_nodes = [n for n in domain_scan.graph.nodes()
                    if n["value"] == "example.com" and n["type"] == "domain"]
    assert len(domain_nodes) == 1
    assert len(domain_nodes[0]["sources"]) >= 2
