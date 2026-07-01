"""Collector registry + contract tests."""

import pytest

from reconweave import collectors as collectors_pkg
from reconweave.collectors.base import CollectorResult
from reconweave.entities import Entity, Relationship
from reconweave.seeds import SeedType


def test_exactly_20_collectors():
    assert len(collectors_pkg.all_collectors()) == 20


def test_category_breakdown():
    counts = {}
    for c in collectors_pkg.all_collectors():
        counts[c.category] = counts.get(c.category, 0) + 1
    assert counts["infra"] == 9
    assert counts["email"] == 4
    assert counts["username"] == 1
    assert counts["people"] == 1
    assert counts["phone"] == 1
    assert counts["leaks"] == 1
    assert counts["crypto"] == 1
    assert counts["media"] == 2


def test_all_collectors_offline_by_default():
    assert all(c.live is False for c in collectors_pkg.all_collectors())


_SAMPLE = {
    SeedType.DOMAIN: "example.com",
    SeedType.SUBDOMAIN: "api.example.com",
    SeedType.EMAIL: "jane@example.com",
    SeedType.USERNAME: "someuser",
    SeedType.SOCIAL_HANDLE: "@someuser",
    SeedType.IP: "8.8.8.8",
    SeedType.ASN: "AS15169",
    SeedType.PERSON: "Jane Roe",
    SeedType.PHONE: "+14155552671",
    SeedType.CRYPTO_WALLET: "0x" + "a" * 40,
    SeedType.FILE_HASH: "f" * 64,
}


@pytest.mark.parametrize("collector", collectors_pkg.all_collectors(),
                         ids=lambda c: c.name)
def test_collector_contract(collector):
    """Every collector returns a well-formed CollectorResult for its seeds."""
    for seed_type in collector.accepts:
        value = _SAMPLE[seed_type]
        result = collector.collect(value, seed_type, {})
        assert isinstance(result, CollectorResult)
        assert result.source == collector.name
        assert 0.0 <= result.confidence <= 1.0
        assert all(isinstance(e, Entity) for e in result.entities)
        assert all(isinstance(r, Relationship) for r in result.relationships)
        # provenance is stamped onto payload
        for e in result.entities:
            assert e.source
        # relationship endpoints reference produced or known ids
        for rel in result.relationships:
            assert rel.source_id and rel.target_id
            assert 0.0 <= rel.confidence <= 1.0


def test_determinism_same_seed_same_output():
    c = collectors_pkg.get_collector("subdomain")
    r1 = c.collect("example.com", SeedType.DOMAIN, {})
    r2 = c.collect("example.com", SeedType.DOMAIN, {})
    ids1 = sorted(e.id for e in r1.entities)
    ids2 = sorted(e.id for e in r2.entities)
    assert ids1 == ids2


def test_collectors_for_filters_by_seed_type():
    infra = collectors_pkg.collectors_for(SeedType.DOMAIN)
    names = {c.name for c in infra}
    assert {"whois", "dns", "subdomain", "crtsh", "webtech"} <= names
    assert "breach" not in names  # email-only


def test_catalog_shape():
    cat = collectors_pkg.catalog()
    assert len(cat) == 20
    for row in cat:
        assert set(row) == {"name", "category", "accepts", "live", "description"}


def test_username_collector_uses_40plus_platforms():
    from reconweave.collectors.username import load_platforms
    assert len(load_platforms()) >= 40
