"""Seed auto-detection across all 13 types."""

import pytest

from reconweave.seeds import SeedType, detect, make_seed


@pytest.mark.parametrize("value,expected", [
    ("example.com", SeedType.DOMAIN),
    ("sub.example.com", SeedType.SUBDOMAIN),
    ("www.dev.example.com", SeedType.SUBDOMAIN),
    ("alice@example.com", SeedType.EMAIL),
    ("cool_user", SeedType.USERNAME),
    ("8.8.8.8", SeedType.IP),
    ("2001:4860:4860::8888", SeedType.IP),
    ("10.0.0.0/24", SeedType.CIDR),
    ("+1 415-555-2671", SeedType.PHONE),
    ("AS15169", SeedType.ASN),
    ("0x" + "a" * 40, SeedType.CRYPTO_WALLET),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", SeedType.CRYPTO_WALLET),
    ("d" * 64, SeedType.FILE_HASH),
    ("a" * 32, SeedType.FILE_HASH),
    ("@some.handle", SeedType.SOCIAL_HANDLE),
    ("Acme Technologies Inc.", SeedType.ORG),
    ("Jane Roe", SeedType.PERSON),
])
def test_detect_all_types(value, expected):
    assert detect(value) == expected


def test_all_13_types_reachable():
    detected = set()
    samples = [
        "example.com", "sub.example.com", "a@b.com", "someuser", "1.2.3.4",
        "10.0.0.0/8", "+14155552671", "AS1", "0x" + "b" * 40, "e" * 40,
        "@handle", "Widgets LLC", "John Smith",
    ]
    for s in samples:
        detected.add(detect(s))
    assert detected == set(SeedType)


def test_hint_overrides_detection():
    # 'admin' would be a username, but we can force org.
    assert detect("admin", hint="org") == SeedType.ORG
    assert detect("admin", hint="person") == SeedType.PERSON


def test_hint_unknown_raises():
    with pytest.raises(ValueError):
        detect("x", hint="not-a-type")


def test_empty_seed_raises():
    with pytest.raises(ValueError):
        detect("   ")


def test_make_seed_roundtrip():
    seed = make_seed("Example.COM")
    assert seed.type == SeedType.DOMAIN
    assert seed.to_dict() == {"value": "Example.COM", "type": "domain"}
