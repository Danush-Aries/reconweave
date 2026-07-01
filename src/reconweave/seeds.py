"""Seed auto-detection for the 13 supported seed types.

A *seed* is the starting point of a scan. ``detect()`` classifies a raw
string into one of :class:`SeedType` using layered, deterministic
heuristics. Ambiguous inputs can always be forced with an explicit
``hint`` (wired to the CLI ``--type`` flag).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SeedType(str, Enum):
    """The 13 auto-detected seed types."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    USERNAME = "username"
    IP = "ip"
    CIDR = "cidr"
    PHONE = "phone"
    ORG = "org"
    PERSON = "person"
    ASN = "asn"
    CRYPTO_WALLET = "crypto_wallet"
    FILE_HASH = "file_hash"
    SOCIAL_HANDLE = "social_handle"


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}$"
)
_ASN_RE = re.compile(r"^AS[0-9]{1,10}$", re.IGNORECASE)
_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_RE = re.compile(r"^(bc1[0-9a-z]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-().]{6,18}$")
_HANDLE_RE = re.compile(r"^@[A-Za-z0-9_.]{2,30}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,40}$")
_ORG_SUFFIX_RE = re.compile(
    r"\b(inc|inc\.|llc|ltd|ltd\.|corp|corp\.|gmbh|plc|co|company|"
    r"technologies|systems|labs|group|holdings|foundation|"
    r"solutions|industries)\b",
    re.IGNORECASE,
)


@dataclass
class Seed:
    """A classified seed value."""

    value: str
    type: SeedType

    def to_dict(self) -> dict:
        return {"value": self.value, "type": self.type.value}


def _digit_count(value: str) -> int:
    return sum(c.isdigit() for c in value)


def detect(value: str, hint: Optional[str] = None) -> SeedType:
    """Classify a raw seed string into a :class:`SeedType`.

    ``hint`` (a SeedType value or name) forces the classification and is
    what the CLI ``--type`` flag feeds in.
    """
    if hint:
        key = hint.strip().lower()
        for st in SeedType:
            if st.value == key or st.name.lower() == key:
                return st
        raise ValueError(f"unknown seed type hint: {hint!r}")

    v = value.strip()
    if not v:
        raise ValueError("empty seed value")

    # Email (before username / domain).
    if "@" in v and _EMAIL_RE.match(v):
        return SeedType.EMAIL

    # Social handle (@name).
    if _HANDLE_RE.match(v):
        return SeedType.SOCIAL_HANDLE

    # CIDR block.
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return SeedType.CIDR
        except ValueError:
            pass

    # Bare IP.
    try:
        ipaddress.ip_address(v)
        return SeedType.IP
    except ValueError:
        pass

    # Autonomous system number.
    if _ASN_RE.match(v):
        return SeedType.ASN

    # Crypto wallets.
    if _ETH_RE.match(v) or _BTC_RE.match(v):
        return SeedType.CRYPTO_WALLET

    # File hash (md5/sha1/sha256). Checked after eth/btc so 0x... wins.
    if _HASH_RE.match(v):
        return SeedType.FILE_HASH

    # Domain vs subdomain.
    if _DOMAIN_RE.match(v):
        labels = v.split(".")
        # A registrable domain has 2 labels (example.com); >2 => subdomain,
        # but keep common multi-part TLDs (co.uk, com.au) as domains.
        multi_tlds = {"co.uk", "com.au", "co.in", "org.uk", "gov.uk", "ac.uk"}
        tail = ".".join(labels[-2:])
        if len(labels) >= 3 and tail not in multi_tlds:
            return SeedType.SUBDOMAIN
        if len(labels) >= 4 and tail in multi_tlds:
            return SeedType.SUBDOMAIN
        return SeedType.DOMAIN

    # Phone number.
    if _PHONE_RE.match(v) and 7 <= _digit_count(v) <= 15:
        return SeedType.PHONE

    # Organization (has an org suffix keyword).
    if _ORG_SUFFIX_RE.search(v):
        return SeedType.ORG

    # Person (looks like a multi-word name).
    if " " in v and all(part.isalpha() for part in v.split()):
        return SeedType.PERSON

    # Fallback: a single token is a username.
    if _USERNAME_RE.match(v):
        return SeedType.USERNAME

    # Anything else with spaces -> treat as org name.
    if " " in v:
        return SeedType.ORG

    return SeedType.USERNAME


def make_seed(value: str, hint: Optional[str] = None) -> Seed:
    return Seed(value=value.strip(), type=detect(value, hint))


__all__ = ["SeedType", "Seed", "detect", "make_seed"]
