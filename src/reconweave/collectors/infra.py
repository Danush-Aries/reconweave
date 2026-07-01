"""Infrastructure collectors (9): whois, dns, reverse_dns, subdomain,
crtsh, portscan, asn, geoip, webtech.

All deterministic + offline. Real network implementations would slot in
behind ``live=True`` with the same result contract.
"""

from __future__ import annotations

from typing import Any, Dict

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship, make_id
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

_REGISTRARS = ["NameCheap Inc.", "GoDaddy LLC", "Cloudflare Inc.", "Gandi SAS", "Porkbun LLC"]
_ORG_SUFFIXES = ["Inc.", "LLC", "Ltd.", "Holdings", "Labs", "Systems"]
_NAMESERVERS = ["ns1", "ns2", "dns1", "dns2", "ns-cloud"]
_SUBDOMAIN_WORDS = [
    "www", "mail", "api", "dev", "staging", "vpn", "admin", "portal",
    "blog", "shop", "app", "test", "git", "cdn", "static", "assets",
    "internal", "beta", "auth", "docs", "status", "mx", "smtp", "ftp",
]
_CITIES = [
    ("US", "United States", "Ashburn", 39.0438, -77.4874),
    ("DE", "Germany", "Frankfurt", 50.1109, 8.6821),
    ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
    ("SG", "Singapore", "Singapore", 1.3521, 103.8198),
    ("GB", "United Kingdom", "London", 51.5074, -0.1278),
    ("IN", "India", "Mumbai", 19.0760, 72.8777),
]
_ASNS = [
    (13335, "CLOUDFLARENET"), (15169, "GOOGLE"), (16509, "AMAZON-02"),
    (14061, "DIGITALOCEAN-ASN"), (24940, "HETZNER-AS"), (63949, "LINODE-AP"),
]
_TECH = [
    ("nginx", "web-server"), ("Cloudflare", "cdn"), ("React", "javascript-framework"),
    ("WordPress", "cms"), ("Google Analytics", "analytics"), ("Let's Encrypt", "ssl"),
    ("PHP", "language"), ("Cloudflare Bot Management", "security"),
    ("HSTS", "security"), ("jQuery", "javascript-library"),
]


def _base_domain(value: str) -> str:
    labels = value.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return value


@register
class WhoisCollector(Collector):
    name = "whois"
    category = "infra"
    description = "Registrant, registrar, and registration dates for a domain."
    accepts = (SeedType.DOMAIN, SeedType.SUBDOMAIN)
    base_confidence = 0.8

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        domain = _base_domain(value)
        r = _rng.rng(self.name, domain)
        org_name = f"{domain.split('.')[0].capitalize()} {_rng.pick(r, _ORG_SUFFIXES)}"
        registrar = _rng.pick(r, _REGISTRARS)
        created = _rng.iso_date(r, 2004, 2019)
        expires = _rng.iso_date(r, 2025, 2029)
        admin = f"{_rng.pick(r, ['Alex', 'Jordan', 'Sam', 'Riley', 'Casey'])} " \
                f"{_rng.pick(r, ['Carter', 'Nguyen', 'Okafor', 'Silva', 'Kim'])}"

        org = Entity(NodeType.ORG, org_name, confidence=self.base_confidence,
                     first_seen=created,
                     attributes={"registrar": registrar, "role": "registrant"})
        person = Entity(NodeType.PERSON, admin, confidence=0.55,
                        attributes={"role": "admin-contact"})
        dom = Entity(NodeType.DOMAIN, domain, first_seen=created,
                     confidence=0.9,
                     attributes={"registrar": registrar, "created": created,
                                 "expires": expires})
        rels = [
            Relationship(org.id, dom.id, EdgeType.OWNS,
                         confidence=self.base_confidence),
            Relationship(person.id, org.id, EdgeType.MEMBER_OF, confidence=0.5),
        ]
        return CollectorResult([org, person, dom], rels, self.name,
                               self.base_confidence,
                               raw={"registrar": registrar, "created": created})


@register
class DnsCollector(Collector):
    name = "dns"
    category = "infra"
    description = "A/AAAA/MX/NS records resolving a domain to IPs and mail hosts."
    accepts = (SeedType.DOMAIN, SeedType.SUBDOMAIN)
    base_confidence = 0.85

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        host = Entity(
            NodeType.SUBDOMAIN if seed_type == SeedType.SUBDOMAIN else NodeType.DOMAIN,
            value, confidence=0.9,
        )
        entities = [host]
        rels = []
        n_ips = r.randint(1, 3)
        for _ in range(n_ips):
            ip = _rng.synthetic_ipv4(r)
            ip_e = Entity(NodeType.IP, ip, confidence=self.base_confidence,
                          attributes={"record": "A"})
            entities.append(ip_e)
            rels.append(Relationship(host.id, ip_e.id, EdgeType.RESOLVES_TO,
                                     confidence=self.base_confidence,
                                     attributes={"record": "A"}))
        ns = f"{_rng.pick(r, _NAMESERVERS)}.{_base_domain(value)}"
        host.attributes["nameservers"] = [ns]
        host.attributes["mx"] = [f"mx{r.randint(1, 2)}.{_base_domain(value)}"]
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"records": n_ips})


@register
class ReverseDnsCollector(Collector):
    name = "reverse_dns"
    category = "infra"
    description = "PTR lookup mapping an IP back to a hostname."
    accepts = (SeedType.IP,)
    base_confidence = 0.7

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        provider = _rng.pick(r, ["compute", "static", "node", "host"])
        ptr = f"{value.replace('.', '-')}.{provider}.example-cloud.net"
        ip = Entity(NodeType.IP, value, confidence=0.9)
        host = Entity(NodeType.DOMAIN, ptr, confidence=self.base_confidence,
                      attributes={"record": "PTR"})
        rel = Relationship(ip.id, host.id, EdgeType.RESOLVES_TO,
                           confidence=self.base_confidence,
                           attributes={"record": "PTR"})
        return CollectorResult([ip, host], [rel], self.name, self.base_confidence)


@register
class SubdomainCollector(Collector):
    name = "subdomain"
    category = "infra"
    description = "Enumerates subdomains via wordlist/passive DNS."
    accepts = (SeedType.DOMAIN,)
    base_confidence = 0.65

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        domain = _base_domain(value)
        r = _rng.rng(self.name, domain)
        dom = Entity(NodeType.DOMAIN, domain, confidence=0.9)
        entities = [dom]
        rels = []
        count = r.randint(4, 9)
        words = _rng.sample(r, _SUBDOMAIN_WORDS, count)
        for w in words:
            fqdn = f"{w}.{domain}"
            sub = Entity(NodeType.SUBDOMAIN, fqdn,
                         confidence=_rng.weighted_confidence(r, self.base_confidence),
                         attributes={"label": w})
            entities.append(sub)
            rels.append(Relationship(sub.id, dom.id, EdgeType.SUBDOMAIN_OF,
                                     confidence=self.base_confidence))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"count": count})


@register
class CrtShCollector(Collector):
    name = "crtsh"
    category = "infra"
    description = "Certificate Transparency (crt.sh style) subdomain discovery."
    accepts = (SeedType.DOMAIN,)
    base_confidence = 0.75

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        domain = _base_domain(value)
        r = _rng.rng(self.name, domain)
        dom = Entity(NodeType.DOMAIN, domain, confidence=0.9)
        entities = [dom]
        rels = []
        count = r.randint(3, 7)
        words = _rng.sample(r, _SUBDOMAIN_WORDS, count)
        for w in words:
            fqdn = f"{w}.{domain}"
            issued = _rng.iso_date(r, 2021, 2024)
            sub = Entity(NodeType.SUBDOMAIN, fqdn, confidence=self.base_confidence,
                         first_seen=issued,
                         attributes={"issuer": "Let's Encrypt", "not_before": issued})
            entities.append(sub)
            rels.append(Relationship(sub.id, dom.id, EdgeType.SUBDOMAIN_OF,
                                     confidence=self.base_confidence,
                                     attributes={"evidence": "certificate-transparency"}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"certificates": count})


@register
class PortScanCollector(Collector):
    name = "portscan"
    category = "infra"
    description = "Open TCP ports and banners for an IP."
    accepts = (SeedType.IP,)
    base_confidence = 0.7

    _PORTS = [
        (22, "ssh", "OpenSSH 8.9"), (80, "http", "nginx"),
        (443, "https", "nginx"), (3306, "mysql", "MySQL 8.0"),
        (6379, "redis", "Redis 7.0"), (8080, "http-alt", "Jetty"),
        (21, "ftp", "vsftpd 3.0"), (25, "smtp", "Postfix"),
    ]

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        n = r.randint(2, 5)
        ports = _rng.sample(r, self._PORTS, n)
        open_ports = [
            {"port": p, "service": s, "banner": b} for (p, s, b) in sorted(ports)
        ]
        ip = Entity(NodeType.IP, value, confidence=0.9,
                    attributes={"open_ports": open_ports,
                                "exposed_services": [p["service"] for p in open_ports]})
        return CollectorResult([ip], [], self.name, self.base_confidence,
                               raw={"open_ports": open_ports})


@register
class AsnCollector(Collector):
    name = "asn"
    category = "infra"
    description = "ASN / BGP origin and announced prefix for an IP or ASN."
    accepts = (SeedType.IP, SeedType.ASN)
    base_confidence = 0.8

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        asnum, org = _rng.pick(r, _ASNS)
        entities = []
        rels = []
        asn_e = Entity(NodeType.ASN, f"AS{asnum}", confidence=self.base_confidence,
                       attributes={"org": org})
        entities.append(asn_e)
        if seed_type == SeedType.IP:
            prefix = ".".join(value.split(".")[:2]) + ".0.0/16"
            cidr = Entity(NodeType.CIDR, prefix, confidence=0.7,
                          attributes={"origin_asn": asnum})
            ip = Entity(NodeType.IP, value, confidence=0.9)
            entities += [cidr, ip]
            rels.append(Relationship(asn_e.id, cidr.id, EdgeType.OWNS,
                                     confidence=self.base_confidence))
            rels.append(Relationship(ip.id, asn_e.id, EdgeType.LINKED_TO,
                                     confidence=0.6,
                                     attributes={"relation": "announced-by"}))
        else:
            for _ in range(r.randint(1, 3)):
                a = r.randint(11, 223)
                b = r.randint(0, 255)
                prefix = f"{a}.{b}.0.0/16"
                cidr = Entity(NodeType.CIDR, prefix, confidence=0.7,
                              attributes={"origin_asn": asnum})
                entities.append(cidr)
                rels.append(Relationship(asn_e.id, cidr.id, EdgeType.OWNS,
                                         confidence=self.base_confidence))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"asn": asnum, "org": org})


@register
class GeoIpCollector(Collector):
    name = "geoip"
    category = "infra"
    description = "Geolocation (country, city, coordinates) for an IP."
    accepts = (SeedType.IP,)
    base_confidence = 0.6

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        cc, country, city, lat, lon = _rng.pick(r, _CITIES)
        ip = Entity(NodeType.IP, value, confidence=0.9,
                    attributes={
                        "country_code": cc, "country": country, "city": city,
                        "latitude": round(lat + r.uniform(-0.4, 0.4), 4),
                        "longitude": round(lon + r.uniform(-0.4, 0.4), 4),
                    })
        return CollectorResult([ip], [], self.name, self.base_confidence,
                               raw={"country": country, "city": city})


@register
class WebTechCollector(Collector):
    name = "webtech"
    category = "infra"
    description = "Web technology fingerprint (server, CMS, JS, CDN) for a host."
    accepts = (SeedType.DOMAIN, SeedType.SUBDOMAIN)
    base_confidence = 0.65

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        n = r.randint(3, 7)
        techs = _rng.sample(r, _TECH, n)
        stack = [{"name": name, "category": cat} for name, cat in techs]
        node_type = NodeType.SUBDOMAIN if seed_type == SeedType.SUBDOMAIN else NodeType.DOMAIN
        host = Entity(node_type, value, confidence=0.9,
                      attributes={"technologies": stack,
                                  "server": next((t["name"] for t in stack
                                                  if t["category"] == "web-server"), "unknown")})
        return CollectorResult([host], [], self.name, self.base_confidence,
                               raw={"technologies": stack})
