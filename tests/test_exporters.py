"""Exporter validity: json, csv, graphml, stix 2.1, misp."""

import json
import xml.dom.minidom

import pytest

from reconweave.exporters import available_formats, export
from reconweave.exporters.stix_exporter import build_bundle
from reconweave.exporters.misp_exporter import build_event


def test_all_formats_registered():
    assert set(available_formats()) >= {"json", "csv", "graphml", "maltego",
                                        "stix", "misp"}


def test_json_export_parses(domain_scan):
    data = json.loads(export(domain_scan, "json"))
    assert data["seed"]["value"] == "example.com"
    assert "nodes" in data and "edges" in data and "risk" in data


def test_csv_export_has_both_sections(domain_scan):
    csv_str = export(domain_scan, "csv")
    assert "# nodes" in csv_str and "# edges" in csv_str
    assert "id,type,value" in csv_str


def test_graphml_is_valid_xml(username_scan):
    xml_str = export(username_scan, "graphml")
    dom = xml.dom.minidom.parseString(xml_str)  # raises on invalid
    assert dom.documentElement.tagName == "graphml"


def test_maltego_alias_equals_graphml(domain_scan):
    assert export(domain_scan, "maltego") == export(domain_scan, "graphml")


def test_stix_bundle_valid(email_scan):
    bundle = json.loads(export(email_scan, "stix"))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list) and bundle["objects"]
    for obj in bundle["objects"]:
        assert "type" in obj and "id" in obj
        assert obj["id"].startswith(obj["type"] + "--")
        if obj["type"] != "bundle":
            # SDOs/SROs carry spec_version 2.1
            assert obj.get("spec_version") == "2.1"


def test_stix_has_relationships(email_scan):
    bundle = build_bundle(email_scan)
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels
    for r in rels:
        assert r["source_ref"] and r["target_ref"]
        assert "relationship_type" in r


def test_stix_deterministic(email_scan):
    assert export(email_scan, "stix") == export(email_scan, "stix")


def test_misp_event_valid(email_scan):
    event = json.loads(export(email_scan, "misp"))["Event"]
    assert event["info"].startswith("reconweave OSINT")
    assert isinstance(event["Attribute"], list)
    for attr in event["Attribute"]:
        assert {"type", "category", "value", "uuid"} <= set(attr)
    assert event["threat_level_id"] in {"1", "2", "3", "4"}


def test_misp_email_attribute_present(email_scan):
    event = build_event(email_scan)["Event"]
    types = {a["type"] for a in event["Attribute"]}
    assert "email-src" in types


def test_unknown_format_raises(domain_scan):
    with pytest.raises(ValueError):
        export(domain_scan, "nope")
