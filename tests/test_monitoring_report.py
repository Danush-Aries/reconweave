"""Monitoring diff/alert and HTML report generation."""

import json

from reconweave.engine import Engine
from reconweave.entities import EdgeType, Entity, NodeType, Relationship
from reconweave.monitoring import Diff, WatchStore, _snapshot_of
from reconweave.report import render_html


def test_watch_baseline_then_stable(tmp_path):
    store = WatchStore(str(tmp_path / "w.db"))
    eng = Engine(use_cache=False)
    d1 = store.check("example.com", eng)
    assert not d1.changed
    assert any("baseline" in a for a in d1.alerts)
    d2 = store.check("example.com", eng)  # deterministic -> no change
    assert not d2.changed
    assert d2.new_nodes == [] and d2.removed_nodes == []
    store.close()
    eng.close()


def test_watch_detects_new_exposure(tmp_path, monkeypatch):
    store = WatchStore(str(tmp_path / "w.db"))
    eng = Engine(use_cache=False)
    # Seed a baseline snapshot with no breaches.
    store._save_snapshot("victim@example.com",
                         {"nodes": ["email:victim@example.com"], "edges": [],
                          "risk": 5, "breaches": []})
    diff = store.check("victim@example.com", eng, store=False)
    # A fresh scan will introduce nodes -> change detected.
    assert diff.changed
    assert isinstance(diff.to_dict(), dict)
    store.close()
    eng.close()


def test_watch_add_list_remove(tmp_path):
    store = WatchStore(str(tmp_path / "w.db"))
    store.add("example.com", "domain")
    assert any(w["seed"] == "example.com" for w in store.list_watches())
    store.remove("example.com")
    assert store.list_watches() == []
    store.close()


def test_snapshot_shape(domain_scan):
    snap = _snapshot_of(domain_scan)
    assert set(snap) == {"nodes", "edges", "risk", "breaches"}
    assert snap["nodes"] == sorted(snap["nodes"])


def test_diff_dataclass_changed_flag():
    d = Diff(seed="x", new_nodes=["a"])
    assert d.changed
    assert Diff(seed="x").changed is False


def test_report_is_self_contained(domain_scan):
    html = render_html(domain_scan)
    assert html.startswith("<!DOCTYPE html>")
    assert "<svg" in html  # inline SVG force graph
    assert "Exposure Risk" in html
    # No external resources.
    assert "http://" not in html.split("</style>")[0]
    assert "cdn" not in html.lower().split("<footer")[0] or "src=" not in html
    assert "<script" not in html


def test_report_contains_seed_and_risk(email_scan):
    html = render_html(email_scan)
    assert email_scan.seed.value in html
    assert str(email_scan.risk.score) in html
