"""CLI and API smoke tests."""

import json

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from reconweave.api import app
from reconweave.cli import app as cli_app

runner = CliRunner()
client = TestClient(app)


# --- CLI ------------------------------------------------------------------
def test_cli_scan_runs(tmp_path):
    result = runner.invoke(cli_app, ["scan", "example.com", "--no-cache"])
    assert result.exit_code == 0
    assert "reconweave scan" in result.stdout
    assert "Exposure risk" in result.stdout


def test_cli_collectors_lists_20():
    result = runner.invoke(cli_app, ["collectors"])
    assert result.exit_code == 0
    assert "collectors (20)" in result.stdout


def test_cli_export_stix(tmp_path):
    out = tmp_path / "b.json"
    result = runner.invoke(cli_app, ["export", "jane@example.com",
                                     "--format", "stix", "--out", str(out)])
    assert result.exit_code == 0
    bundle = json.loads(out.read_text())
    assert bundle["type"] == "bundle"


def test_cli_report_writes_html(tmp_path):
    out = tmp_path / "r.html"
    result = runner.invoke(cli_app, ["report", "someuser", "--type", "username",
                                     "--out", str(out)])
    assert result.exit_code == 0
    assert out.read_text().startswith("<!DOCTYPE html>")


def test_cli_version():
    result = runner.invoke(cli_app, ["version"])
    assert result.exit_code == 0
    assert "reconweave" in result.stdout


# --- API ------------------------------------------------------------------
def test_api_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["collectors"] == 20


def test_api_collectors():
    resp = client.get("/collectors")
    assert resp.status_code == 200
    assert resp.json()["count"] == 20


def test_api_seed_type():
    resp = client.get("/seed-type/example.com")
    assert resp.json()["type"] == "domain"


def test_api_scan():
    resp = client.post("/scan", json={"seed": "example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["seed"]["type"] == "domain"
    assert body["stats"]["nodes"] > 0
    assert "risk" in body


def test_api_export_stix():
    resp = client.post("/export/stix", json={"seed": "jane@example.com"})
    assert resp.status_code == 200
    assert json.loads(resp.text)["type"] == "bundle"


def test_api_openapi_available():
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "reconweave"
