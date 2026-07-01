"""FastAPI surface for reconweave (OpenAPI at /docs).

Endpoints:
  GET  /health            -> liveness + version
  GET  /collectors        -> collector catalog
  POST /scan              -> run a scan, return summary + graph
  POST /export/{fmt}      -> run a scan and return an export
  GET  /seed-type/{value} -> classify a seed
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import __version__, collectors as collectors_pkg
from .engine import Engine
from .exporters import available_formats, export
from .risk import compute_risk  # noqa: F401 (kept for API completeness)
from .seeds import detect

app = FastAPI(
    title="reconweave",
    version=__version__,
    description="Offline-first OSINT correlation platform. "
                "Synthetic deterministic data by default; --live for real sources.",
)


class ScanRequest(BaseModel):
    seed: str
    type: Optional[str] = None
    live: bool = False


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "reconweave", "version": __version__,
            "collectors": len(collectors_pkg.all_collectors())}


@app.get("/collectors")
def list_collectors() -> Dict[str, Any]:
    cat = collectors_pkg.catalog()
    return {"count": len(cat), "collectors": cat}


@app.get("/seed-type/{value}")
def seed_type(value: str) -> Dict[str, Any]:
    return {"value": value, "type": detect(value).value}


@app.post("/scan")
def scan(req: ScanRequest) -> Dict[str, Any]:
    eng = Engine(use_cache=False)
    try:
        result = eng.scan(req.seed, req.type, live=req.live)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        eng.close()
    return result.to_dict()


@app.post("/export/{fmt}", response_class=PlainTextResponse)
def export_scan(fmt: str, req: ScanRequest) -> str:
    if fmt not in available_formats():
        raise HTTPException(status_code=404,
                            detail=f"unknown format; choose {available_formats()}")
    eng = Engine(use_cache=False)
    try:
        result = eng.scan(req.seed, req.type, live=req.live)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        eng.close()
    return export(result, fmt)


__all__ = ["app"]
