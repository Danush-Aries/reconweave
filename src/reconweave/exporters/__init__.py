"""Export a :class:`ScanResult` to interchange formats.

Formats: json, csv, graphml (Maltego-importable), stix (STIX 2.1 bundle),
misp (MISP event). STIX and MISP are hand-built valid JSON with NO hard
third-party dependency.
"""

from __future__ import annotations

from typing import Callable, Dict

from .csv_exporter import to_csv
from .graphml_exporter import to_graphml
from .json_exporter import to_json
from .misp_exporter import to_misp
from .stix_exporter import to_stix

FORMATS: Dict[str, Callable] = {
    "json": to_json,
    "csv": to_csv,
    "graphml": to_graphml,
    "maltego": to_graphml,  # alias: Maltego imports GraphML
    "stix": to_stix,
    "misp": to_misp,
}


def export(result, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt not in FORMATS:
        raise ValueError(f"unknown export format: {fmt!r} "
                         f"(choose from {', '.join(sorted(FORMATS))})")
    return FORMATS[fmt](result)


def available_formats() -> list:
    return sorted(FORMATS)


__all__ = ["export", "available_formats", "FORMATS",
           "to_json", "to_csv", "to_graphml", "to_stix", "to_misp"]
