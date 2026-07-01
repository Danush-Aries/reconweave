"""JSON exporter: the full ScanResult as pretty JSON."""

from __future__ import annotations

import json


def to_json(result) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=False, default=str)


__all__ = ["to_json"]
