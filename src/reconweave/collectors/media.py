"""Media collectors (2): exif (Pillow) and reverse_image (perceptual hash).

Both operate on a file path when one is available (real, deterministic
computation via Pillow) and otherwise synthesize deterministic metadata
from the seed so the pipeline still runs fully offline.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .. import _rng
from ..entities import EdgeType, Entity, NodeType, Relationship
from ..seeds import SeedType
from .base import Collector, CollectorResult, register

try:  # Pillow is a hard dep but guard so import never breaks the registry.
    from PIL import Image  # type: ignore

    _HAVE_PIL = True
except Exception:  # pragma: no cover
    _HAVE_PIL = False

_CAMERAS = [("Apple", "iPhone 13"), ("Canon", "EOS R5"), ("Nikon", "D850"),
            ("Samsung", "Galaxy S22"), ("DJI", "Mavic 3")]


def _resolve_path(value: str, ctx: Dict[str, Any]) -> Optional[str]:
    candidate = ctx.get("file") or value
    if candidate and isinstance(candidate, str) and os.path.isfile(candidate):
        return candidate
    return None


def _average_hash(path: str, size: int = 8) -> Optional[str]:
    if not _HAVE_PIL:
        return None
    try:
        with Image.open(path) as im:
            im = im.convert("L").resize((size, size))
            pixels = list(im.getdata())
            avg = sum(pixels) / len(pixels)
            bits = "".join("1" if p >= avg else "0" for p in pixels)
            return f"{int(bits, 2):0{size * size // 4}x}"
    except Exception:  # pragma: no cover
        return None


@register
class ExifCollector(Collector):
    name = "exif"
    category = "media"
    description = "Extracts EXIF (GPS, camera, timestamp) from an image via Pillow."
    accepts = (SeedType.FILE_HASH,)
    base_confidence = 0.7

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        path = _resolve_path(value, ctx)
        attrs: Dict[str, Any] = {"kind": "image"}
        real_exif = {}
        if path and _HAVE_PIL:
            try:
                with Image.open(path) as im:
                    attrs["format"] = im.format
                    attrs["size"] = list(im.size)
                    exif = getattr(im, "_getexif", lambda: None)() or {}
                    real_exif = {str(k): str(v) for k, v in exif.items()}
            except Exception:  # pragma: no cover
                pass
        if not real_exif:
            make, model = _rng.pick(r, _CAMERAS)
            attrs.update({
                "camera_make": make, "camera_model": model,
                "datetime": _rng.iso_date(r, 2018, 2024) + " 1%d:%02d:%02d" % (
                    r.randint(0, 9), r.randint(0, 59), r.randint(0, 59)),
                "gps": {"lat": round(r.uniform(-60, 60), 5),
                        "lon": round(r.uniform(-120, 120), 5)},
                "software": _rng.pick(r, ["Adobe Lightroom", "iOS 17", "GIMP 2.10"]),
                "synthetic": True,
            })
        else:
            attrs["exif"] = real_exif
        media_id = value if seed_type == SeedType.FILE_HASH else _rng.fingerprint(value)
        # A media artifact is modelled as a generic SOCIAL_PROFILE-class node.
        node = Entity(NodeType.SOCIAL_PROFILE, f"image:{media_id[:16]}",
                      confidence=self.base_confidence, attributes=attrs)
        return CollectorResult([node], [], self.name, self.base_confidence,
                               raw=attrs)


@register
class ReverseImageCollector(Collector):
    name = "reverse_image"
    category = "media"
    description = "Perceptual (average) hash for reverse-image matching via Pillow."
    accepts = (SeedType.FILE_HASH,)
    base_confidence = 0.55

    def run(self, value: str, seed_type: SeedType, ctx: Dict[str, Any]) -> CollectorResult:
        r = _rng.rng(self.name, value)
        path = _resolve_path(value, ctx)
        phash = _average_hash(path) if path else None
        if phash is None:
            phash = _rng.fingerprint("phash:" + value, 16)
            computed = False
        else:
            computed = True
        media_id = value if seed_type == SeedType.FILE_HASH else _rng.fingerprint(value)
        node = Entity(NodeType.SOCIAL_PROFILE, f"image:{media_id[:16]}",
                      confidence=self.base_confidence,
                      attributes={"phash": phash, "phash_computed": computed})
        entities = [node]
        rels = []
        # Simulate a reverse-image hit linking to an online profile.
        if _rng.chance(r, 0.4):
            handle = "user" + phash[:6]
            prof = Entity(NodeType.SOCIAL_PROFILE, f"instagram:{handle}",
                          confidence=0.4,
                          attributes={"platform": "Instagram", "match": "reverse-image"})
            entities.append(prof)
            rels.append(Relationship(node.id, prof.id, EdgeType.LINKED_TO,
                                     confidence=0.4,
                                     attributes={"method": "reverse-image", "phash": phash}))
        return CollectorResult(entities, rels, self.name, self.base_confidence,
                               raw={"phash": phash, "computed": computed})
