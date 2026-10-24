"""Canvas signature validation, canonical hashing and SVG rendering (pure functions)."""

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List

MAX_STROKES = 200
MAX_POINTS = 20000
MIN_POINTS = 10
MIN_EXTENT_PX = 12
BOUNDS_TOLERANCE = 1.0


class SignatureError(ValueError):
    pass


def utc_timestamp(now: datetime = None) -> str:
    """Standardized UTC timestamp string, e.g. 2026-10-24T15:04:05.123Z."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_strokes(strokes: List[List[Dict[str, Any]]], width: int, height: int) -> List[List[Dict[str, float]]]:
    """Validate raw vector strokes and round coordinates to 0.01 px. Raises SignatureError."""
    if not strokes:
        raise SignatureError("The signature is empty")
    if len(strokes) > MAX_STROKES:
        raise SignatureError(f"Too many strokes (limit {MAX_STROKES})")
    total = sum(len(s) for s in strokes)
    if total > MAX_POINTS:
        raise SignatureError(f"Too many points (limit {MAX_POINTS})")
    if total < MIN_POINTS:
        raise SignatureError("The signature is too short; please sign again")

    out, xs, ys = [], [], []
    for stroke in strokes:
        if not stroke:
            raise SignatureError("A stroke has no points")
        last_t = -1
        norm = []
        for p in stroke:
            x, y, t = p["x"], p["y"], p["t"]
            if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (x, y, t)):
                raise SignatureError("Coordinates must be finite numbers")
            if not (-BOUNDS_TOLERANCE <= x <= width + BOUNDS_TOLERANCE and -BOUNDS_TOLERANCE <= y <= height + BOUNDS_TOLERANCE):
                raise SignatureError("A point lies outside the signature canvas")
            if t < 0 or t < last_t:
                raise SignatureError("Point timestamps must be non-negative and increasing within a stroke")
            last_t = t
            norm.append({"x": round(float(x), 2), "y": round(float(y), 2), "t": int(t)})
            xs.append(x)
            ys.append(y)
        out.append(norm)
    if max(max(xs) - min(xs), max(ys) - min(ys)) < MIN_EXTENT_PX:
        raise SignatureError("The signature is too small; please sign again")
    return out


def canonical_hash(record: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def hash_inputs(user_id: str, document_ref: str, width: int, height: int, strokes, signed_at_utc: str, ip: str) -> Dict[str, Any]:
    return {
        "user_id": str(user_id), "document_ref": document_ref, "canvas": {"width": width, "height": height},
        "strokes": strokes, "signed_at_utc": signed_at_utc, "ip_address": ip,
    }


def render_svg(strokes, width: int, height: int) -> str:
    paths = []
    for stroke in strokes:
        if len(stroke) == 1:
            p = stroke[0]
            paths.append(f'<circle cx="{p["x"]}" cy="{p["y"]}" r="1.2" fill="#0f172a"/>')
        else:
            pts = " ".join(f'{p["x"]},{p["y"]}' for p in stroke)
            paths.append(f'<polyline points="{pts}" fill="none" stroke="#0f172a" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(width)}" height="{int(height)}" viewBox="0 0 {int(width)} {int(height)}">'
        f'<rect width="100%" height="100%" fill="#ffffff"/>{"".join(paths)}</svg>'
    )
