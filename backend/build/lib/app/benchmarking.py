"""Pure helpers shared by the opt-in benchmark CLI and its tests."""

from __future__ import annotations

from datetime import datetime
from math import ceil
from typing import Iterable


def nearest_rank_percentile(samples: Iterable[float], percentile: float) -> float | None:
    """Return a nearest-rank percentile in the units supplied by the caller."""
    values = sorted(float(value) for value in samples)
    if not values:
        return None
    if not 0 <= percentile <= 100:
        raise ValueError("percentile must be between 0 and 100")
    rank = max(1, ceil((percentile / 100) * len(values)))
    return round(values[rank - 1], 3)


def timing_summary(samples: Iterable[float]) -> dict[str, float | int | None]:
    values = sorted(float(value) for value in samples)
    if not values:
        return {"count": 0, "min": None, "mean": None, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "count": len(values),
        "min": round(values[0], 3),
        "mean": round(sum(values) / len(values), 3),
        "p50": nearest_rank_percentile(values, 50),
        "p95": nearest_rank_percentile(values, 95),
        "p99": nearest_rank_percentile(values, 99),
        "max": round(values[-1], 3),
    }


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        from datetime import timezone

        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def elapsed_ms(start: str | None, end: str | None) -> float | None:
    first, last = parse_timestamp(start), parse_timestamp(end)
    if first is None or last is None:
        return None
    return round(max(0.0, (last - first).total_seconds() * 1000), 3)
