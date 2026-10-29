#!/usr/bin/env python3
"""Compare local health-request latency with cold and reused connections.

Only accepts loopback origins. The endpoint is unauthenticated liveness and
does not touch workspace data or call external providers.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any

from run_benchmark import api_path, new_client, validate_loopback

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = REPO_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from app.benchmarking import timing_summary  # noqa: E402


def measure(origin: str, *, reuse_connection: bool, samples: int, timeout: float) -> dict[str, Any]:
    timings: list[float] = []
    pooled = new_client(origin, timeout) if reuse_connection else None
    try:
        for _ in range(samples):
            client = pooled or new_client(origin, timeout)
            try:
                started = time.perf_counter()
                response = client.get(api_path("/health/live"))
                response.raise_for_status()
                response.read()
                timings.append((time.perf_counter() - started) * 1000)
            finally:
                if pooled is None:
                    client.close()
    finally:
        if pooled is not None:
            pooled.close()
    return {
        "origin": validate_loopback(origin),
        "connection_mode": "reused_client" if reuse_connection else "new_client_per_request",
        "endpoint": "GET /api/v1/health/live",
        **timing_summary(timings),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-origin", default=os.getenv("CYBERLENS_VERIFY_ORIGIN", "https://localhost:18443"))
    parser.add_argument("--api-origin", default=os.getenv("CYBERLENS_VERIFY_API_ORIGIN", "http://127.0.0.1:18000"))
    parser.add_argument("--samples", type=int, default=20, help="Requests per origin/connection mode, 1–1000")
    parser.add_argument("--timeout-seconds", type=float, default=10)
    parser.add_argument("--output", type=Path, help="Optional JSON output path; an existing file is not overwritten")
    args = parser.parse_args()
    if not 1 <= args.samples <= 1000:
        parser.error("--samples must be between 1 and 1000")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    for origin in (args.gateway_origin, args.api_origin):
        validate_loopback(origin)
    return args


def main() -> int:
    args = parse_args()
    result = {
        "result_kind": "measured",
        "test_date_utc": datetime.now(timezone.utc).isoformat(),
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "configuration": {
            "samples_per_profile": args.samples,
            "timeout_seconds": args.timeout_seconds,
            "sequence": ["gateway new", "gateway reused", "API new", "API reused"],
            "provider_requests": 0,
            "workspace_mutations": 0,
        },
        "measurements": [
            measure(args.gateway_origin, reuse_connection=False, samples=args.samples, timeout=args.timeout_seconds),
            measure(args.gateway_origin, reuse_connection=True, samples=args.samples, timeout=args.timeout_seconds),
            measure(args.api_origin, reuse_connection=False, samples=args.samples, timeout=args.timeout_seconds),
            measure(args.api_origin, reuse_connection=True, samples=args.samples, timeout=args.timeout_seconds),
        ],
        "interpretation": "Liveness-only timings compare local connection setup and reuse. They do not measure authenticated route work or public provider latency.",
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
