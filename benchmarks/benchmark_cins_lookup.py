"""Reproducible local exact-IP index microbenchmark; never contacts providers."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date
import ipaddress
import json
import os
import platform
import random
import sys
import time
import tracemalloc


DATASET_BASE = int(ipaddress.IPv4Address("198.18.0.0"))
MISS_BASE = int(ipaddress.IPv4Address("192.0.2.0"))
SYNTHETIC_CAPACITY = 1 << 17  # 198.18.0.0/15 (RFC 2544 benchmark range)


def run(dataset_size: int, lookups: int, workers: int, seed: int) -> dict:
    if not 1 <= dataset_size <= SYNTHETIC_CAPACITY:
        raise ValueError(f"dataset size must be 1..{SYNTHETIC_CAPACITY}")
    if lookups < 1 or workers < 1:
        raise ValueError("lookups and workers must be positive")

    rng = random.Random(seed)
    tracemalloc.start()
    started = time.perf_counter()
    indexed_addresses = frozenset(
        str(ipaddress.IPv4Address(DATASET_BASE + offset)) for offset in range(dataset_size)
    )
    index_build_seconds = time.perf_counter() - started
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    queries = []
    hit_count_expected = 0
    for _ in range(lookups):
        if rng.randrange(2):
            queries.append(str(ipaddress.IPv4Address(DATASET_BASE + rng.randrange(dataset_size))))
            hit_count_expected += 1
        else:
            queries.append(str(ipaddress.IPv4Address(MISS_BASE + rng.randrange(254))))

    def lookup_batch(batch: list[str]) -> int:
        return sum(1 for candidate in batch if str(ipaddress.ip_address(candidate)) in indexed_addresses)

    batches = [queries[index::workers] for index in range(workers)]
    lookup_started = time.perf_counter()
    if workers == 1:
        hit_count = lookup_batch(batches[0])
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            hit_count = sum(pool.map(lookup_batch, batches))
    elapsed = time.perf_counter() - lookup_started
    if hit_count != hit_count_expected:
        raise RuntimeError("synthetic lookup count did not match deterministic expectation")

    return {
        "benchmark": "cins_exact_ip_index_microbenchmark",
        "date": date.today().isoformat(),
        "environment": {
            "python": sys.version.split()[0], "implementation": platform.python_implementation(),
            "os": platform.platform(), "processor": platform.processor() or "not reported",
            "logical_cpu_count": os.cpu_count(),
        },
        "dataset": {
            "size": dataset_size, "address_range": "198.18.0.0/15 (RFC 2544 synthetic benchmark range)",
            "seed": seed, "stored_index": "frozenset of canonical IPv4 strings",
        },
        "workload": {"lookups": lookups, "workers": workers, "expected_hit_rate": 0.5,
                     "actual_hits": hit_count, "actual_hit_rate": hit_count / lookups},
        "measured": {
            "index_build_seconds": round(index_build_seconds, 6),
            "lookup_elapsed_seconds": round(elapsed, 6),
            "lookups_per_second": round(lookups / elapsed, 2),
            "index_allocated_current_bytes": current_bytes,
            "index_allocated_peak_bytes": peak_bytes,
            "index_shallow_bytes": sys.getsizeof(indexed_addresses),
        },
        "scope_note": (
            "Synthetic local index microbenchmark only. It measures canonical-IP parsing and frozenset membership; "
            "it excludes provider downloads, database access, and the public-address eligibility check. "
            "The RFC 2544 range is synthetic and no network requests are made."
        ),
        "targets_included": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-size", type=int, default=15000)
    parser.add_argument("--lookups", type=int, default=100000)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--seed", type=int, default=2501)
    args = parser.parse_args()
    print(json.dumps(run(args.dataset_size, args.lookups, args.workers, args.seed), indent=2))


if __name__ == "__main__":
    main()
