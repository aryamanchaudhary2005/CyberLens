#!/usr/bin/env python3
"""Run an opt-in synthetic workload against a local Demo stack.

This script only creates investigations and immutable reports. It never resets,
deletes, or updates workspace records, and sends credentials only to loopback.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = REPO_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from app.benchmarking import elapsed_ms, timing_summary  # noqa: E402

DATASET_PATH = Path(__file__).parent / "datasets" / "demo_scenarios.json"
API_SUFFIX = "/api/v1"
TERMINAL_STATUSES = {"completed", "partial", "failed"}


def load_dataset() -> dict[str, Any]:
    raw = DATASET_PATH.read_bytes()
    dataset = json.loads(raw)
    dataset["sha256"] = hashlib.sha256(raw).hexdigest()
    return dataset


def validate_loopback(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("base URL must be an HTTP or HTTPS loopback IP or localhost origin without embedded credentials")
    host = parsed.hostname.casefold()
    try:
        loopback = ipaddress_is_loopback(host)
    except ValueError:
        loopback = host == "localhost" and localhost_resolves_to_loopback(parsed)
    if not loopback:
        raise ValueError("benchmark credentials are permitted only for a loopback IP or localhost address")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("base URL must be an origin such as http://127.0.0.1:8000")
    return f"{parsed.scheme}://{parsed.netloc}"


def verify_tls_for_origin(url: str) -> bool:
    """Trust normal certificates everywhere; allow the self-signed TLS cert only on validated loopback."""
    parsed = urlsplit(validate_loopback(url))
    return parsed.scheme != "https"


def new_client(base_url: str, timeout: float, **kwargs: Any) -> httpx.Client:
    validated_url = validate_loopback(base_url)
    return httpx.Client(base_url=validated_url, timeout=timeout, trust_env=False,
                        verify=verify_tls_for_origin(validated_url), **kwargs)


def ipaddress_is_loopback(host: str) -> bool:
    import ipaddress

    return ipaddress.ip_address(host).is_loopback


def localhost_resolves_to_loopback(parsed: Any) -> bool:
    import ipaddress

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo("localhost", port, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ipaddress.ip_address(address).is_loopback for address in addresses)
    except (OSError, ValueError):
        return False


def api_path(path: str) -> str:
    return f"{API_SUFFIX}{path}"


def request_json(client: httpx.Client, method: str, path: str, **kwargs: Any) -> tuple[httpx.Response, Any]:
    response = client.request(method, api_path(path), **kwargs)
    response.raise_for_status()
    if response.content:
        return response, response.json()
    return response, None


def list_all_assets(client: httpx.Client) -> tuple[list[dict[str, Any]], int]:
    page_size = 250
    response, first_page = request_json(client, "GET", f"/assets?page=1&page_size={page_size}&sort=identifier&order=asc")
    total = int(response.headers.get("X-Total-Count", len(first_page)))
    assets = list(first_page)
    page = 2
    while len(assets) < total:
        _, rows = request_json(client, "GET", f"/assets?page={page}&page_size={page_size}&sort=identifier&order=asc")
        if not rows:
            break
        assets.extend(rows)
        page += 1
    if len(assets) < total:
        raise RuntimeError(f"Asset pagination returned {len(assets)} of {total} records")
    return assets, total


def client_resource_snapshot() -> dict[str, Any]:
    snapshot: dict[str, Any] = {"process_cpu_seconds": round(time.process_time(), 3), "peak_rss_bytes": None,
                                "measurement": "benchmark client process"}
    try:
        if os.name == "nt":
            import ctypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            process = ctypes.windll.kernel32.GetCurrentProcess()
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb)
            if ok:
                snapshot["peak_rss_bytes"] = int(counters.PeakWorkingSetSize)
                snapshot["working_set_bytes"] = int(counters.WorkingSetSize)
                snapshot["page_fault_count"] = int(counters.PageFaultCount)
        else:
            import resource

            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            snapshot["peak_rss_bytes"] = int(peak if platform.system() == "Darwin" else peak * 1024)
    except (ImportError, OSError, AttributeError):
        snapshot["measurement_note"] = "process memory API was unavailable on this platform"
    return snapshot


def system_memory_bytes() -> int | None:
    try:
        if os.name == "nt":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        else:
            return int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, AttributeError, ValueError):
        return None
    return None


def docker_stats_snapshot() -> dict[str, Any]:
    if not shutil_which("docker"):
        return {"available": False, "reason": "Docker CLI is not installed"}
    try:
        listed = subprocess.run(["docker", "compose", "ps", "-q"], cwd=REPO_ROOT,
                                check=True, capture_output=True, text=True, timeout=8)
        container_ids = [value.strip() for value in listed.stdout.splitlines() if value.strip()]
        if not container_ids:
            return {"available": False, "reason": "No running CyberLens Compose containers were listed"}
        result = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}", *container_ids],
                                cwd=REPO_ROOT, check=True, capture_output=True, text=True, timeout=8)
        containers = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return {"available": True, "containers": containers}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"available": False, "reason": f"Docker stats unavailable: {type(exc).__name__}"}


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


def authenticated_client(base_url: str, username: str, password: str, timeout: float) -> tuple[httpx.Client, str]:
    client = new_client(base_url, timeout, follow_redirects=False)
    _, csrf_payload = request_json(client, "GET", "/auth/csrf")
    csrf_token = str(csrf_payload["csrf_token"])
    _, login_payload = request_json(client, "POST", "/auth/login", json={"username": username, "password": password},
                                    headers={"X-CSRF-Token": csrf_token})
    return client, str(login_payload["csrf_token"])


def measure_api_latency(base_url: str, cookies: dict[str, str], requests: int,
                        concurrency: int, timeout: float) -> tuple[dict[str, Any], list[float]]:
    def sample(_: int) -> tuple[float, int]:
        with new_client(base_url, timeout, cookies=cookies) as client:
            started = time.perf_counter()
            response = client.get(api_path("/assets?page=1&page_size=25&sort=identifier&order=asc"))
            duration = (time.perf_counter() - started) * 1000
            response.raise_for_status()
            response.read()
            return duration, len(response.content)

    timings: list[float] = []
    response_bytes = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(sample, index) for index in range(requests)]
        for future in as_completed(futures):
            duration, size = future.result()
            timings.append(duration)
            response_bytes += size
    return {**timing_summary(timings), "endpoint": "GET /api/v1/assets?page=1&page_size=25&sort=identifier&order=asc",
            "concurrency": concurrency, "response_bytes_total": response_bytes,
            "samples_include_new_local_http_connections": True}, timings


def start_investigation(base_url: str, cookies: dict[str, str], csrf: str,
                        asset_id: str, scenario: str, timeout: float) -> dict[str, Any]:
    with new_client(base_url, timeout, cookies=cookies) as client:
        _, payload = request_json(client, "POST", "/investigations", json={"asset_id": asset_id, "scenario": scenario},
                                  headers={"X-CSRF-Token": csrf})
        return payload


def get_investigation(base_url: str, cookies: dict[str, str], investigation_id: str,
                      timeout: float) -> dict[str, Any]:
    with new_client(base_url, timeout, cookies=cookies) as client:
        _, payload = request_json(client, "GET", f"/investigations/{investigation_id}")
        return payload


def wait_for_investigations(base_url: str, cookies: dict[str, str], ids: list[str],
                            timeout_seconds: float, request_timeout: float,
                            concurrency: int, poll_seconds: float) -> dict[str, dict[str, Any]]:
    pending = set(ids)
    completed: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + timeout_seconds
    while pending and time.monotonic() < deadline:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(get_investigation, base_url, cookies, item_id, request_timeout): item_id
                       for item_id in sorted(pending)}
            for future in as_completed(futures):
                item_id = futures[future]
                value = future.result()
                if value["status"] in TERMINAL_STATUSES:
                    completed[item_id] = value
                    pending.discard(item_id)
        if pending:
            time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))
    if pending:
        raise TimeoutError(f"Timed out waiting for {len(pending)} investigations: {', '.join(sorted(pending))}")
    return completed


def finding_signature(item: dict[str, Any]) -> str:
    return json.dumps([item.get("category"), item.get("severity"), item.get("title"), item.get("source")],
                      ensure_ascii=False, separators=(",", ":")).casefold()


def summarize_investigations(details: dict[str, dict[str, Any]]) -> dict[str, Any]:
    queue_wait_ms: list[float] = []
    durations_ms: list[float] = []
    total_attempts = retry_investigations = failed_investigations = 0
    collector_counts: dict[str, int] = {}
    unavailable_collectors = 0
    finding_occurrences = duplicate_signatures = 0
    per_scenario = []
    for detail in details.values():
        attempts = detail.get("attempts", [])
        total_attempts += len(attempts)
        retry_investigations += int(len(attempts) > 1)
        failed_investigations += int(detail.get("status") == "failed")
        attempt_queue = []
        attempt_duration = []
        for attempt in attempts:
            wait = elapsed_ms(attempt.get("created_at"), attempt.get("started_at"))
            duration = elapsed_ms(attempt.get("started_at"), attempt.get("finished_at"))
            if wait is not None:
                queue_wait_ms.append(wait)
                attempt_queue.append(wait)
            if duration is not None:
                durations_ms.append(duration)
                attempt_duration.append(duration)
        run_statuses: dict[str, int] = {}
        for run in detail.get("collector_runs", []):
            status = str(run.get("status", "unknown"))
            collector_counts[status] = collector_counts.get(status, 0) + 1
            run_statuses[status] = run_statuses.get(status, 0) + 1
            unavailable_collectors += int(status == "unavailable")
        findings = detail.get("findings", [])
        signatures = [finding_signature(item) for item in findings]
        finding_occurrences += len(signatures)
        duplicate_signatures += len(signatures) - len(set(signatures))
        per_scenario.append({"investigation_id": detail["id"], "scenario": detail.get("scenario"),
                             "status": detail.get("status"), "attempt_count": len(attempts),
                             "queue_wait_ms": attempt_queue, "investigation_duration_ms": attempt_duration,
                             "collector_status_counts": run_statuses, "finding_count": len(findings)})
    count = len(details)
    total_collectors = sum(collector_counts.values())
    return {
        "investigation_count": count,
        "attempt_count": total_attempts,
        "queue_wait_ms": timing_summary(queue_wait_ms),
        "investigation_duration_ms": timing_summary(durations_ms),
        "investigation_retry_rate": round(retry_investigations / count, 4) if count else None,
        "investigation_failure_rate": round(failed_investigations / count, 4) if count else None,
        "collector_status_counts": collector_counts,
        "collector_unavailable_rate": round(unavailable_collectors / total_collectors, 4) if total_collectors else None,
        "finding_signature_duplicate_rate": round(duplicate_signatures / finding_occurrences, 4) if finding_occurrences else 0.0,
        "finding_occurrences": finding_occurrences,
        "duplicate_finding_signatures": duplicate_signatures,
        "scenarios": sorted(per_scenario, key=lambda item: str(item.get("scenario"))),
        "metric_definitions": {
            "queue_wait_ms": "attempt.started_at minus attempt.created_at",
            "investigation_duration_ms": "attempt.finished_at minus attempt.started_at; aggregated across attempts",
            "investigation_retry_rate": "investigations with more than one persisted attempt divided by benchmark investigations",
            "investigation_failure_rate": "terminal failed investigations divided by benchmark investigations",
            "collector_unavailable_rate": "unavailable collector runs divided by all persisted collector runs",
            "finding_signature_duplicate_rate": "repeated category/severity/title/source signatures within the same investigation divided by all finding occurrences; this is not a database uniqueness audit",
        },
    }


def summarize_scenario_results(queued: list[dict[str, Any]], details: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    scenario_by_id = {item["investigation"]["id"]: item["scenario"] for item in queued}
    results = []
    for investigation_id, detail in details.items():
        scenario = scenario_by_id[investigation_id]
        results.append({"scenario": scenario["key"], "asset_identifier": scenario["asset_identifier"],
                        "status": detail["status"],
                        "finding_categories": sorted({finding["category"] for finding in detail.get("findings", [])}),
                        "unavailable_collectors": sorted({run["collector"] for run in detail.get("collector_runs", [])
                                                           if run["status"] == "unavailable"})})
    return sorted(results, key=lambda item: item["scenario"])


def generate_reports(base_url: str, cookies: dict[str, str], csrf: str,
                    details: dict[str, dict[str, Any]], timeout: float) -> tuple[dict[str, Any], list[float]]:
    durations: list[float] = []
    report_ids = []
    for detail in details.values():
        with new_client(base_url, timeout, cookies=cookies) as client:
            started = time.perf_counter()
            _, report = request_json(client, "POST", "/reports", json={"format": "json", "investigation_id": detail["id"]},
                                     headers={"X-CSRF-Token": csrf})
            durations.append((time.perf_counter() - started) * 1000)
            report_ids.append(report["id"])
    return {**timing_summary(durations), "format": "json", "report_ids": report_ids}, durations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("CYBERLENS_BENCHMARK_BASE_URL", "http://127.0.0.1:8000"),
                        help="Loopback API origin; defaults to http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=100, help="API collection requests; default 100")
    parser.add_argument("--concurrency", type=int, default=5, help="Maximum parallel API and job submissions; default 5")
    parser.add_argument("--timeout-seconds", type=float, default=180, help="Investigation completion timeout; default 180")
    parser.add_argument("--request-timeout-seconds", type=float, default=10, help="Per-request HTTP timeout; default 10")
    parser.add_argument("--poll-seconds", type=float, default=0.5, help="Polling interval in seconds; default 0.5")
    parser.add_argument("--output", type=Path, help="Optional JSON output path; existing files are never overwritten")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (args.requests < 1 or args.concurrency < 1 or args.timeout_seconds <= 0 or
            args.request_timeout_seconds <= 0 or args.poll_seconds <= 0):
        raise SystemExit("requests, concurrency, and timeouts must be positive")
    if args.output and args.output.exists():
        raise SystemExit(f"Refusing to overwrite existing benchmark output: {args.output}")
    username = os.environ.get("CYBERLENS_BENCHMARK_USERNAME", "")
    password = os.environ.get("CYBERLENS_BENCHMARK_PASSWORD", "")
    if not username or not password:
        raise SystemExit("Set CYBERLENS_BENCHMARK_USERNAME and CYBERLENS_BENCHMARK_PASSWORD; credentials are not accepted as command-line arguments.")
    try:
        base_url = validate_loopback(args.base_url)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    dataset = load_dataset()
    started_at = datetime.now(timezone.utc).isoformat()
    client_before = client_resource_snapshot()
    docker_before = docker_stats_snapshot()
    process_cpu_before = time.process_time()
    wall_started = time.perf_counter()
    client, csrf = authenticated_client(base_url, username, password, args.request_timeout_seconds)
    try:
        _, readiness = request_json(client, "GET", "/health/ready")
        if readiness.get("mode") != "demo" or readiness.get("demo_data") is not True:
            raise SystemExit("Refusing benchmark: API is not in offline Demo mode")
        if not readiness.get("dependencies", {}).get("worker"):
            raise SystemExit("Refusing benchmark: worker readiness is false")
        cookies = dict(client.cookies.items())

        api_results, _ = measure_api_latency(base_url, cookies, args.requests, args.concurrency, args.request_timeout_seconds)
        assets, workspace_asset_count = list_all_assets(client)
        assets_by_identifier = {item["identifier"]: item for item in assets}
        missing = [item["asset_identifier"] for item in dataset["scenarios"] if item["asset_identifier"] not in assets_by_identifier]
        if missing:
            raise SystemExit("Demo fixture assets are missing. Seed only the missing fixtures with: " + dataset["seed_command"])

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {
                pool.submit(start_investigation, base_url, cookies, csrf,
                            assets_by_identifier[scenario["asset_identifier"]]["id"], scenario["key"],
                            args.request_timeout_seconds): scenario
                for scenario in dataset["scenarios"]
            }
            queued = []
            for future in as_completed(futures):
                scenario = futures[future]
                queued.append({"scenario": scenario, "investigation": future.result()})
        details_by_id = wait_for_investigations(base_url, cookies, [item["investigation"]["id"] for item in queued],
                                                args.timeout_seconds, args.request_timeout_seconds, args.concurrency,
                                                args.poll_seconds)
        investigation_summary = summarize_investigations(details_by_id)
        reports, report_times = generate_reports(base_url, cookies, csrf, details_by_id, args.request_timeout_seconds)
        _, operations = request_json(client, "GET", "/metrics")
    finally:
        try:
            client.post(api_path("/auth/logout"), headers={"X-CSRF-Token": csrf}, timeout=args.request_timeout_seconds)
        except httpx.HTTPError:
            pass
        client.close()

    wall_seconds = time.perf_counter() - wall_started
    process_cpu_seconds = time.process_time() - process_cpu_before
    client_after = client_resource_snapshot()
    docker_after = docker_stats_snapshot()
    scenario_results = summarize_scenario_results(queued, details_by_id)

    output = {
        "result_kind": "measured",
        "targets_included": False,
        "test_date_utc": started_at,
        "git_revision": git_revision(),
        "hardware": {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor() or None,
                     "benchmark_client_python": platform.python_version(),
                     "logical_cpu_count": os.cpu_count(), "system_memory_bytes": system_memory_bytes()},
        "dataset": {"id": dataset["dataset_id"], "schema_version": dataset["schema_version"],
                    "scenario_count": len(dataset["scenarios"]), "fixture_asset_count": len(dataset["scenarios"]),
                    "workspace_asset_count": workspace_asset_count,
                    "fixture_sha256": dataset["sha256"], "investigation_count": len(details_by_id),
                    "finding_count": investigation_summary["finding_occurrences"]},
        "configuration": {"api_origin": base_url, "mode": readiness["mode"], "api_requests": args.requests,
                          "concurrency": args.concurrency, "investigation_timeout_seconds": args.timeout_seconds,
                          "request_timeout_seconds": args.request_timeout_seconds, "poll_interval_seconds": args.poll_seconds,
                          "report_format": "json"},
        "api_latency_ms": api_results,
        "investigations": investigation_summary,
        "investigation_scenarios": scenario_results,
        "report_generation_ms": reports,
        "runtime_metrics_snapshot": operations,
        "resource_use": {"wall_seconds": round(wall_seconds, 3), "benchmark_client_cpu_seconds": round(process_cpu_seconds, 3),
                         "benchmark_client_before": client_before, "benchmark_client_after": client_after,
                         "docker_stats_before": docker_before, "docker_stats_after": docker_after},
    }
    serialized = json.dumps(output, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(serialized + "\n")
        except FileExistsError as exc:
            raise SystemExit(f"Refusing to overwrite existing benchmark output: {args.output}") from exc
    print(serialized)
    return 0


def git_revision() -> str | None:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                                capture_output=True, text=True, timeout=2, check=True)
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
