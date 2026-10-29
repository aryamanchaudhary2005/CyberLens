from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from app.benchmarking import elapsed_ms, nearest_rank_percentile, parse_timestamp, timing_summary
from app.collectors.demo import demo_result
from app.cli import DEMO_ASSET_DEFINITIONS

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from benchmarks.run_benchmark import (summarize_investigations, summarize_scenario_results, validate_loopback,
                                     verify_tls_for_origin)


def test_nearest_rank_percentiles_are_deterministic_and_documentable():
    values = [12, 1, 8, 4, 16]
    assert nearest_rank_percentile(values, 50) == 8.0
    assert nearest_rank_percentile(values, 95) == 16.0
    assert nearest_rank_percentile(values, 99) == 16.0
    assert timing_summary(values) == {
        "count": 5,
        "min": 1.0,
        "mean": 8.2,
        "p50": 8.0,
        "p95": 16.0,
        "p99": 16.0,
        "max": 16.0,
    }


def test_empty_timing_samples_are_not_reported_as_zero_measurements():
    assert nearest_rank_percentile([], 95) is None
    assert timing_summary([]) == {
        "count": 0,
        "min": None,
        "mean": None,
        "p50": None,
        "p95": None,
        "p99": None,
        "max": None,
    }


def test_timestamp_helpers_handle_utc_and_missing_values():
    assert parse_timestamp("2026-10-17T12:00:00Z") == datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    assert elapsed_ms("2026-10-17T12:00:00Z", "2026-10-17T12:00:02Z") == 2000.0
    assert elapsed_ms(None, "2026-10-17T12:00:02Z") is None


def test_percentile_rejects_out_of_range_values():
    with pytest.raises(ValueError, match="between 0 and 100"):
        nearest_rank_percentile([1], 101)


def test_benchmark_scenario_manifest_matches_existing_demo_cli_assets():
    manifest = json.loads((PROJECT_ROOT / "benchmarks" / "datasets" / "demo_scenarios.json").read_text(encoding="utf-8"))
    manifest_assets = [(row["asset_kind"], row["asset_identifier"], row["key"]) for row in manifest["scenarios"]]
    cli_assets = [(kind, identifier, scenario) for kind, identifier, scenario, _notes in DEMO_ASSET_DEFINITIONS]
    assert manifest["schema_version"] == 1
    assert manifest["dataset_id"] == "cyberlens-demo-scenarios-v1"
    assert manifest_assets == cli_assets
    collectors = ("dns_rdap", "web_tls", "reputation", "hibp", "nvd_kev")
    for scenario in manifest["scenarios"]:
        asset = SimpleNamespace(identifier=scenario["asset_identifier"])
        results = [demo_result(asset, scenario["key"], collector) for collector in collectors]
        finding_categories = sorted({finding["category"] for result in results for finding in result.findings})
        unavailable = sorted(collector for collector, result in zip(collectors, results) if result.status == "unavailable")
        assert finding_categories == sorted(scenario["expected_finding_categories"])
        assert unavailable == sorted(scenario["expected_unavailable_collectors"])


def test_benchmark_refuses_non_loopback_api_origins():
    assert validate_loopback("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert validate_loopback("http://[::1]:8000") == "http://[::1]:8000"
    assert validate_loopback("https://127.0.0.1:18443") == "https://127.0.0.1:18443"
    assert validate_loopback("https://localhost:18443") == "https://localhost:18443"
    assert verify_tls_for_origin("https://127.0.0.1:18443") is False
    assert verify_tls_for_origin("https://localhost:18443") is False
    assert verify_tls_for_origin("http://127.0.0.1:8000") is True
    with pytest.raises(ValueError, match="loopback"):
        validate_loopback("http://example.com:8000")
    with pytest.raises(ValueError, match="loopback"):
        verify_tls_for_origin("https://example.com:8443")


def test_benchmark_scenario_result_keeps_the_scenario_record_for_output():
    result = summarize_scenario_results(
        [{"scenario": {"key": "routine_website", "asset_identifier": "shop.example.test"},
          "investigation": {"id": "investigation-1"}}],
        {"investigation-1": {"status": "partial", "findings": [{"category": "tls_web"}],
                             "collector_runs": [{"collector": "reputation", "status": "unavailable"}]}},
    )

    assert result == [{"scenario": "routine_website", "asset_identifier": "shop.example.test", "status": "partial",
                      "finding_categories": ["tls_web"], "unavailable_collectors": ["reputation"]}]


def test_benchmark_aggregates_attempts_outages_and_duplicate_signatures():
    summary = summarize_investigations({
        "routine": {
            "id": "routine", "scenario": "routine_website", "status": "completed",
            "attempts": [{"created_at": "2026-10-17T12:00:00Z", "started_at": "2026-10-17T12:00:00.250Z",
                          "finished_at": "2026-10-17T12:00:02.250Z"}],
            "collector_runs": [{"status": "success"}, {"status": "unavailable"}],
            "findings": [
                {"category": "tls_web", "severity": "low", "title": "Same finding", "source": "Synthetic"},
                {"category": "tls_web", "severity": "low", "title": "Same finding", "source": "Synthetic"},
            ],
        },
        "outage": {
            "id": "outage", "scenario": "provider_outage", "status": "failed",
            "attempts": [
                {"created_at": "2026-10-17T12:00:00Z", "started_at": "2026-10-17T12:00:00Z",
                 "finished_at": "2026-10-17T12:00:01Z"},
                {"created_at": "2026-10-17T12:00:02Z", "started_at": "2026-10-17T12:00:02.500Z",
                 "finished_at": "2026-10-17T12:00:03Z"},
            ],
            "collector_runs": [{"status": "success"}],
            "findings": [],
        },
    })
    assert summary["investigation_count"] == 2
    assert summary["attempt_count"] == 3
    assert summary["queue_wait_ms"]["count"] == 3
    assert summary["investigation_duration_ms"]["count"] == 3
    assert summary["investigation_retry_rate"] == 0.5
    assert summary["investigation_failure_rate"] == 0.5
    assert summary["collector_status_counts"] == {"success": 2, "unavailable": 1}
    assert summary["collector_unavailable_rate"] == 0.3333
    assert summary["finding_signature_duplicate_rate"] == 0.5
    assert summary["duplicate_finding_signatures"] == 1
