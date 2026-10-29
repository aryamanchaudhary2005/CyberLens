"""Deterministic synthetic results. This module never performs network I/O."""

from app.collectors.types import CollectorResult
from app.collectors.common import finding, now_iso
import json
from pathlib import Path


def demo_result(asset, scenario: str, collector: str, components=None) -> CollectorResult:
    observed_at = now_iso()
    source = {
        "dns_rdap": "Synthetic DNS and RDAP fixture",
        "web_tls": "Synthetic website and TLS fixture",
        "reputation": "Synthetic VirusTotal fixture",
        "hibp": "Synthetic HIBP fixture",
        "xposedornot": "Synthetic XposedOrNot fixture",
        "spamhaus_drop": "Synthetic Spamhaus DROP fixture",
        "cins_army": "Synthetic CINS Army fixture",
        "openphish": "Synthetic OpenPhish fixture",
        "nvd_kev": "Synthetic NVD and CISA KEV fixture",
        "osv": "Synthetic OSV package fixture",
    }[collector]
    evidence = {"demo_data": True, "scenario": scenario, "observed_at": observed_at}
    findings: list[dict] = []

    if collector == "dns_rdap":
        evidence.update({"submitted_host": asset.identifier, "records": {"A": {"status": "success", "values": ["203.0.113.10"]},
            "AAAA": {"status": "no_match", "values": []}, "MX": {"status": "success", "values": ["10 mail.example.test"]},
            "NS": {"status": "success", "values": ["ns1.example.test"]}, "TXT": {"status": "success", "values": ["v=spf1 -all"]},
            "CAA": {"status": "success", "values": ["0 issue \"example.test\""]}, "DMARC": {"status": "success", "values": ["v=DMARC1; p=none"]}},
            "email_configuration": {"mx_present": True, "spf_present": True, "dmarc_present": True},
            "rdap": {"status": "success", "registrar": "Example Registrar (synthetic)", "redacted_fields": ["registrant"]},
            "relationships": [{"from": asset.identifier, "to": "203.0.113.10", "observed_at": observed_at}]})
        if scenario == "routine_website":
            findings.append(finding("dns_email", "low", "DMARC policy is monitor only", "The synthetic domain has mail records but uses a monitoring-only DMARC policy.", "Review aggregate reports and consider a staged move to quarantine or reject.", source))
    elif collector == "web_tls":
        evidence.update({"https": {"available": True, "status_code": 200, "redirects": [], "tls_version": "TLSv1.3"},
            "certificate": {"issuer": "Example CA (synthetic)", "hostname_match": True, "trust_valid": True, "expired": False, "days_until_expiry": 90},
            "security_headers": {"strict-transport-security": "max-age=31536000"}})
        if scenario in {"suspicious_website", "provider_outage"}:
            evidence["https"].update({"status_code": 302, "redirects": ["https://login.example.test/"]})
            findings.append(finding("tls_web", "medium", "Unexpected login redirect", "The synthetic website redirects to an unfamiliar login path. This fixture is a review prompt, not evidence of compromise.", "Confirm the redirect with the website owner and inspect the authorized destination.", source, {"demo_data": True}))
        if scenario == "routine_website":
            findings.append(finding("tls_web", "low", "Content Security Policy not observed", "The synthetic HTTPS response omits a Content-Security-Policy header.", "Define and test a site-appropriate Content Security Policy.", source))
    elif collector == "reputation":
        if scenario == "provider_outage":
            return CollectorResult(status="unavailable", source=source, evidence={**evidence, "provider_status": "simulated_quota"}, error_explanation="Synthetic provider outage: quota unavailable. No reputation verdict was generated.")
        malicious = 3 if scenario in {"suspicious_website", "openphish_overlap"} else 0
        suspicious = 1 if scenario in {"suspicious_website", "openphish_overlap"} else 0
        evidence.update({"asset_context": "direct", "analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": 70}, "last_analysis_date": observed_at})
        if malicious or suspicious:
            findings.append(finding("reputation", "high" if malicious >= 2 else "medium", "Synthetic adverse reputation verdicts", "Bundled demo data contains adverse verdicts for this submitted asset.", "Review each provider and verify asset ownership before deciding on response.", source, {"malicious": malicious, "suspicious": suspicious, "asset_context": "direct", "demo_data": True}))
    elif collector == "hibp":
        if scenario == "provider_outage":
            return CollectorResult(status="unavailable", source=source, evidence={**evidence, "provider_status": "simulated_rate_limit"}, error_explanation="Synthetic provider outage: HIBP rate limit reached. No breach record was fabricated.")
        breaches = [{"name": "ExampleBreach", "title": "Example Breach (synthetic)", "breach_date": "2024-03-01", "data_classes": ["Email addresses", "Passwords"]}] if scenario == "exposed_email" else []
        evidence.update({"breaches": breaches, "breach_count": len(breaches), "account_context": "historical exposure"})
        if breaches:
            findings.append(finding("breach_exposure", "medium", "Historical email breach exposure (demo)", "Synthetic fixture reports historical exposure. It does not show the account is currently compromised.", "Confirm ownership, review exposed data categories, and follow the account protection process.", source, {"breach_count": 1, "account_context": "historical exposure", "demo_data": True}))
    elif collector == "xposedornot":
        if scenario == "provider_outage":
            return CollectorResult(status="unavailable", source=source,
                evidence={**evidence, "provider_status": "simulated_unavailable", "records": []},
                error_explanation="Synthetic XposedOrNot provider outage. No breach record was fabricated.")
        records = ([{"record_id": "XON-DEMO-2024", "name": "ExampleBreach (synthetic)",
            "breach_date": "2024-03-01", "exposed_data": ["Email addresses", "Passwords"],
            "verified": True, "verification_value": "synthetic fixture", "source": "XposedOrNot"}]
            if scenario == "exposed_email" else [])
        evidence.update({"provider_status": "found" if records else "no_match",
            "result": "found" if records else "no_match", "records": records,
            "verification_flags": [], "breach_count": len(records),
            "verified_record_count": len(records), "account_context": "historical exposure",
            "coverage_note": "Synthetic XposedOrNot fixture; coverage differs from HIBP."})
        if not records:
            evidence["no_match_message"] = "No record found in this provider's dataset."
        if records:
            findings.append(finding("breach_exposure", "medium", "Verified historical email breach exposure (demo)",
                "Synthetic XposedOrNot fixture reports verified historical exposure. It does not show the account is currently compromised.",
                "Review the synthetic exposed-data categories and follow the account protection process.", source,
                {"provider": "xposedornot", "breach_count": 1,
                 "verified_record_ids": ["XON-DEMO-2024"], "account_context": "historical exposure", "demo_data": True}))
    elif collector == "spamhaus_drop":
        fixture_path = Path(__file__).resolve().parents[1] / "data" / "spamhaus_drop_demo.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        matches = []
        if asset.kind == "ip" and scenario not in {"ip_cins_only", "ip_no_match"}:
            import ipaddress

            try:
                address = ipaddress.ip_address(asset.identifier)
                for item in fixture["networks"]:
                    network = ipaddress.ip_network(item["network"], strict=True)
                    if address.version == network.version and address in network:
                        matches.append({"network": network.with_prefixlen, "sbl_id": item["sbl_id"]})
            except ValueError:
                matches = []
        evidence.update({"provider": "Synthetic Spamhaus DROP fixture",
            "provider_version": fixture["fixture_version"],
            "provider_status": "listed" if matches else "not_listed_in_snapshot",
            "result": "listed" if matches else "not_listed_in_snapshot",
            "match_scope": "direct_public_ip", "asset_ip": asset.identifier,
            "snapshot_id": "synthetic-spamhaus-drop-demo-v1", "content_sha256": None,
            "parser_version": fixture["fixture_version"], "snapshot_record_count": len(fixture["networks"]),
            "snapshot_retrieved_at": None, "provider_published_at": None,
            "last_successful_revalidation_at": None, "snapshot_age_seconds": 0,
            "freshness": "synthetic", "attribution": fixture["attribution"],
            "matched_networks": matches,
            "coverage_note": "Synthetic Demo fixture only. It is not provider data and does not establish safety or complete reputation coverage."})
        if matches:
            matched_display = ", ".join(f"{row['network']} ({row['sbl_id']})" for row in matches)
            findings.append(finding("reputation", "medium", "Direct IP listed in a synthetic DROP fixture",
                f"The synthetic Demo IP matches {matched_display}. This is a review prompt, not a real provider verdict or evidence of compromise.",
                "Review the synthetic evidence and record an applicability decision only for workflow demonstration.", source,
                {**evidence, "severity_policy": "CyberLens medium-priority review rule v1", "demo_data": True},
                applicability="needs_review"))
        else:
            evidence["message"] = "Not listed in this synthetic snapshot."
        return CollectorResult(status="success" if matches else "no_match", source=source,
                               evidence=evidence, findings=findings)
    elif collector == "cins_army":
        if scenario == "ip_provider_outage":
            return CollectorResult(status="unavailable", source=source,
                evidence={**evidence, "provider": "Synthetic CINS Army fixture", "provider_status": "simulated_unavailable",
                          "result": "unknown", "freshness": "unknown", "records": [],
                          "coverage_note": "Synthetic outage; no listing or removal was inferred."},
                error_explanation="Synthetic CINS Army provider outage. No listing result was fabricated.")
        fixture_path = Path(__file__).resolve().parents[1] / "data" / "cins_army_demo.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        try:
            import ipaddress

            address = ipaddress.ip_address(asset.identifier) if asset.kind == "ip" else None
            normalized = str(address) if address is not None else None
        except ValueError:
            normalized = None
        listed = bool(normalized and normalized in fixture["addresses"])
        if scenario == "ip_no_match":
            listed = False
        evidence.update({"provider": "Synthetic CINS Army fixture", "provider_version": fixture["fixture_version"],
            "source_id": "cins_army", "provider_status": "listed" if listed else "not_listed_in_snapshot",
            "result": "listed" if listed else "not_listed_in_snapshot", "match_scope": "direct_public_ip",
            "asset_ip": asset.identifier, "matched_ip": normalized if listed else None,
            "snapshot_id": "synthetic-cins-army-demo-v1", "content_sha256": None,
            "parser_version": fixture["fixture_version"], "snapshot_record_count": len(fixture["addresses"]),
            "snapshot_retrieved_at": None, "provider_published_at": None,
            "last_successful_revalidation_at": None, "snapshot_age_seconds": 0,
            "freshness": "synthetic", "attribution": fixture["attribution"],
            "coverage_note": "Synthetic fixture with reserved IPs. The source provides IPs only and no per-indicator score, attack category, report count, or first-seen time."})
        if listed:
            findings.append(finding("reputation", "medium", "Direct IP listed in a synthetic CINS Army fixture",
                f"The synthetic reserved IP {normalized} appears in the offline fixture. This is a review prompt, not provider data or evidence of an attack.",
                "Review the synthetic source evidence and record an applicability decision only for workflow demonstration.",
                source, {**evidence, "severity_policy": "CyberLens medium-priority review rule v1", "demo_data": True},
                applicability="needs_review"))
        else:
            evidence["message"] = "Not listed in this synthetic snapshot."
        return CollectorResult(status="success" if listed else "no_match", source=source,
                               evidence=evidence, findings=findings)
    elif collector == "openphish":
        fixture_path = Path(__file__).resolve().parents[1] / "data" / "openphish_demo.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        if scenario == "openphish_outage":
            return CollectorResult(status="unavailable", source=source,
                evidence={**evidence, "provider_status": "simulated_unavailable", "result": "unknown",
                          "freshness": "unknown", "snapshot_id": None,
                          "coverage_note": "Synthetic provider outage. No listing or removal was inferred."},
                error_explanation="Synthetic OpenPhish provider outage. No listing result was fabricated.")
        from app.url_normalization import canonicalize_http_url
        try:
            canonical_url, hostname = canonicalize_http_url(asset.identifier) if asset.kind == "url" else ("", "")
        except ValueError:
            canonical_url, hostname = "", ""
        listed = any(item["canonical_url"] == canonical_url for item in fixture["listed_urls"])
        if scenario == "openphish_no_match":
            listed = False
        evidence.update({"provider": source, "source_id": "openphish",
            "provider_version": fixture["fixture_version"],
            "provider_status": "listed" if listed else "no_match",
            "result": "listed" if listed else "not_listed_in_snapshot",
            "match_scope": "exact_url" if listed else "exact_url",
            "snapshot_id": "synthetic-openphish-demo-v1", "content_sha256": None,
            "parser_version": fixture["fixture_version"], "snapshot_record_count": len(fixture["listed_urls"]),
            "snapshot_retrieved_at": None, "last_successful_revalidation_at": None,
            "snapshot_age_seconds": 0, "freshness": "synthetic",
            "attribution": fixture["attribution"],
            "coverage_note": "Synthetic offline URL fixture only. It does not establish that a page remains reachable or that an asset is compromised. CyberLens does not visit listed destinations."})
        if listed:
            findings.append(finding("reputation", "medium", "URL listed in a synthetic OpenPhish fixture",
                "The submitted URL exactly matches a synthetic offline record. This is not provider data and does not establish compromise. Analyst review is required before risk contribution.",
                "Review the synthetic evidence and record an applicability decision only for workflow demonstration.",
                source, {**evidence, "severity_policy": "CyberLens medium-priority review rule v1",
                         "risk_contribution_requires": "analyst applicability = applies", "demo_data": True},
                applicability="needs_review"))
        else:
            evidence["message"] = "No exact URL match in this synthetic snapshot."
        return CollectorResult(status="success" if listed else "no_match", source=source,
                               evidence=evidence, findings=findings)
    elif collector == "nvd_kev":
        if scenario == "provider_outage":
            return CollectorResult(status="unavailable", source=source, evidence={**evidence, "provider_status": "simulated_timeout"}, error_explanation="Synthetic provider outage: NVD timed out. No CVE candidates were generated.")
        if scenario == "vulnerable_application":
            candidates = [
                {"cve_id": "CVE-2024-0001", "description": "Synthetic affected-version candidate for demonstration.", "cvss_version": "3.1", "cvss_score": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "affected_versions": ["2.4.0 through 2.4.50"], "fixture_case": "affected_version", "kev": True},
                {"cve_id": "CVE-2023-0002", "description": "Synthetic version-range candidate for analyst review.", "cvss_version": "3.1", "cvss_score": 6.5, "severity": "medium", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "affected_versions": ["2.0 through 2.4.48"], "fixture_case": "unaffected_installed_version", "kev": False},
                {"cve_id": "CVE-2022-0003", "description": "Synthetic candidate with configuration-dependent applicability.", "cvss_version": "3.1", "cvss_score": 8.1, "severity": "high", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "affected_versions": ["2.4.x when optional module is enabled"], "fixture_case": "ambiguous_configuration", "kev": False},
                {"cve_id": "CVE-2021-0004", "description": "Synthetic candidate with no supplied severity metadata.", "cvss_version": None, "cvss_score": None, "severity": "unknown", "vector": None, "affected_versions": [], "fixture_case": "unknown_severity", "kev": False},
            ]
            for candidate in candidates:
                candidate["references"] = [f"https://nvd.nist.gov/vuln/detail/{candidate['cve_id']}"]
                candidate["applicability"] = "needs_review"
                candidate["component"] = {"vendor": "Synthetic vendor", "product": "Sample application", "version": "1.0"}
                # Fixed synthetic values keep Demo fully offline and make the
                # EPSS display reproducible without implying exploitation.
                candidate.update({
                    "epss_score": {"CVE-2024-0001": 0.96, "CVE-2023-0002": 0.08,
                                    "CVE-2022-0003": 0.23, "CVE-2021-0004": 0.01}[candidate["cve_id"]],
                    "epss_percentile": {"CVE-2024-0001": 0.995, "CVE-2023-0002": 0.72,
                                         "CVE-2022-0003": 0.91, "CVE-2021-0004": 0.31}[candidate["cve_id"]],
                    "epss_observed_at": observed_at,
                    "epss_provider_status": "success",
                    "epss_freshness": "synthetic",
                    "epss_source_date": None,
                    "epss_provider": "Synthetic EPSS fixture",
                    "epss_provider_version": "CyberLens Demo fixture schema 1",
                    "epss_cache_state": "not_used",
                })
            evidence["epss"] = {"provider": "Synthetic EPSS fixture", "provider_version": "CyberLens Demo fixture schema 1",
                                "status": "synthetic", "results": candidates}
            evidence["candidates"] = candidates
            for candidate in candidates:
                findings.append(finding("vulnerabilities", candidate["severity"], f"{candidate['cve_id']} applicability candidate",
                    candidate["description"] + " Analyst confirmation is required before this finding affects risk.",
                    "Check the installed product, exact version, configuration, and vendor advisory; then record an applicability decision.", source,
                    {**candidate, "demo_data": True}, applicability="needs_review"))
    elif collector == "osv":
        package_components = [item for item in (components or []) if item.package_ecosystem and item.package_name]
        evidence.update({"provider": "Synthetic OSV fixture", "provider_version": "CyberLens Demo fixture schema 1",
            "provider_status": "not_assessed" if not package_components else "partial",
            "components": [], "advisories": [],
            "message": "Demo mode performs no OSV network requests. Only the bundled synthetic package/version fixture is assessed."})
        if not package_components:
            return CollectorResult(status="not_applicable", source=source, evidence=evidence,
                error_explanation="No explicit package metadata was entered; no package was inferred or sent to OSV.")
        fixture_path = Path(__file__).resolve().parents[1] / "data" / "osv_demo_query.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        statuses = []
        for component in package_components[:20]:
            match = (component.package_ecosystem == "npm" and component.package_name == "cyberlens-demo-widget"
                     and component.version == "1.0.0")
            statuses.append("success" if match else "not_assessed")
            evidence["components"].append({"component_id": component.id, "ecosystem": component.package_ecosystem,
                "package_name": component.package_name, "version": component.version,
                "status": "synthetic_match" if match else "not_assessed"})
            if not match:
                continue
            advisory = {**fixture, "observed_at": observed_at, "advisory_status": "active",
                "provider_status": "synthetic", "freshness": "synthetic",
                "provider_version": "CyberLens Demo fixture schema 1",
                "fixed_versions": [event["fixed"] for affected in fixture["affected"]
                    for version_range in affected.get("ranges", []) for event in version_range.get("events", [])
                    if "fixed" in event]}
            aliases = advisory["aliases"]
            details = {"advisory_id": advisory["id"], "aliases": aliases, "cve_id": aliases[0],
                "component_id": component.id,
                "package": {"ecosystem": component.package_ecosystem, "name": component.package_name,
                            "version": component.version},
                "affected": advisory["affected"], "fixed_versions": advisory["fixed_versions"],
                "references": advisory["references"], "severity_metadata": [], "published": advisory["published"],
                "modified": advisory["modified"], "withdrawn": None, "observed_at": observed_at,
                "provider_status": "synthetic", "freshness": "synthetic",
                "provider_version": advisory["provider_version"], "advisory_status": "active",
                "summary": advisory["summary"], "demo_data": True}
            evidence["advisories"].append({**advisory, "component_id": component.id,
                "ecosystem": component.package_ecosystem, "package_name": component.package_name,
                "package_version": component.version})
            findings.append(finding("vulnerabilities", "high", f"{advisory['id']} package applicability candidate",
                advisory["summary"], "Review this synthetic advisory against the explicitly entered package version and record an analyst applicability decision. Fixed version: 1.0.1.",
                source, details, applicability="needs_review"))
        evidence["provider_status"] = "success" if all(item == "success" for item in statuses) else "partial"
        return CollectorResult(status="success" if findings else "not_applicable", source=source,
            evidence=evidence, findings=findings,
            error_explanation=None if findings else "No bundled Demo advisory matches these explicit package details; Live OSV was not queried.")
    return CollectorResult(status="success", source=source, evidence=evidence, findings=findings)
