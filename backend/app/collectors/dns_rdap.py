import json
import ipaddress
import time
from urllib.parse import quote

import dns.exception
import dns.resolver
from publicsuffix2 import get_sld

from app.collectors.common import finding, host_for_asset, json_get, now_iso
from app.collectors.types import CollectorResult
from app.network import safe_get
from app.config import get_settings

IANA_RDAP_REGISTRY = "https://data.iana.org/rdap/dns.json"
_rdap_services: list[tuple[list[str], list[str]]] | None = None


def registrable_domain(host: str) -> str:
    normalized = host.rstrip(".")
    try:
        return ipaddress.ip_address(normalized).compressed
    except ValueError:
        pass
    # Strict mode avoids treating an unknown public suffix as an eTLD+1.
    # Keep the submitted host separately in evidence when RDAP needs this fallback.
    result = get_sld(normalized, strict=True)
    return result or normalized.lower()


def _query_record(resolver, name: str, record_type: str, deadline: float | None = None) -> dict:
    try:
        lifetime = get_settings().collector_timeout_seconds
        if deadline is not None:
            lifetime = min(lifetime, deadline - time.monotonic())
        if lifetime <= 0:
            return {"status": "failed", "values": [], "error": "OutboundTimeout"}
        answer = resolver.resolve(name, record_type, lifetime=lifetime)
        values = [item.to_text().strip('"') for item in answer]
        return {"status": "success" if values else "no_match", "values": values}
    except dns.resolver.NXDOMAIN:
        return {"status": "not_found", "values": []}
    except dns.resolver.NoAnswer:
        return {"status": "no_match", "values": []}
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        return {"status": "failed", "values": [], "error": type(exc).__name__}


def discover_rdap_endpoint(domain: str, deadline: float | None = None) -> str | None:
    global _rdap_services
    if _rdap_services is None:
        response = safe_get(IANA_RDAP_REGISTRY, timeout=get_settings().collector_timeout_seconds,
                            max_bytes=2_000_000, max_redirects=1, deadline=deadline)
        if response.status != 200:
            raise RuntimeError(f"IANA RDAP registry returned HTTP {response.status}")
        registry = json.loads(response.body.decode("utf-8"))
        services = registry.get("services") if isinstance(registry, dict) else None
        if not isinstance(services, list):
            raise ValueError("IANA RDAP registry has an invalid services list")
        _rdap_services = []
        for entry in services:
            if (isinstance(entry, list) and len(entry) == 2 and isinstance(entry[0], list)
                    and isinstance(entry[1], list) and all(isinstance(item, str) for item in (*entry[0], *entry[1]))):
                _rdap_services.append((entry[0], entry[1]))
    matches: list[tuple[int, str]] = []
    for suffixes, urls in _rdap_services:
        for suffix in suffixes:
            if domain == suffix.lower() or domain.endswith("." + suffix.lower()):
                for base in urls:
                    if base.lower().startswith("https://"):
                        matches.append((len(suffix), base.rstrip("/")))
    return max(matches, default=(0, None), key=lambda item: item[0])[1]


def collect_dns_rdap(asset) -> CollectorResult:
    host = host_for_asset(asset)
    deadline = time.monotonic() + get_settings().collector_timeout_seconds
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(get_settings().collector_timeout_seconds, 5.0)
    evidence: dict = {"submitted_host": host, "hostname": host, "records": {}, "observed_at": now_iso()}
    errors = 0
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        result = _query_record(resolver, host, record_type, deadline)
        evidence["records"][record_type] = result
        errors += result["status"] == "failed"
    address_statuses = {evidence["records"][kind]["status"] for kind in ("A", "AAAA")}
    if address_statuses == {"not_found"}:
        evidence["dns_status"] = "not_found"
        evidence["registrable_domain"] = registrable_domain(host)
        evidence["rdap_domain"] = evidence["registrable_domain"]
        evidence["rdap"] = {"status": "not_attempted", "reason": "Hostname has no DNS records"}
        return CollectorResult(status="no_match", source="DNS and IANA RDAP", evidence=evidence)
    evidence["dns_status"] = "failed" if address_statuses == {"failed"} else "success"
    txt_records = evidence["records"]["TXT"]["values"]
    mx_records = evidence["records"]["MX"]["values"]
    evidence["email_configuration"] = {
        "mx_present": bool(mx_records),
        "spf_present": any(value.lower().startswith("v=spf1") for value in txt_records),
    }
    dmarc = _query_record(resolver, f"_dmarc.{host}", "TXT", deadline)
    evidence["records"]["DMARC"] = dmarc
    errors += dmarc["status"] == "failed"
    evidence["email_configuration"]["dmarc_present"] = any(
        value.lower().startswith("v=dmarc1") for value in dmarc["values"]
    )
    findings = []
    if mx_records and not evidence["email_configuration"]["spf_present"]:
        findings.append(finding("dns_email", "low", "SPF record not found",
            "The domain has MX records but no SPF TXT record was observed.",
            "Confirm the domain's mail senders and publish an appropriate SPF policy.", "DNS", {"host": host}))
    if mx_records and not evidence["email_configuration"]["dmarc_present"]:
        findings.append(finding("dns_email", "low", "DMARC record not found",
            "The domain has MX records but no DMARC TXT record was observed.",
            "Publish a DMARC policy after confirming SPF and DKIM alignment.", "DNS", {"host": host}))

    evidence["domain_to_ip"] = {
        "A": evidence["records"]["A"]["values"],
        "AAAA": evidence["records"]["AAAA"]["values"],
    }
    evidence["registrable_domain"] = registrable_domain(host)
    evidence["rdap_domain"] = evidence["registrable_domain"]
    try:
        endpoint = discover_rdap_endpoint(evidence["rdap_domain"], deadline)
        if endpoint is None:
            evidence["rdap"] = {"status": "unavailable", "reason": "No RDAP provider registered with IANA"}
        else:
            status, payload, _ = json_get(f"{endpoint}/domain/{quote(evidence['rdap_domain'], safe='.-')}", deadline=deadline)
            if status == 200:
                if not isinstance(payload, dict):
                    raise ValueError("RDAP returned an invalid object")
                events = payload.get("events", [])
                raw_nameservers = payload.get("nameservers", [])
                if not isinstance(events, list) or not isinstance(raw_nameservers, list):
                    raise ValueError("RDAP returned malformed events or nameservers")
                nameservers = [item.get("ldhName") for item in raw_nameservers
                               if isinstance(item, dict) and item.get("ldhName")]
                safe_events = [e for e in events if isinstance(e, dict)]
                evidence["rdap"] = {
                    "status": "success", "provider": endpoint, "handle": payload.get("handle"),
                    "ldh_name": payload.get("ldhName"), "status_values": payload.get("status", []),
                    "nameservers": nameservers,
                    "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")} for e in safe_events],
                    "redacted_fields": payload.get("redacted", []),
                }
            elif status == 404:
                evidence["rdap"] = {"status": "no_match", "provider": endpoint}
            else:
                evidence["rdap"] = {"status": "failed", "provider": endpoint, "http_status": status}
    except Exception as exc:
        evidence["rdap"] = {"status": "failed", "error": type(exc).__name__}

    rdap_status = evidence.get("rdap", {}).get("status")
    if errors and (errors == len(evidence["records"]) or evidence["dns_status"] == "failed"):
        status = "failed" if rdap_status not in {"success", "no_match"} else "partial"
        explanation = "DNS lookups failed; see per-record evidence."
        return CollectorResult(status=status, source="DNS and IANA RDAP", evidence=evidence,
                               findings=findings, error_explanation=explanation)
    if errors:
        return CollectorResult(status="partial", source="DNS and IANA RDAP", evidence=evidence,
                               findings=findings, error_explanation="One or more DNS lookups failed; see per-record evidence.")
    return CollectorResult(status="success", source="DNS and IANA RDAP", evidence=evidence, findings=findings)
