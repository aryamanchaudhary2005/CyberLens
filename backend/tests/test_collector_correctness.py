import json
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import jobs
from app.cpe import cpe_inventory_mismatch
from app.collectors import dns_rdap, intelligence, nvd, website
from app.collectors.types import CollectorResult
from app.models import AuditEvent
from app.network import SafeResponse
from app.routes.assets import normalize_asset
from conftest import csrf, login

FIXTURES = Path(__file__).parent / "fixtures" / "providers"


@pytest.fixture
def provider_fixtures():
    return {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in FIXTURES.glob("*.json")}


def test_url_canonicalization_preserves_case_sensitive_path():
    first, first_key = normalize_asset("url", "HTTPS://Example.COM/Admin/Case?token=synthetic#part")
    second, second_key = normalize_asset("url", "https://example.com/admin/case")
    third, third_key = normalize_asset("url", "https://example.com/Admin/Case?token=synthetic#part")
    assert first == "https://example.com/Admin/Case?token=synthetic#part"
    assert first_key == first
    assert second_key == second
    assert third_key == third
    assert first_key == third_key
    assert first_key != second_key


def test_cpe_selection_requires_matching_vendor_product_and_exact_version():
    valid = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert cpe_inventory_mismatch(valid, "Apache", "HTTP Server", "2.4.49") is None
    assert cpe_inventory_mismatch(valid, "Other", "HTTP Server", "2.4.49")
    assert cpe_inventory_mismatch(valid, "Apache", "Different Product", "2.4.49")
    assert cpe_inventory_mismatch(valid, "Apache", "HTTP Server", "2.4.50")
    assert cpe_inventory_mismatch("cpe:2.3:a:apache", "Apache", "HTTP Server", "2.4.49")


def test_cpe_select_api_validates_and_audits_against_inventory(workspace):
    client, factory = workspace
    login(client)
    asset = client.post("/api/v1/assets", headers=csrf(client), json={
        "kind": "application", "identifier": "CPE validation target", "notes": ""}).json()
    component = client.post(f"/api/v1/assets/{asset['id']}/components", headers=csrf(client), json={
        "vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"}).json()
    mismatch = client.put(
        f"/api/v1/integrations/assets/{asset['id']}/components/{component['id']}/cpe",
        params={"cpe_name": "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"}, headers=csrf(client))
    assert mismatch.status_code == 422
    selected_name = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    selected = client.put(
        f"/api/v1/integrations/assets/{asset['id']}/components/{component['id']}/cpe",
        params={"cpe_name": selected_name}, headers=csrf(client))
    assert selected.status_code == 200, selected.text
    db = factory()
    event = db.query(AuditEvent).filter_by(action="software_component.cpe_selected").one()
    assert event.entity_id == component["id"]
    assert event.details_json["cpe_name"] == selected_name
    assert event.details_json["inventory"] == {"vendor": "Apache", "product": "HTTP Server", "version": "2.4.49"}
    db.close()


def test_demo_cpe_search_returns_matching_offline_inventory_candidate(workspace):
    client, _factory = workspace
    login(client)
    response = client.get("/api/v1/integrations/nvd/cpes", params={
        "keyword_search": "Apache HTTP Server", "software_vendor": "Apache",
        "software_product": "HTTP Server", "software_version": "2.4.49"})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["demo_data"] is True
    assert result["results"][0]["cpe_name"] == r"cpe:2.3:a:apache:http\ server:2.4.49:*:*:*:*:*:*:*"


def test_registrable_domain_uses_public_suffix_and_keeps_hostname(monkeypatch):
    host = "portal.eu.example.co.uk"
    assert dns_rdap.registrable_domain(host) == "example.co.uk"
    assert dns_rdap.registrable_domain("203.0.113.4") == "203.0.113.4"
    asset = SimpleNamespace(kind="domain", identifier=host)
    monkeypatch.setattr(dns_rdap, "_query_record", lambda *_args, **_kwargs: {"status": "no_match", "values": []})
    monkeypatch.setattr(dns_rdap, "discover_rdap_endpoint", lambda *_args, **_kwargs: None)
    result = dns_rdap.collect_dns_rdap(asset)
    assert result.evidence["submitted_host"] == host
    assert result.evidence["registrable_domain"] == "example.co.uk"


def test_dns_record_status_distinguishes_no_record_nxdomain_and_lookup_failure(monkeypatch):
    from app.config import get_settings
    import dns.exception
    import dns.resolver

    class Resolver:
        def resolve(self, _name, record_type, **_kwargs):
            if record_type == "A":
                raise dns.resolver.NoAnswer
            if record_type == "AAAA":
                raise dns.resolver.NXDOMAIN
            raise dns.exception.Timeout

    monkeypatch.setattr(dns_rdap, "get_settings", lambda: SimpleNamespace(collector_timeout_seconds=2))
    assert dns_rdap._query_record(Resolver(), "host.example", "A")["status"] == "no_match"
    assert dns_rdap._query_record(Resolver(), "host.example", "AAAA")["status"] == "not_found"
    assert dns_rdap._query_record(Resolver(), "host.example", "MX")["status"] == "failed"


def test_provider_fixtures_are_validated_offline(provider_fixtures, monkeypatch):
    assert set(provider_fixtures) == {"rdap_registry", "rdap_domain", "nvd_cpes", "nvd_cves", "epss",
                                      "cisa_kev", "virustotal", "hibp", "dns_records", "website_response",
                                      "osv_query", "xposedornot_found", "xposedornot_no_match",
                                      "xposedornot_unverified"}
    monkeypatch.setattr(dns_rdap, "_rdap_services", None)
    monkeypatch.setattr(dns_rdap, "safe_get", lambda *_args, **_kwargs: SafeResponse(
        200, {}, json.dumps(provider_fixtures["rdap_registry"]).encode(), dns_rdap.IANA_RDAP_REGISTRY, []))
    assert dns_rdap.discover_rdap_endpoint("www.example.test") == "https://rdap.example.test"

    settings = SimpleNamespace(nvd_api_key="fixture-nvd-key", collector_timeout_seconds=2)
    monkeypatch.setattr(nvd, "get_settings", lambda: settings)
    headers_seen = []

    def nvd_response(url, **kwargs):
        headers_seen.append((url, kwargs.get("headers")))
        payload = provider_fixtures["nvd_cpes"] if "/cpes/" in url else (
            provider_fixtures["nvd_cves"] if "/cves/" in url else provider_fixtures["cisa_kev"])
        return SafeResponse(200, {}, json.dumps(payload).encode(), url, [])

    monkeypatch.setattr(nvd, "safe_get", nvd_response)
    nvd._cpe_cache.clear(); nvd._cve_cache.clear(); nvd._kev_cache = None
    assert nvd.search_cpes("Apache HTTP Server")["results"][0]["cpe_name"].endswith("2.4.49:*:*:*:*:*:*:*")
    page = nvd.search_cve_page("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert page["results"][0]["kev"] is True
    nvd_call = next(headers for url, headers in headers_seen if "services.nvd.nist.gov" in url)
    cisa_call = next(headers for url, headers in headers_seen if "cisa.gov" in url)
    assert nvd_call == {"apiKey": "fixture-nvd-key"}
    assert cisa_call == {}

    class FixtureRecord:
        def __init__(self, value):
            self.value = value

        def to_text(self):
            return self.value

    class FixtureResolver:
        def __init__(self, **_kwargs):
            pass

        def resolve(self, name, record_type, **_kwargs):
            key = "DMARC" if name.startswith("_dmarc.") else record_type
            record = provider_fixtures["dns_records"][key]
            if record["status"] != "success":
                raise dns.resolver.NoAnswer
            return [FixtureRecord(value) for value in record["values"]]

    monkeypatch.setattr(dns_rdap, "get_settings", lambda: SimpleNamespace(collector_timeout_seconds=2))
    monkeypatch.setattr(dns_rdap.dns.resolver, "Resolver", FixtureResolver)
    monkeypatch.setattr(dns_rdap, "_rdap_services", None)
    monkeypatch.setattr(dns_rdap, "safe_get", lambda *_args, **_kwargs: SafeResponse(
        200, {}, json.dumps(provider_fixtures["rdap_registry"]).encode(), dns_rdap.IANA_RDAP_REGISTRY, []))
    monkeypatch.setattr(dns_rdap, "json_get", lambda *_args, **_kwargs: (
        200, provider_fixtures["rdap_domain"], {}))
    dns_result = dns_rdap.collect_dns_rdap(SimpleNamespace(kind="domain", identifier="www.example.test"))
    assert dns_result.evidence["records"]["A"] == provider_fixtures["dns_records"]["A"]
    assert dns_result.evidence["rdap"]["handle"] == "EXAMPLE-TEST"
    assert dns_result.evidence["submitted_host"] == "www.example.test"

    monkeypatch.setattr(intelligence, "get_settings", lambda: SimpleNamespace(
        virustotal_api_key=None, hibp_api_key="hibp-fixture-key", collector_timeout_seconds=2))
    monkeypatch.setattr(intelligence, "_request_json", lambda *_args, **_kwargs: (
        200, provider_fixtures["hibp"], {}))
    hibp_result = intelligence.collect_hibp(SimpleNamespace(kind="email", identifier="analyst@example.test"))
    assert hibp_result.status == "success" and hibp_result.evidence["breach_count"] == 1


def test_virustotal_ip_endpoint_uses_ip_addresses_and_provider_fixture(provider_fixtures, monkeypatch):
    monkeypatch.setattr(intelligence, "get_settings", lambda: SimpleNamespace(
        virustotal_api_key="vt-key", hibp_api_key=None, collector_timeout_seconds=2))
    calls = []

    def response(url, headers, *, provider_host):
        calls.append((url, headers, provider_host))
        return 200, provider_fixtures["virustotal"], {}

    monkeypatch.setattr(intelligence, "_request_json", response)
    result = intelligence.collect_virustotal(SimpleNamespace(kind="ip", identifier="8.8.8.8"))
    assert result.status == "success"
    assert calls[0][0] == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    assert calls[0][1]["x-apikey"] == "vt-key"
    assert calls[0][2] == "www.virustotal.com"


def test_provider_credential_helpers_refuse_unintended_origins(monkeypatch):
    monkeypatch.setattr(intelligence, "safe_get", lambda *_args, **_kwargs: pytest.fail("HIBP key leaked"))
    with pytest.raises(ValueError, match="intended HTTPS provider"):
        intelligence._request_json("https://attacker.example/api", {"hibp-api-key": "secret"},
                                   provider_host="haveibeenpwned.com")
    monkeypatch.setattr(nvd, "get_settings", lambda: SimpleNamespace(nvd_api_key="secret", collector_timeout_seconds=2))
    monkeypatch.setattr(nvd, "safe_get", lambda *_args, **_kwargs: pytest.fail("NVD key leaked"))
    with pytest.raises(ValueError, match="NVD credentials"):
        nvd._get_json("https://attacker.example/feed", include_nvd_key=True)


@pytest.mark.parametrize(("collector", "source"), [
    (intelligence.collect_virustotal, "VirusTotal"),
    (intelligence.collect_hibp, "Have I Been Pwned"),
])
def test_missing_provider_keys_do_not_send_requests(collector, source, monkeypatch):
    monkeypatch.setattr(intelligence, "get_settings", lambda: SimpleNamespace(
        virustotal_api_key=None, hibp_api_key=None, collector_timeout_seconds=2))
    monkeypatch.setattr(intelligence, "_request_json", lambda *_args, **_kwargs: pytest.fail("request sent without key"))
    asset = SimpleNamespace(kind="ip", identifier="8.8.8.8") if source == "VirusTotal" else SimpleNamespace(
        kind="email", identifier="person@example.test")
    assert collector(asset).status == "unavailable"


@pytest.mark.parametrize(("status", "message"), [(429, "quota"), (403, "key")])
def test_virustotal_provider_quota_and_access_errors_are_unavailable(status, message, monkeypatch):
    monkeypatch.setattr(intelligence, "get_settings", lambda: SimpleNamespace(
        virustotal_api_key="vt-key", hibp_api_key=None, collector_timeout_seconds=2))
    monkeypatch.setattr(intelligence, "_request_json", lambda *_args, **_kwargs: (status, {}, {}))
    result = intelligence.collect_virustotal(SimpleNamespace(kind="ip", identifier="2001:4860:4860::8888"))
    assert result.status == "unavailable"
    assert message in (result.error_explanation or "").lower()


def test_malformed_provider_payloads_fail_without_findings(provider_fixtures, monkeypatch):
    monkeypatch.setattr(intelligence, "get_settings", lambda: SimpleNamespace(
        virustotal_api_key="vt-key", hibp_api_key="hibp-key", collector_timeout_seconds=2))
    monkeypatch.setattr(intelligence, "_request_json", lambda *_args, **_kwargs: (200, {"data": "wrong"}, {}))
    vt = intelligence.collect_virustotal(SimpleNamespace(kind="domain", identifier="example.test"))
    assert vt.status == "failed" and not vt.findings
    monkeypatch.setattr(intelligence, "_request_json", lambda *_args, **_kwargs: (200, [{"DataClasses": "wrong"}], {}))
    hibp = intelligence.collect_hibp(SimpleNamespace(kind="email", identifier="person@example.test"))
    assert hibp.status == "failed" and not hibp.findings

    monkeypatch.setattr(nvd, "get_settings", lambda: SimpleNamespace(nvd_api_key=None, collector_timeout_seconds=2))
    monkeypatch.setattr(nvd, "safe_get", lambda url, **_kwargs: SafeResponse(
        200, {}, b'{"products":"malformed"}', url, []))
    nvd._cpe_cache.clear()
    with pytest.raises(ValueError, match="products list"):
        nvd.search_cpes("Apache HTTP Server")


def test_stored_cpe_is_revalidated_before_nvd_lookup(monkeypatch):
    monkeypatch.setattr(nvd, "search_cve_page", lambda *_args, **_kwargs: pytest.fail("invalid CPE queried"))
    component = SimpleNamespace(id="component", vendor="Apache", product="HTTP Server", version="2.4.49",
                                cpe_name="cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*")
    result = nvd.collect_nvd(SimpleNamespace(kind="application"), [component])
    assert result.status == "unavailable"
    assert result.evidence["components"][0]["status"] == "invalid_selection"


def _certificate(host: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.DER)


def test_website_evidence_records_tls_identity_protocol_and_certificate_failure(provider_fixtures, monkeypatch):
    monkeypatch.setattr(website, "get_settings", lambda: SimpleNamespace(collector_timeout_seconds=2))
    certificate = _certificate("site.example.test")
    calls = []

    def safe_get(url, **kwargs):
        calls.append((url, kwargs))
        if kwargs.get("verify_tls"):
            raise ssl.SSLCertVerificationError("fixture certificate trust failure")
        if url.startswith("https://"):
            return SafeResponse(200, provider_fixtures["website_response"]["headers"], b"ok", url, [],
                peer_certificate=certificate, tls_version="TLSv1.3", tls_hostname="site.example.test",
                negotiated_protocol="http/1.1")
        return SafeResponse(200, {}, b"ok", url, [])

    monkeypatch.setattr(website, "safe_get", safe_get)
    result = website.collect_website(SimpleNamespace(kind="url", identifier="https://site.example.test/Case"))
    evidence = result.evidence
    assert evidence["https"]["tls_hostname"] == "site.example.test"
    assert evidence["https"]["negotiated_protocol"] == "http/1.1"
    assert evidence["certificate"]["tls_hostname"] == "site.example.test"
    assert evidence["certificate"]["subject_alt_names"]["dns"] == ["site.example.test"]
    assert evidence["certificate"]["sha256_fingerprint"]
    assert evidence["certificate"]["trust_valid"] is False
    assert evidence["certificate"]["trust_error"] == "SSLCertVerificationError"
    assert calls[0][1]["deadline"] == calls[1][1]["deadline"] == calls[2][1]["deadline"]


def test_demo_collector_path_never_calls_live_providers_or_network(monkeypatch):
    monkeypatch.setattr(intelligence, "safe_get", lambda *_args, **_kwargs: pytest.fail("network request in Demo"))
    monkeypatch.setattr(jobs, "collect_virustotal", lambda *_args: pytest.fail("live collector in Demo"))
    asset = SimpleNamespace(kind="ip", identifier="8.8.8.8")
    result = jobs._run_collector("reputation", asset, [], "demo", "routine_website", False)
    assert result.status == "success"
    assert result.evidence["demo_data"] is True


def test_live_collector_failure_is_not_replaced_with_demo(monkeypatch):
    monkeypatch.setattr(jobs, "collect_virustotal", lambda *_args: CollectorResult(
        status="failed", source="VirusTotal", error_explanation="fixture failure"))
    monkeypatch.setattr(jobs, "demo_result", lambda *_args: pytest.fail("Live result replaced by Demo"))
    result = jobs._run_collector("reputation", SimpleNamespace(kind="ip", identifier="8.8.8.8"), [],
                                 "live", None, True)
    assert result.status == "failed"


def test_evidence_provenance_metadata_is_standardized():
    result = CollectorResult(status="unavailable", source="VirusTotal", evidence={"observed_at": "2026-10-17T00:00:00+00:00"})
    evidence = jobs._evidence_with_provenance(result, "reputation", "live")
    assert evidence["provenance"] == {
        "schema_version": 1,
        "source": "VirusTotal",
        "provider": "VirusTotal",
        "provider_version": "VirusTotal API v3",
        "observed_at": "2026-10-17T00:00:00+00:00",
        "freshness": {"state": "unavailable", "source_timestamp": None},
        "status": "unavailable",
    }
