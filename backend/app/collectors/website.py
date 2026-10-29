from datetime import datetime, timezone
import ipaddress
import ssl
import time
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from app.collectors.common import finding, host_for_asset, now_iso
from app.collectors.types import CollectorResult
from app.config import get_settings
from app.network import UnsafeDestination, safe_get


def _hostname_matches(host: str, certificate: x509.Certificate) -> bool:
    try:
        sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        addresses = sans.get_values_for_type(x509.IPAddress)
        try:
            ip = ipaddress.ip_address(host)
            return ip in addresses
        except ValueError:
            names = sans.get_values_for_type(x509.DNSName)
            candidates = names
    except x509.ExtensionNotFound:
        candidates = [item.value for item in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    host = host.rstrip(".").lower()
    for name in candidates:
        name = name.rstrip(".").lower()
        if name == host or (name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count(".")):
            return True
    return False


def _extract_certificate(raw: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(raw)
    before = cert.not_valid_before_utc
    after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    issuer = ", ".join(item.value for item in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
    subject = ", ".join(item.value for item in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = sans.get_values_for_type(x509.DNSName)
        ip_addresses = [address.compressed for address in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_addresses = [], []
    return {
        "subject": subject or cert.subject.rfc4514_string(),
        "issuer": issuer or cert.issuer.rfc4514_string(),
        "subject_alt_names": {"dns": dns_names, "ip": ip_addresses},
        "not_before": before.isoformat(),
        "not_after": after.isoformat(),
        "hostname_match": _hostname_matches(host, cert),
        "expired": now < before or now > after,
        "days_until_expiry": (after - now).total_seconds() / 86400,
        "serial_number": format(cert.serial_number, "x"),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "tls_hostname": host,
    }


def collect_website(asset) -> CollectorResult:
    target = asset.identifier if asset.kind == "url" else f"https://{asset.identifier}/"
    parsed = urlsplit(target)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return CollectorResult(status="failed", source="Authorized HTTP(S) and TLS inspection",
                               error_explanation="The asset is not a valid HTTP(S) website target.")
    settings = get_settings()
    deadline = time.monotonic() + settings.collector_timeout_seconds
    evidence: dict = {"submitted_url": target, "observed_at": now_iso(), "max_redirects": 3, "max_response_bytes": 500_000}
    findings: list[dict] = []
    https_url = urlunsplit(("https", parsed.netloc, parsed.path or "/", "", ""))
    try:
        tls_response = safe_get(https_url, timeout=settings.collector_timeout_seconds, max_bytes=500_000,
                                max_redirects=3, verify_tls=False, deadline=deadline)
    except UnsafeDestination as exc:
        return CollectorResult(status="failed", source="Authorized HTTP(S) and TLS inspection",
                               evidence={"blocked": str(exc)}, error_explanation="Outbound request was blocked by destination safety checks.")
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        evidence["https"] = {"available": False, "error": type(exc).__name__}
        findings.append(finding("tls_web", "medium", "HTTPS unavailable",
            "A bounded HTTPS request to the authorized website could not be completed.",
            "Enable HTTPS with a trusted certificate and verify the endpoint after remediation.",
            "Website configuration", {"error": type(exc).__name__}))
        return CollectorResult(status="success", source="Authorized HTTP(S) and TLS inspection", evidence=evidence, findings=findings)
    except Exception as exc:
        return CollectorResult(status="failed", source="Authorized HTTP(S) and TLS inspection",
                               evidence={"error": type(exc).__name__}, error_explanation="Website check failed before a response was received.")

    final_host = tls_response.tls_hostname or urlsplit(tls_response.final_url).hostname or parsed.hostname
    evidence["https"] = {"available": True, "status_code": tls_response.status,
                         "final_url": tls_response.final_url, "redirects": tls_response.redirects,
                         "redirect_hops": tls_response.redirect_hops,
                         "tls_hostname": tls_response.tls_hostname,
                         "tls_version": tls_response.tls_version,
                         "negotiated_protocol": tls_response.negotiated_protocol,
                         "http_protocol": tls_response.http_protocol}
    header_names = tls_response.headers
    evidence["security_headers"] = {
        key: header_names.get(key) for key in (
            "strict-transport-security", "content-security-policy", "x-content-type-options",
            "x-frame-options", "referrer-policy",
        ) if header_names.get(key)
    }

    cert_info = None
    if tls_response.peer_certificate:
        try:
            cert_info = _extract_certificate(tls_response.peer_certificate, final_host)
            cert_info["tls_version"] = tls_response.tls_version
            cert_info["negotiated_protocol"] = tls_response.negotiated_protocol
            evidence["certificate"] = cert_info
        except Exception as exc:
            evidence["certificate"] = {"parse_error": type(exc).__name__}
    else:
        evidence["certificate"] = {"status": "not_observed", "tls_hostname": tls_response.tls_hostname}
    try:
        verified_response = safe_get(https_url, timeout=settings.collector_timeout_seconds, max_bytes=1024,
                                     max_redirects=3, verify_tls=True, deadline=deadline)
        same_endpoint = (verified_response.final_url == tls_response.final_url and
                         verified_response.tls_hostname == tls_response.tls_hostname)
        same_certificate = (tls_response.peer_certificate is not None and
                            verified_response.peer_certificate == tls_response.peer_certificate)
        evidence["certificate"]["trust_valid"] = True if same_endpoint and same_certificate else None
        evidence["certificate"]["trust_check_endpoint_match"] = same_endpoint
        evidence["certificate"]["trust_check_certificate_match"] = same_certificate
        evidence["certificate"]["trust_check_tls_hostname"] = verified_response.tls_hostname
        evidence["certificate"]["trust_check_final_url"] = verified_response.final_url
        if not same_endpoint:
            evidence["certificate"]["trust_error"] = "Verified request ended at a different TLS endpoint"
        elif not same_certificate:
            evidence["certificate"]["trust_error"] = "Verified request observed a different certificate"
    except Exception as exc:
        if "certificate" not in evidence:
            evidence["certificate"] = {"status": "not_observed", "tls_hostname": tls_response.tls_hostname}
        evidence["certificate"]["trust_valid"] = False if isinstance(exc, ssl.SSLCertVerificationError) else None
        evidence["certificate"]["trust_error"] = type(exc).__name__

    if cert_info:
        problems = []
        if cert_info["expired"]:
            problems.append("certificate is outside its validity period")
        if not cert_info["hostname_match"]:
            problems.append("certificate hostname does not match the target")
        if evidence["certificate"].get("trust_valid") is False:
            problems.append("certificate chain is not trusted")
        if problems:
            findings.append(finding("tls_web", "high", "TLS certificate requires review",
                "The observed TLS certificate " + "; ".join(problems) + ".",
                "Install a current certificate for the exact website host from a trusted certificate authority.",
                "TLS certificate inspection", {"problems": problems, **cert_info}))
        elif cert_info["days_until_expiry"] <= 14:
            findings.append(finding("tls_web", "low", "TLS certificate expires soon",
                "The certificate expires within 14 days.",
                "Renew the certificate before expiry and verify automated renewal.",
                "TLS certificate inspection", cert_info))

    if "strict-transport-security" not in header_names:
        findings.append(finding("tls_web", "low", "HSTS header not observed",
            "The HTTPS response did not include Strict-Transport-Security.",
            "Assess whether the website should publish an HSTS policy after confirming HTTPS coverage.",
            "HTTP response headers"))
    if "content-security-policy" not in header_names:
        findings.append(finding("tls_web", "low", "Content Security Policy not observed",
            "The HTTPS response did not include a Content-Security-Policy header.",
            "Define a Content Security Policy that fits the site's resources and test it before enforcement.",
            "HTTP response headers"))
    if "x-content-type-options" not in header_names:
        findings.append(finding("tls_web", "low", "Content type protection not observed",
            "The HTTPS response did not include X-Content-Type-Options.",
            "Consider setting X-Content-Type-Options: nosniff.", "HTTP response headers"))
    csp = header_names.get("content-security-policy", "").lower()
    if "x-frame-options" not in header_names and "frame-ancestors" not in csp:
        findings.append(finding("tls_web", "low", "Framing protection not observed",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "Set a framing policy appropriate for the site's embedding requirements.", "HTTP response headers"))

    http_url = urlunsplit(("http", parsed.netloc, parsed.path or "/", "", ""))
    try:
        http_response = safe_get(http_url, timeout=settings.collector_timeout_seconds, max_bytes=1024,
                                 max_redirects=3, verify_tls=False, deadline=deadline)
        redirects_to_https = urlsplit(http_response.final_url).scheme.lower() == "https"
        evidence["http_redirect"] = {"final_url": http_response.final_url, "redirects": http_response.redirects,
                                     "redirect_hops": http_response.redirect_hops,
                                     "redirects_to_https": redirects_to_https}
        if not redirects_to_https:
            findings.append(finding("tls_web", "medium", "HTTP does not redirect to HTTPS",
                "The bounded HTTP request ended without an HTTPS destination.",
                "Redirect HTTP traffic to HTTPS and review canonical links and cookies.", "HTTP redirect check"))
    except Exception as exc:
        evidence["http_redirect"] = {"status": "unavailable", "error": type(exc).__name__}

    return CollectorResult(status="success", source="Authorized HTTP(S) and TLS inspection",
                           evidence=evidence, findings=findings)
