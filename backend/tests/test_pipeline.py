import pytest
from app.tools.tool_registry import (
    validate_ioc_format, defang_ioc, normalize_source_url,
    compute_content_hash, extract_deterministic_iocs
)
from app.services.gmail_service import gmail_service

def test_ioc_format_validation():
    assert validate_ioc_format("ipv4", "192.0.2.1") is True
    assert validate_ioc_format("ipv4", "999.999.999.999") is False
    assert validate_ioc_format("cve", "CVE-2023-4966") is True
    assert validate_ioc_format("cve", "cve-not-real") is False
    assert validate_ioc_format("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True
    assert validate_ioc_format("domain", "c2-malicious.com") is True

def test_ioc_defanging():
    assert defang_ioc("ipv4", "198.51.100.1") == "198[.]51[.]100[.]1"
    assert defang_ioc("domain", "evil-c2.net") == "evil-c2[.]net"
    assert defang_ioc("url", "http://evil.com/payload.exe") == "hxxp://evil[.]com/payload[.]exe"

def test_source_url_normalization():
    raw = "https://www.CISA.gov/cybersecurity-advisories/aa24-001a?utm_source=twitter&ref=feed"
    normalized = normalize_source_url(raw)
    assert "utm_source" not in normalized
    assert normalized.startswith("https://www.cisa.gov")

def test_deterministic_ioc_extraction():
    sample_text = """
    Advisory notes threat group Volt Typhoon exploiting CVE-2024-21762.
    Malicious payloads dropped had SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
    Observed pivot IP 45.154.255.88 contacting external endpoints.
    """
    iocs = extract_deterministic_iocs(sample_text)
    types = [i["ioc_type"] for i in iocs]
    assert "cve" in types
    assert "sha256" in types
    assert "ipv4" in types

def test_email_payload_generation():
    bundle = {
        "title": "Test Threat Incident",
        "severity": "CRITICAL",
        "affected_organization": "Cyber Defense Test Org",
        "summary": "Exploit identified.",
        "root_cause_analysis": "Weak authentication.",
        "source_url": "https://cisa.gov",
        "iocs": [{"ioc_type": "ipv4", "defanged_value": "198[.]51[.]100[.]1", "context_role": "C2 Server"}],
        "techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application", "supporting_behavior": "Remote exploit"}],
        "recommendations": [{"category": "IMMEDIATE", "title": "Patch", "action_items": "Apply update"}]
    }
    email_pack = gmail_service.create_incident_email(bundle, recipient="test@example.com")
    assert email_pack["recipient"] == "test@example.com"
    assert "CRITICAL" in email_pack["subject"]
    assert "198[.]51[.]100[.]1" in email_pack["html"]
    assert "T1190" in email_pack["plain"]
