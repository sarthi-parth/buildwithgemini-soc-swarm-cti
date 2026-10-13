from app.services.rule_generator import generate_siem_rules_for_incident
from app.services.stix_service import generate_stix_bundle
from app.services.asset_matcher import match_incident_to_assets
from app.services.webhook_service import build_slack_block_kit_payload, send_webhook_alert

def test_rule_generator():
    inc = {
        "title": "Apache HTTP Server Vulnerability Disclosed (CVE-2026-9999)",
        "severity": "CRITICAL"
    }
    iocs = [
        {"ioc_type": "ipv4", "normalized_value": "198.51.100.4"},
        {"ioc_type": "domain", "normalized_value": "evil-c2.org"}
    ]
    ioas = [{"technique_id": "T1190", "pattern_name": "Exploit Public-Facing Application"}]
    
    rules = generate_siem_rules_for_incident(inc, iocs, ioas)
    assert "sigma" in rules
    assert "splunk" in rules
    assert "elastic" in rules
    assert "suricata" in rules
    assert "aws_waf" in rules
    assert "yara" in rules
    
    assert "198.51.100.4" in rules["sigma"]
    assert "evil-c2.org" in rules["splunk"]
    assert "CVE-2026-9999" in rules["elastic"]
    assert "T1190" in rules["suricata"]

def test_stix_bundle_generation():
    incidents = [{"id": "inc-1", "title": "Zero Day in VPN Gateway", "severity": "HIGH", "summary": "Active zero day."}]
    iocs = [{"ioc_type": "ipv4", "normalized_value": "203.0.113.5"}]
    ioas = [{"technique_id": "T1190", "pattern_name": "Exploit Public Application"}]
    
    bundle = generate_stix_bundle(incidents, iocs, ioas)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    
    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert "indicator" in types
    assert "attack-pattern" in types
    assert "report" in types

def test_asset_matcher():
    inc = {
        "title": "Privilege Escalation Flaw Found in Linux Kernel & Ubuntu",
        "summary": "Impacts Ubuntu servers and Kubernetes clusters.",
        "severity": "CRITICAL"
    }
    custom_stack = ["Linux", "Ubuntu", "Kubernetes", "Windows Server"]
    res = match_incident_to_assets(inc, custom_stack)
    assert res["is_impacted"] is True
    assert "Linux" in res["matched_assets"]
    assert "Ubuntu" in res["matched_assets"]
    assert "Kubernetes" in res["matched_assets"]
    assert res["exposure_level"] == "CRITICAL_EXPOSURE"
    assert len(res["runbook"]) > 0

def test_slack_webhook_payload():
    inc = {
        "title": "Ransomware Attack Strikes Hospital",
        "severity": "HIGH",
        "category": "Ransomware",
        "summary": "LockBit strain deployed."
    }
    iocs = [{"ioc_type": "domain", "defanged_value": "lockbit[.]leak"}]
    payload = build_slack_block_kit_payload(inc, iocs)
    assert payload["channel"] == "#soc-threat-intel"
    assert len(payload["blocks"]) >= 4
    
    preview = send_webhook_alert("", payload)
    assert preview["status"] == "PREVIEW_READY"
