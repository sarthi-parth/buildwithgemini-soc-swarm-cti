import pytest
from app.services.mitre_service import build_mitre_matrix, get_technique_details, COMMON_TECHNIQUES
from app.services.playbook_service import list_available_playbooks, get_playbook_run, PLAYBOOK_CATALOG
from app.services.epss_service import calculate_epss_score, prioritize_incidents_by_epss
from app.services.rule_generator import generate_siem_rules_for_incident

def test_mitre_matrix_generation():
    incidents = [
        {"id": "inc-1", "title": "Critical RCE via Apache Exploit", "initial_access_vector": "Exploit Public Application"},
        {"id": "inc-2", "title": "LockBit Ransomware Payload Encryption", "initial_access_vector": "Phishing Email"}
    ]
    ioas = [
        {"incident_id": "inc-1", "technique_id": "T1190", "behavior_description": "Crafted HTTP payload execution"},
        {"incident_id": "inc-2", "technique_id": "T1486", "behavior_description": "Data Encrypted for Impact"}
    ]
    matrix = build_mitre_matrix(incidents, ioas)
    assert "tactics" in matrix
    assert len(matrix["tactics"]) == 14
    assert matrix["total_active_techniques"] >= 2
    assert len(matrix["top_techniques"]) > 0

def test_playbook_service():
    playbooks = list_available_playbooks()
    assert len(playbooks) >= 3
    keys = [p["key"] for p in playbooks]
    assert "ransomware" in keys
    assert "zeroday_rce" in keys

    run = get_playbook_run("ransomware", target_ip="10.200.1.5", target_domain="evil-c2.org")
    assert run["title"] == "Ransomware Outbreak & Encryption Neutralization"
    assert len(run["steps"]) >= 4
    # Check rendered commands
    step3 = [s for s in run["steps"] if s["step_number"] == 3][0]
    assert "10.200.1.5" in step3["command"]

def test_epss_scoring():
    rce_score = calculate_epss_score("CVE-2026-9999", title="Critical Remote Code Execution RCE in Edge Gateway", summary="Active CISA KEV listing")
    assert rce_score["epss_score"] > 0.60
    assert rce_score["quadrant"] in ("CRITICAL_ZERO_HOUR", "HIGH_PRIORITY_DISCLOSURE")
    assert "Remote Code Execution (RCE) Vector (+0.45)" in rce_score["risk_factors"]

    low_score = calculate_epss_score("CVE-2026-0001", title="Minor information disclosure", summary="No known exploit")
    assert low_score["epss_score"] < 0.30

    incidents = [
        {"id": "1", "title": "CVE-2026-1111 Minor bug", "summary": "Info leak"},
        {"id": "2", "title": "CVE-2026-9999 Critical RCE Zero-Day in CISA KEV", "summary": "Active Ransomware exploitation"}
    ]
    prioritized = prioritize_incidents_by_epss(incidents)
    assert prioritized[0]["id"] == "2"
    assert prioritized[0]["epss"]["epss_score"] > prioritized[1]["epss"]["epss_score"]

def test_microsoft_defender_kql_rule_generation():
    inc = {"title": "Zero-Day Exploit CVE-2026-7777", "severity": "CRITICAL"}
    iocs = [
        {"ioc_type": "ipv4", "normalized_value": "45.33.32.156"},
        {"ioc_type": "domain", "normalized_value": "dark-operator.xyz"}
    ]
    ioas = [{"technique_id": "T1190"}]
    rules = generate_siem_rules_for_incident(inc, iocs, ioas)
    assert "microsoft_defender" in rules
    assert "DeviceNetworkEvents" in rules["microsoft_defender"]
    assert "45.33.32.156" in rules["microsoft_defender"]
    assert "dark-operator.xyz" in rules["microsoft_defender"]
    assert "CVE-2026-7777" in rules["microsoft_defender"]
