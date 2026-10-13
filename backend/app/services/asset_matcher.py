import re
from typing import List, Dict, Any, Tuple

DEFAULT_ORG_STACK = [
    "Linux", "Ubuntu", "Windows Server", "Kubernetes", "Docker", "Apache", "Nginx",
    "PostgreSQL", "MySQL", "Redis", "AWS", "Google Cloud", "Palo Alto", "Cisco",
    "VMware", "Fortinet", "Python", "Node.js", "LangChain", "OpenAI", "Gemini"
]

def match_incident_to_assets(incident: Dict[str, Any], org_assets: List[str] = None) -> Dict[str, Any]:
    """Evaluates whether a threat report directly impacts the organization's technology stack."""
    if not org_assets:
        org_assets = DEFAULT_ORG_STACK
        
    combined_text = (
        (incident.get("title") or "") + " " +
        (incident.get("summary") or "") + " " +
        (incident.get("affected_systems") or "") + " " +
        (incident.get("affected_organization") or "")
    ).lower()
    
    matched = []
    for asset in org_assets:
        pattern = r'\b' + re.escape(asset.lower()) + r'\b'
        if re.search(pattern, combined_text):
            matched.append(asset)
            
    is_impacted = len(matched) > 0
    severity = incident.get("severity", "MEDIUM")
    
    exposure_level = "NONE"
    if is_impacted:
        exposure_level = "CRITICAL_EXPOSURE" if severity == "CRITICAL" else ("HIGH_EXPOSURE" if severity == "HIGH" else "MODERATE_EXPOSURE")
        
    # Generate tailored emergency remediation runbook
    runbook = []
    if is_impacted:
        runbook.append(f"🚨 EMERGENCY ALERT: Your monitored assets ({', '.join(matched)}) are directly referenced in this advisory.")
        runbook.append(f"1. Audit Inventory: Identify all instances, containers, or endpoints running {', '.join(matched)} across production and staging.")
        runbook.append("2. Perimeter Shielding: Apply immediate egress/ingress filtering or WAF rule blocking referenced C2 nodes.")
        runbook.append("3. Version Verification: Cross-reference installed patch versions against the vendor advisory.")
        runbook.append("4. Threat Hunting: Query EDR and SIEM using the generated Sigma and Splunk rules for past 30 days of telemetry.")
    else:
        runbook.append("Informational tracking: No immediate direct matches with current active tech stack assets.")
        
    return {
        "is_impacted": is_impacted,
        "matched_assets": matched,
        "exposure_level": exposure_level,
        "runbook": runbook
    }
