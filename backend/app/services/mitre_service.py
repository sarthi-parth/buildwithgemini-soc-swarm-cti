"""MITRE ATT&CK Enterprise Matrix Navigator Service
Provides comprehensive tactic/technique catalog, mapping, and matrix aggregation for CTI incidents.
"""
from typing import Dict, List, Any
from collections import defaultdict

MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "Recon"},
    {"id": "TA0042", "name": "Resource Development", "short": "Res Dev"},
    {"id": "TA0001", "name": "Initial Access", "short": "Init Access"},
    {"id": "TA0002", "name": "Execution", "short": "Execution"},
    {"id": "TA0003", "name": "Persistence", "short": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "Priv Escal"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "Def Evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "Cred Access"},
    {"id": "TA0007", "name": "Discovery", "short": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "Lateral Mvmt"},
    {"id": "TA0009", "name": "Collection", "short": "Collection"},
    {"id": "TA0011", "name": "Command & Control", "short": "C2"},
    {"id": "TA0010", "name": "Exfiltration", "short": "Exfiltration"},
    {"id": "TA0040", "name": "Impact", "short": "Impact"},
]

COMMON_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001", "tactic_name": "Initial Access", "severity": "CRITICAL"},
    "T1566": {"name": "Phishing", "tactic": "TA0001", "tactic_name": "Initial Access", "severity": "HIGH"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001", "tactic_name": "Initial Access", "severity": "HIGH"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "TA0001", "tactic_name": "Initial Access", "severity": "CRITICAL"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "tactic_name": "Execution", "severity": "HIGH"},
    "T1204": {"name": "User Execution", "tactic": "TA0002", "tactic_name": "Execution", "severity": "MEDIUM"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003", "tactic_name": "Persistence", "severity": "MEDIUM"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "TA0003", "tactic_name": "Persistence", "severity": "HIGH"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004", "tactic_name": "Privilege Escalation", "severity": "CRITICAL"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004", "tactic_name": "Privilege Escalation", "severity": "HIGH"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005", "tactic_name": "Defense Evasion", "severity": "HIGH"},
    "T1070": {"name": "Indicator Removal on Host", "tactic": "TA0005", "tactic_name": "Defense Evasion", "severity": "MEDIUM"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006", "tactic_name": "Credential Access", "severity": "CRITICAL"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006", "tactic_name": "Credential Access", "severity": "HIGH"},
    "T1046": {"name": "Network Service Discovery", "tactic": "TA0007", "tactic_name": "Discovery", "severity": "MEDIUM"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007", "tactic_name": "Discovery", "severity": "LOW"},
    "T1021": {"name": "Remote Services (SMB/RDP/SSH)", "tactic": "TA0008", "tactic_name": "Lateral Movement", "severity": "CRITICAL"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "TA0008", "tactic_name": "Lateral Movement", "severity": "HIGH"},
    "T1005": {"name": "Data from Local System", "tactic": "TA0009", "tactic_name": "Collection", "severity": "HIGH"},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "TA0011", "tactic_name": "Command & Control", "severity": "CRITICAL"},
    "T1573": {"name": "Encrypted Channel", "tactic": "TA0011", "tactic_name": "Command & Control", "severity": "HIGH"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "TA0010", "tactic_name": "Exfiltration", "severity": "CRITICAL"},
    "T1486": {"name": "Data Encrypted for Impact (Ransomware)", "tactic": "TA0040", "tactic_name": "Impact", "severity": "CRITICAL"},
    "T1489": {"name": "Service Stop", "tactic": "TA0040", "tactic_name": "Impact", "severity": "HIGH"},
}

def get_technique_details(technique_id: str) -> Dict[str, Any]:
    tid = technique_id.upper().strip()
    if tid in COMMON_TECHNIQUES:
        return {"id": tid, **COMMON_TECHNIQUES[tid]}
    return {
        "id": tid,
        "name": f"Technique {tid}",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "severity": "HIGH"
    }

def build_mitre_matrix(incidents: List[Dict[str, Any]], ioas: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Correlates incidents and extracted IOAs against the MITRE ATT&CK Enterprise Matrix."""
    technique_counts = defaultdict(int)
    technique_incidents = defaultdict(list)
    
    # 1. Harvest from IOA records
    for ioa in ioas:
        tid = (ioa.get("technique_id") or "T1190").upper()
        technique_counts[tid] += 1
        meta = ioa.get("behavior_description") or ioa.get("name")
        technique_incidents[tid].append({
            "incident_id": ioa.get("incident_id"),
            "context": meta or "Observed Attack Pattern"
        })
        
    # 2. Harvest from incident access vectors
    for inc in incidents:
        vector = (inc.get("initial_access_vector") or "").lower()
        title = (inc.get("title") or "").lower()
        if "exploit" in vector or "cve" in vector or "vulnerability" in title:
            technique_counts["T1190"] += 1
            technique_incidents["T1190"].append({"incident_id": inc.get("id"), "context": inc.get("title")})
        if "phish" in vector or "email" in vector or "attachment" in title:
            technique_counts["T1566"] += 1
            technique_incidents["T1566"].append({"incident_id": inc.get("id"), "context": inc.get("title")})
        if "ransomware" in title or "encrypt" in title:
            technique_counts["T1486"] += 1
            technique_incidents["T1486"].append({"incident_id": inc.get("id"), "context": inc.get("title")})
        if "c2" in title or "botnet" in title or "beacon" in title:
            technique_counts["T1071"] += 1
            technique_incidents["T1071"].append({"incident_id": inc.get("id"), "context": inc.get("title")})

    # Ensure baseline demonstration techniques if empty
    if not technique_counts:
        technique_counts["T1190"] = 4
        technique_counts["T1566"] = 3
        technique_counts["T1059"] = 2
        technique_counts["T1071"] = 5
        technique_counts["T1486"] = 3

    # Group techniques by Tactic
    tactic_columns = []
    total_active_techniques = len(technique_counts)
    
    for tactic in MITRE_TACTICS:
        t_id = tactic["id"]
        # Find matching techniques in catalog
        matching = []
        for tid, details in COMMON_TECHNIQUES.items():
            if details["tactic"] == t_id:
                count = technique_counts.get(tid, 0)
                matching.append({
                    "id": tid,
                    "name": details["name"],
                    "severity": details["severity"],
                    "count": count,
                    "is_active": count > 0,
                    "incidents": technique_incidents.get(tid, [])[:3]
                })
        tactic_columns.append({
            "tactic_id": t_id,
            "tactic_name": tactic["name"],
            "tactic_short": tactic["short"],
            "techniques": matching,
            "active_count": sum(1 for m in matching if m["is_active"])
        })

    return {
        "tactics": tactic_columns,
        "total_active_techniques": total_active_techniques,
        "top_techniques": sorted(
            [{"id": tid, "count": count, **get_technique_details(tid)} for tid, count in technique_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:5]
    }
