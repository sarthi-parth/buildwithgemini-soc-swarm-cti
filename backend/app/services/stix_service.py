import uuid
import datetime
from typing import List, Dict, Any

def generate_stix_bundle(incidents: List[Dict[str, Any]], iocs: List[Dict[str, Any]] = None, ioas: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Converts threat incidents, defanged indicators, and IOAs into an official STIX 2.1 JSON Bundle."""
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'soc-swarm-cti')}"
    
    objects = []
    
    # 1. Author Identity
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_str,
        "modified": now_str,
        "name": "SOC Swarm CTI Autonomous Agent",
        "description": "Multi-agent Cyber Threat Intelligence Federation grounded in Gemini 3.8 Flash",
        "identity_class": "system"
    })
    
    # 2. Indicators (IOCs)
    indicator_ids = []
    if iocs:
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "").lower()
            val = (ioc.get("normalized_value") or ioc.get("defanged_value") or "").replace("[.]", ".")
            if not val:
                continue
                
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            
            pattern = ""
            if ioc_type in ("ipv4", "ip", "c2_ip"):
                pattern = f"[ipv4-addr:value = '{val}']"
            elif ioc_type in ("domain", "hostname"):
                pattern = f"[domain-name:value = '{val}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{val}']"
            elif ioc_type == "cve":
                pattern = f"[vulnerability:name = '{val.upper()}']"
            else:
                pattern = f"[file:hashes.'SHA-256' = '{val}']"
                
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_str,
                "modified": now_str,
                "name": f"Indicator: {val}",
                "description": f"Extracted threat indicator: {val}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_str,
                "created_by_ref": identity_id
            })
            
    # 3. Attack Patterns (IOAs)
    attack_pattern_ids = []
    if ioas:
        for ioa in ioas:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            attack_pattern_ids.append(ap_id)
            tech_id = ioa.get("technique_id", "T1190")
            pattern_name = ioa.get("pattern_name", "Observed Behavior")
            
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_str,
                "modified": now_str,
                "name": pattern_name,
                "description": ioa.get("observed_behavior", ""),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                    }
                ],
                "created_by_ref": identity_id
            })
            
    # 4. Reports for Incidents
    for inc in incidents:
        rep_id = f"report--{uuid.uuid4()}"
        ref_ids = indicator_ids[:5] + attack_pattern_ids[:3]
        
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": rep_id,
            "created": now_str,
            "modified": now_str,
            "name": inc.get("title", "Threat Incident Report"),
            "description": inc.get("summary", ""),
            "published": now_str,
            "report_types": ["threat-report"],
            "object_refs": [identity_id] + ref_ids,
            "created_by_ref": identity_id,
            "labels": [inc.get("category", "General Cybersecurity"), inc.get("severity", "HIGH")]
        })
        
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
