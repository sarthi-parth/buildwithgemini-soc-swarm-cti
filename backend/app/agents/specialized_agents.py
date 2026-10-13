import json
import os
import re
from typing import Dict, Any, List, Optional
from google.genai import Client
from app.config import settings
from app.tools.tool_registry import extract_deterministic_iocs, validate_ioc_format, defang_ioc

def get_genai_client() -> Optional[Client]:
    try:
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
        os.environ["GOOGLE_CLOUD_PROJECT"] = settings.GOOGLE_CLOUD_PROJECT
        os.environ["GOOGLE_CLOUD_LOCATION"] = settings.GOOGLE_CLOUD_LOCATION
        return Client()
    except Exception as e:
        print(f"[Agents] Error creating GenAI Client: {e}")
        return None

def clean_json_response(text: str) -> Dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try finding json block
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return {"raw_text": text}


# ==========================================
# AGENT 1: THREAT DISCOVERY AGENT
# ==========================================
class ThreatDiscoveryAgent:
    name = "Threat Discovery Agent"

    @classmethod
    async def run(cls, raw_item: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies incoming feed entry, evaluates CTI priority, normalizes metadata."""
        title = raw_item.get("title", "")
        summary = raw_item.get("summary", "")
        url = raw_item.get("url", "")

        client = get_genai_client()
        if not client:
            return {
                "is_incident": True,
                "category": "Security Advisory",
                "severity": "HIGH",
                "affected_org": "Unknown",
                "summary": summary[:400]
            }

        prompt = f"""
You are the Threat Discovery Agent in a SOC Cyber Threat Intelligence platform.
Evaluate this security item:
Title: {title}
URL: {url}
Snippet: {summary}

Respond ONLY with a JSON object:
{{
  "is_incident": true/false (true if this describes a breach, ransomware, vulnerability, active exploitation, or security advisory),
  "category": "Ransomware" | "Breach" | "Vulnerability Exploitation" | "Malware Campaign" | "Advisory",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "affected_org": "Organization or vendor affected, or 'Multiple/Industry-wide'",
  "relevance_rationale": "One sentence explaining why this requires SOC investigation"
}}
"""
        resp = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
        )
        data = clean_json_response(resp.text)
        return data


# ==========================================
# AGENT 2: BREACH INVESTIGATION AGENT
# ==========================================
class BreachInvestigationAgent:
    name = "Breach Investigation Agent"

    @classmethod
    async def run(cls, title: str, source_text: str) -> Dict[str, Any]:
        """Analyzes what happened, root cause, affected assets, and reconstructs timeline."""
        client = get_genai_client()
        prompt = f"""
You are the Senior Breach Investigation Agent in a SOC CTI swarm.
Source Report Title: {title}
Evidence Text:
\"\"\"{source_text[:7000]}\"\"\"

Analyze the evidence carefully. Never invent details not present in the text.
Return ONLY a valid JSON object matching this schema:
{{
  "affected_organization": "Target name",
  "incident_summary": "Comprehensive 3-5 sentence explanation of what happened, how, and why.",
  "initial_access_vector": "Reported initial access method or 'Unknown / Not Disclosed'",
  "affected_systems": "Description of compromised servers, data, or credentials",
  "root_cause_analysis": "Root cause or configuration flaw, explicitly distinguishing confirmed facts from analyst inferences",
  "timeline": [
    {{"stage": "Initial Access", "description": "...", "timestamp": "ISO or date string if mentioned, else empty"}}
  ],
  "unknowns": ["List of critical facts not disclosed in the report"]
}}
"""
        resp = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
        )
        return clean_json_response(resp.text)


# ==========================================
# AGENT 3: IOC EXTRACTION & ENRICHMENT AGENT
# ==========================================
class IOCExtractionAgent:
    name = "IOC Extraction and Enrichment Agent"

    @classmethod
    async def run(cls, source_text: str, investigation_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts deterministic IOCs + LLM contextual indicator extraction with provenance."""
        # 1. Deterministic Pass
        deterministic_iocs = extract_deterministic_iocs(source_text)

        # 2. LLM Pass for Domains, URLs, Malware Families
        client = get_genai_client()
        llm_iocs = []
        if client:
            prompt = f"""
Extract Indicators of Compromise (IOCs) from this cybersecurity evidence.
Evidence:
\"\"\"{source_text[:6000]}\"\"\"

Only extract indicators explicitly mentioned as malicious or observed in the threat activity (domains, malicious URLs, malware family names, attacker IPs, CVEs).
Return ONLY a JSON array of objects:
[
  {{
    "ioc_type": "domain" | "url" | "malware_family" | "ipv4" | "cve",
    "normalized_value": "exact indicator string",
    "context_role": "C2 Server, Malicious Payload, Exploit target, etc.",
    "confidence": 0.95
  }}
]
"""
            try:
                resp = client.models.generate_content(
                    model=settings.GEMINI_MODEL,
                    contents=prompt,
                )
                parsed = clean_json_response(resp.text)
                if isinstance(parsed, list):
                    llm_iocs = parsed
                elif isinstance(parsed, dict) and "raw_text" not in parsed:
                    llm_iocs = parsed.get("iocs", [])
            except Exception as e:
                print(f"[IOC Agent] LLM extraction error: {e}")

        # Merge & Validate
        combined = []
        seen = set()

        for item in deterministic_iocs + llm_iocs:
            itype = item.get("ioc_type", "").lower()
            val = str(item.get("normalized_value", "")).strip()
            if not val or not itype:
                continue
            if itype == "domain" and (val.endswith(".gov") or val in ("cisa.gov", "microsoft.com", "google.com", "thehackernews.com")):
                continue # ignore legitimate publishers
            if not validate_ioc_format(itype, val):
                continue
            if val.lower() not in seen:
                seen.add(val.lower())
                combined.append({
                    "ioc_type": itype,
                    "normalized_value": val,
                    "defanged_value": defang_ioc(itype, val),
                    "context_role": item.get("context_role", "Threat Artifact"),
                    "confidence": float(item.get("confidence", 0.9)),
                    "threat_status": "SUSPICIOUS"
                })

        return combined


# ==========================================
# AGENT 4: ATTACK CHAIN, MITRE ATT&CK & IOA AGENT
# ==========================================
class AttackChainAgent:
    name = "Attack Chain, MITRE ATT&CK and IOA Agent"

    @classmethod
    async def run(cls, investigation: Dict[str, Any], source_text: str) -> Dict[str, Any]:
        """Maps observed behaviors to MITRE ATT&CK techniques AND extracts Indicators of Attack (IOAs)."""
        client = get_genai_client()
        prompt = f"""
You are the Attack Chain and Indicators of Attack (IOA) Specialist in a SOC Cyber Threat Intelligence platform.

Incident Summary: {investigation.get('incident_summary')}
Initial Access Vector: {investigation.get('initial_access_vector')}
Evidence Passage: \"\"\"{source_text[:4000]}\"\"\"

TASK:
1. Map reported adversary activities to MITRE ATT&CK techniques (techniques array).
2. Extract concrete Indicators of Attack (ioas array).
   - An IOA (Indicator of Attack) represents dynamic runtime attacker behaviors, execution methods, command lines, persistence mechanisms, defense evasion, or lateral movement patterns (e.g. LOLBin abuse, unmanaged PowerShell, credential dumping via comsvcs, scheduled task creation, token impersonation).
   - An IOA answers HOW the attack proceeds and the intent, contrasting with static IOCs (hashes/IPs).

Return ONLY valid JSON matching this schema:
{{
  "techniques": [
    {{
      "technique_id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "supporting_behavior": "Adversary exploited vulnerability in perimeter service",
      "confidence": 0.9,
      "is_confirmed": true
    }}
  ],
  "ioas": [
    {{
      "ioa_type": "EXECUTION",
      "pattern_name": "PowerShell Download Cradle & Memory Injection",
      "technique_id": "T1059.001",
      "observed_behavior": "Detailed description of adversary execution behavior observed in this report",
      "detection_logic": "Sigma/EDR guidance: process=powershell.exe with commandline arguments matching IEX/DownloadString",
      "evidence_quote": "Direct quote from source text supporting this observation",
      "confidence": 0.92
    }}
  ]
}}
"""
        resp = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
        )
        parsed = clean_json_response(resp.text)
        if isinstance(parsed, dict):
            return {
                "techniques": parsed.get("techniques", []),
                "ioas": parsed.get("ioas", [])
            }
        elif isinstance(parsed, list):
            return {"techniques": parsed, "ioas": []}
        return {"techniques": [], "ioas": []}



# ==========================================
# AGENT 5: HISTORICAL INTELLIGENCE & RAG AGENT
# ==========================================
class HistoricalRAGAgent:
    name = "Historical Intelligence and RAG Agent"

    @classmethod
    async def run(cls, title: str, summary: str, iocs: List[Dict[str, Any]], vector_store) -> Dict[str, Any]:
        """Correlates with past incidents using hybrid exact IOC matching + semantic RAG search."""
        query = f"{title}. {summary}"
        rag_chunks = vector_store.similarity_search(query, top_k=4)

        return {
            "query_used": query[:120],
            "retrieved_evidence": rag_chunks,
            "similar_incidents_found": len(rag_chunks),
            "correlation_summary": (
                f"Retrieved {len(rag_chunks)} related knowledge chunk(s) from past investigations."
                if rag_chunks else "No prior recorded incidents match this profile (novel campaign)."
            )
        }


# ==========================================
# AGENT 6: ROOT CAUSE & DEFENSIVE RECOMMENDATIONS AGENT
# ==========================================
class DefensiveRecommendationsAgent:
    name = "Root Cause and Defensive Recommendations Agent"

    @classmethod
    async def run(cls, investigation: Dict[str, Any], techniques: List[Dict[str, Any]], iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generates prioritized mitigations, detection rules, and hardening recommendations."""
        client = get_genai_client()
        prompt = f"""
You are the Principal Defensive Engineer in a SOC CTI swarm.
Investigation Data:
- Target: {investigation.get('affected_organization')}
- Summary: {investigation.get('incident_summary')}
- Root Cause: {investigation.get('root_cause_analysis')}
- Techniques: {[t.get('name') for t in techniques]}
- IOCs: {[i.get('normalized_value') for i in iocs[:5]]}

Generate actionable, prioritized mitigations in 5 categories:
1. IMMEDIATE (containment)
2. SHORT_TERM (patching & remediation)
3. PREVENTIVE (architecture & IAM)
4. DETECTION (Sigma / YARA / log queries)
5. LONG_TERM (governance & resilience)

Return ONLY a JSON array of objects:
[
  {{
    "category": "IMMEDIATE" | "SHORT_TERM" | "PREVENTIVE" | "DETECTION" | "LONG_TERM",
    "title": "Action title",
    "action_items": "Specific steps defenders must take",
    "priority": "URGENT" | "HIGH" | "MEDIUM",
    "implementation_effort": "LOW" | "MEDIUM" | "HIGH"
  }}
]
"""
        resp = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
        )
        parsed = clean_json_response(resp.text)
        if isinstance(parsed, list):
            return parsed
        return parsed.get("recommendations", []) if isinstance(parsed, dict) else []


# ==========================================
# AGENT 7: EVIDENCE VERIFICATION & QC AGENT
# ==========================================
class EvidenceVerificationAgent:
    name = "Evidence Verification and Quality Control Agent"

    @classmethod
    async def run(cls, source_text: str, investigation: Dict[str, Any], iocs: List[Dict[str, Any]], techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Independent auditor that verifies claims against source evidence and flags unsupported inferences."""
        client = get_genai_client()
        prompt = f"""
You are the Independent Evidence Verification and Quality Control Agent.
Audit this CTI investigation strictly against the provided source evidence.
Source Evidence:
\"\"\"{source_text[:5000]}\"\"\"

Findings to Audit:
- Incident Summary: {investigation.get('incident_summary')}
- Root Cause: {investigation.get('root_cause_analysis')}
- Initial Access: {investigation.get('initial_access_vector')}
- Extracted IOCs: {[i.get('normalized_value') for i in iocs]}
- MITRE Techniques: {[t.get('technique_id') for t in techniques]}

Evaluate:
1. Are the facts directly grounded in the source text?
2. Are IOCs real or hallucinated?
3. Are unconfirmed root causes labeled as inferences rather than established facts?

Return ONLY a JSON object:
{{
  "status": "APPROVED" | "NEEDS_CORRECTION",
  "review_score": 0.95 (0.0 to 1.0),
  "verified_facts": ["List of facts supported by text"],
  "unsupported_claims": ["Any claim not in the source, or empty list"],
  "reasons": "Detailed rationale for approval or rejection"
}}
"""
        resp = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=prompt,
        )
        return clean_json_response(resp.text)


# ==========================================
# AGENT 8: INTELLIGENCE REPORT & GMAIL AGENT
# ==========================================
class ReportAndNotificationAgent:
    name = "Intelligence Report and Gmail Notification Agent"

    @classmethod
    async def run(cls, incident_bundle: Dict[str, Any], gmail_service) -> Dict[str, Any]:
        """Builds final advisory, formats HTML/Text, and dispatches/previews Gmail notification."""
        email_pack = gmail_service.create_incident_email(incident_bundle)
        send_result = await gmail_service.send_email(
            recipient=email_pack["recipient"],
            subject=email_pack["subject"],
            html_content=email_pack["html"],
            plain_content=email_pack["plain"]
        )
        return {
            "email_pack": email_pack,
            "send_result": send_result
        }
