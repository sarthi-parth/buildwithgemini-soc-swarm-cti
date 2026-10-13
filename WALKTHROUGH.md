# Walkthrough: SOC Swarm CTI - Live Multi-Platform Intelligence, IOA Extraction & Cloud Deployment

**SOC Swarm CTI** is an autonomous multi-agent Cyber Threat Intelligence (CTI) and breach investigation application powered by **Gemini 3.8 Flash**, **Vertex AI text-embedding-004**, **SQLite**, **Streamlit**, **FastAPI**, and **React + Vite**.

This milestone delivers live real-time ingestion across 7 threat intelligence platforms (government catalogs, live botnet trackers, and research feeds), multi-version change detection (`report_versions`), behavioral Indicators of Attack (IOA), and deployment to **Google Cloud Run**.

---

## 1. Multi-Platform Live Ingestion Architecture

```mermaid
graph TD
    A[CISA KEV: Live Exploited Zero-Days] -->|Live REST/JSON| H(Live Platform Fetcher)
    B[abuse.ch Feodo Tracker: Live Botnet C2 IPs] -->|Live REST/JSON| H
    C[CISA Advisories: Emergency Directives] -->|Live RSS/XML| H
    D[The Hacker News: Breaking Breaches] -->|Live RSS/XML| H
    E[SANS ISC: Telemetry & Handler Diaries] -->|Live RSS/XML| H
    F[Security Affairs: APT & State Cyber Warfare] -->|Live RSS/XML| H
    G[arXiv AI Security: Prompt Injections & Jailbreaks] -->|Live RSS/XML| H
    H -->|Deduplicate & Content Hash| I{Change Detector}
    I -->|New Report| J[Store Incident + Version 1]
    I -->|Hash Mismatch / Update| K[Create Version Snapshot & Diff Summary]
    J & K --> L[Extract & Defang IOCs: IPv4, URL, CVE, Domain]
    J & K --> M[Extract Behavioral IOAs: MITRE ATT&CK & EDR Logic]
    J & K --> N[Log Alert in Gmail Notification Center]
    L & M & N --> O[(SQLite Relational DB: cti_platform.db)]
    O --> P[Streamlit UI + Gemini 3.8 Flash Chat]
    O --> Q[Cloud Run Production Endpoint]
```

---

## 2. Integrated Live Threat Intelligence Platforms

1. **CISA Known Exploited Vulnerabilities (KEV)**:
   - Official US Cybersecurity and Infrastructure Security Agency catalog of actively exploited CVE zero-days.
   - Extracts: CVE ID, vendor, product, date added, remediation required, and `T1190` exploit attack patterns.
2. **abuse.ch Feodo Tracker**:
   - Real-time botnet command-and-control (C2) server IP addresses and port telemetry (Emotet, QakBot, Dridex).
   - Extracts: Safe defanged IPv4 IOCs (`162[.]243[.]103[.]246:8080`), port numbers, malware families, and C2 beaconing IOAs (`T1071.001`).
3. **CISA Cybersecurity Advisories**:
   - National emergency directives and industrial control systems (ICS) advisories.
4. **The Hacker News (THN)**:
   - Global cyber breach reporting, ransomware campaigns, and zero-day disclosures.
5. **SANS Internet Storm Center (ISC)**:
   - Real-time global threat levels, port scanning activity, and daily handler analysis diaries.
6. **Security Affairs**:
   - Nation-state cyber warfare, APT espionage, and critical infrastructure attacks.
7. **arXiv AI Security (cs.CR)**:
   - Academic and industry disclosures on LLM prompt injections, jailbreaks, malicious MCP server tools, and autonomous agent hijacking (`T1059.006`).

---

## 3. Mandatory Feature Verification

### 1. Incident Versioning & Meaningful Update Detection (Feature #7)
- SHA-256 content hashes are calculated for every incoming report.
- When an advisory is updated on the source platform:
  - Preserves previous versions in `report_versions` table (`version_number = 1, 2, ...`).
  - Records diff summary and analyst change notes.
  - Updates incident flag to `is_updated = 1` and displays badge `🔔 UPDATED (v2)` in UI.
  - Emits an `[SOC SWARM][REPORT UPDATE]` notification.

### 2. Daily Threat Intelligence Newsletters & Deduplication
- **Cross-Source Deduplication**: Normalizes stories across multiple outlets reporting on the same breach or CVE, ensuring only unique incidents are cataloged.
- **Executive Daily Digest**: Synthesized with Gemini 3.8 Flash, featuring:
  - 🛡️ Executive Strategic Briefing
  - 🚨 Critical CVEs & Zero-Day Exploitations
  - 🤖 AI Security & Adversarial Threat Watch
  - 🦠 Active Botnet Infrastructure & Network IOCs
  - ⚔️ Behavioral IOAs & MITRE ATT&CK Recommendations
  - 📋 Index of Unique Verified Disclosures for the Day
- **Historical Time-Travel Archive**: Date picker allowing security analysts to select any previous calendar date (`2026-10-13`, `2026-10-12`, `2026-10-11`, etc.) to view past briefings and reports.
- **One-Click Markdown Download**: Analysts can export the complete daily newsletter for executive briefings.

### 3. Behavioral IOA Extraction
- Extracts adversary tactics, techniques, and procedures (TTPs) mapped to **MITRE ATT&CK**.
- Generates concrete detection logic (Sigma rules, EDR queries, Suricata signatures).
- Exportable to CSV via one click in the **IOA Explorer** tab.

### 4. Defensive IOC Normalization & Defanging
- Defangs IPv4, IPv6, URLs, domains, and emails (`[.]`, `hxxp://`).
- Exportable to CSV via one click in the **IOC Explorer** tab.

### 5. Gemini 3.8 Flash Threat Intelligence Chat
- Grounded in local SQLite store and live telemetry.
- Exact database lookup for IP, domain, hash, or CVE queries.
- Clear separation between stored database findings and live synthesized intelligence.

### 6. Autonomous SIEM & EDR Rule Synthesizer
- Generates production-ready detection logic across 6 enterprise standards:
  - **Sigma Rule (YAML)**: EDR detection rule mapped to MITRE ATT&CK technique IDs.
  - **Splunk SPL**: Ready-to-execute search syntax for firewall, proxy, and EDR indexes.
  - **Elasticsearch KQL**: Query for Elastic Defend and Kibana SIEM.
  - **Suricata / Snort**: Network intrusion signature for active botnet C2 traffic.
  - **AWS WAF / Cloudflare**: IP set blocklist JSON for boundary protection.
  - **YARA**: File and host memory pattern signature.

### 7. Tech Stack Watchdog & Impact Matcher
- Evaluates threat reports against the organization's monitored infrastructure (Linux, Kubernetes, Docker, Windows Server, Apache, Nginx, PostgreSQL, AWS, Palo Alto, Cisco, Fortinet, etc.).
- Categorizes exposure level (`CRITICAL_EXPOSURE`, `HIGH_EXPOSURE`) and synthesizes an automated emergency remediation runbook.

### 8. STIX 2.1 & TAXII 2.1 Compliance
- Implements Oasis STIX 2.1 JSON bundle standard (`bundle`, `identity`, `indicator`, `attack-pattern`, `report`).
- Exposes direct endpoint `/api/stix2/bundle` and one-click JSON download for enterprise SIEM ingestion.

### 9. ChatOps & Slack Dispatcher
- Formats rich Slack Block-Kit messages with buttons (`[🛡️ View in Dashboard]`, `[📋 Copy Sigma Rule]`) and posts to `#soc-threat-intel`.

---

## 4. Deployment Verification

### 1. Local Streamlit MVP
- URL: [http://localhost:8501](http://localhost:8501)
- HTTP Status: `200 OK`
- Navigation: Daily Threat Intel Digest, Executive Dashboard, SIEM & EDR Rule Synthesizer, Tech Stack Watchdog, STIX 2.1 Exporter, ChatOps Dispatcher, Live Ingestion, Feed, IOC Explorer, IOA Explorer, Chat, Settings.

### 2. Google Cloud Run (Production)
- Service: `soc-swarm-cti`
- Current Revision: `soc-swarm-cti-00004-sfd`
- Production URL: [https://soc-swarm-cti-235215015655.asia-south2.run.app](https://soc-swarm-cti-235215015655.asia-south2.run.app)
- Traffic: 100% routed
- HTTP Verification:
  ```bash
  curl -s -I https://soc-swarm-cti-235215015655.asia-south2.run.app
  HTTP/2 200
  ```

### 3. GitHub Source Code Repository
- Public URL: [https://github.com/sarthi-parth/buildwithgemini-soc-swarm-cti](https://github.com/sarthi-parth/buildwithgemini-soc-swarm-cti)
- Pushed Commit: `76840ed` (*feat: add SIEM/EDR rule synthesizer, STIX 2.1 exporter, tech stack watchdog runbooks, and Slack ChatOps*)

### 4. MITRE ATT&CK Enterprise Matrix Navigator
- Evaluates 14 Enterprise Tactics (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact).
- Real-time heat-map correlating active threat telemetry and behavioral IOAs against MITRE technique IDs (`T1190`, `T1566`, `T1059`, `T1071`, `T1486`).
- Direct technique drill-down with correlated incidents and defensive mitigation mappings.

### 5. Autonomous Incident Response Playbook Runner (NIST SP 800-61)
- Interactive containment and remediation execution across 3 primary threat scenarios:
  1. **Ransomware Outbreak & Encryption Neutralization** (Endpoint layer-2/3 isolation, krbtgt Kerberos rotation, C2 egress DROP rules)
  2. **Zero-Day Public Exploitation (RCE) Response** (Socket enumeration, reverse proxy WAF virtual patching, VPN allowlisting)
  3. **Botnet C2 Beaconing & Lateral Infection Triage** (NetFlow jitter correlation, internal DNS sinkholing, BGP null-routing)
- Generates copyable, production-ready mitigation scripts across PowerShell, Linux iptables, Nginx, Zeek, and Cisco IOS.

### 6. EPSS & CVSS Threat Prioritization Engine
- Computes real-world Exploit Prediction Scoring System (EPSS) probability percentages (0–100%) and percentile rankings.
- 4-Quadrant Threat Triage Matrix:
  - **CRITICAL ZERO-HOUR** (EPSS > 70%, SLA < 24h)
  - **HIGH PRIORITY** (EPSS > 40%, SLA < 72h)
  - **ELEVATED MONITORING** (Bi-weekly maintenance)
  - **STANDARD HYGIENE**
- Interactive Zero-Day Sandbox Calculator for ad-hoc threat evaluation.

### 7. Multi-SIEM/EDR Hunting Query Synthesizer (7 Formats)
- Production-ready signatures for:
  1. Sigma Rule (YAML)
  2. Splunk Enterprise (SPL)
  3. Elasticsearch / Kibana (KQL)
  4. **Microsoft Defender XDR & Microsoft Sentinel Advanced Hunting (KQL)**
  5. Suricata & Snort NIDS Signatures
  6. AWS WAF IPSet & Cloudflare Blocklist JSON
  7. YARA Host Memory & Binary Rules

---

## 4. Production Deployment & Verification

### 1. Cloud Run Deployment
- Service: `soc-swarm-cti`
- Production URL: [https://soc-swarm-cti-235215015655.asia-south2.run.app](https://soc-swarm-cti-235215015655.asia-south2.run.app)
- Traffic: 100% routed
- HTTP Verification:
  ```bash
  curl -s -I https://soc-swarm-cti-235215015655.asia-south2.run.app
  HTTP/2 200
  ```

### 2. Vertex AI Agent Platform Deployment (Reasoning Engine)
- Target: `agent_runtime` (Location: `us-east1`)
- Agent Runtime ID: `projects/235215015655/locations/us-east1/reasoningEngines/6059220564185186304`
- Protocol: Agent-to-Agent (A2A)

### 3. Automated Test Suite
- Test Runner: `pytest` (**18/18 tests passed - 100% pass rate**)
  - `test_rule_generator`: Passed
  - `test_stix_bundle_generation`: Passed
  - `test_asset_matcher`: Passed
  - `test_slack_webhook_payload`: Passed
  - `test_defang_val`: Passed
  - `test_title_similarity_deduplication`: Passed
  - `test_newsletter_generation_flow`: Passed
  - `test_ioc_format_validation`: Passed
  - `test_ioc_defanging`: Passed
  - `test_source_url_normalization`: Passed
  - `test_deterministic_ioc_extraction`: Passed
  - `test_email_payload_generation`: Passed
  - `test_prompt_injection_sanitization_in_iocs`: Passed
  - `test_email_recipient_tamper_defense`: Passed
  - `test_mitre_matrix_generation`: Passed
  - `test_playbook_service`: Passed
  - `test_epss_scoring`: Passed
  - `test_microsoft_defender_kql_rule_generation`: Passed
