import datetime
from sqlalchemy.future import select
from app.database.session import AsyncSessionLocal
from app.database.models import (
    Incident, SourceDocument, IOC, IncidentIOC,
    IncidentTechnique, AttackTechnique, MitigationRecommendation,
    VerificationReview, Notification, IOA
)
from app.rag.vector_store import vector_store

DEMO_INCIDENTS = [
    {
        "title": "SYNTHETIC DEMO: LockBit 4.0 Campaign Compromises Regional Healthcare Network",
        "org": "Apex Memorial Health Systems",
        "severity": "CRITICAL",
        "summary": "Threat actors associated with LockBit 4.0 gained initial foothold through an exposed Citrix NetScaler ADC gateway exploiting CVE-2023-4966 (Citrix Bleed). The attackers exfiltrated 450GB of patient electronic health records before deploying ransomware encrypting 1,200 endpoints across three hospital campuses.",
        "root_cause": "Unpatched internet-facing Citrix NetScaler device vulnerable to CVE-2023-4966 combined with lack of multi-factor authentication on administrative session tokens.",
        "initial_access": "Exploitation of CVE-2023-4966 on unpatched perimeter NetScaler gateway.",
        "iocs": [
            {"type": "cve", "val": "CVE-2023-4966", "role": "Perimeter Exploit"},
            {"type": "ipv4", "val": "194.26.29.114", "role": "LockBit C2 Server"},
            {"type": "domain", "val": "apex-telemetry-sync.com", "role": "Staging Exfiltration Host"},
            {"type": "sha256", "val": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "role": "LockBit Encryptor Binary"}
        ],
        "ioas": [
            {
                "type": "EXECUTION",
                "pattern": "GPO-Based Ransomware Binary Staging & Execution",
                "tech": "T1484.001",
                "behavior": "Adversaries modified Group Policy Objects across domain controllers to stage and execute LockBit payloads simultaneously on 1,200 domain-joined workstations.",
                "detection": "Event ID 5136 (Directory Service Object Modified) where GPO scheduled task is created pointing to %TEMP% or administrative shares.",
                "quote": "Adversaries utilized hijacked domain administrative credentials to deploy scheduled tasks via Active Directory Group Policy."
            },
            {
                "type": "DEFENSE_EVASION",
                "pattern": "Citrix NetScaler Memory Dump & Token Replay",
                "tech": "T1539",
                "behavior": "Extracted session tokens directly from NetScaler memory using HTTP buffer over-read without generating standard logon events.",
                "detection": "HTTP POST/GET to /oauth/idp/idx with oversized headers returning HTTP 200 containing partial session cookies.",
                "quote": "Citrix Bleed vulnerability allowed unauthenticated attackers to dump session tokens directly from memory."
            }
        ],
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "behavior": "Exploitation of Citrix Bleed buffer overflow"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "behavior": "Hijacked authenticated session cookies"},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "behavior": "LockBit 4.0 AES-256 payload deployed via GPO"}
        ],
        "recommendations": [
            {"cat": "IMMEDIATE", "title": "Revoke NetScaler Sessions", "action": "Invalidate all active Citrix NetScaler AAA sessions and rotate credentials.", "prio": "URGENT"},
            {"cat": "PREVENTIVE", "title": "Deploy Hotfix for CVE-2023-4966", "action": "Upgrade all Citrix ADC and Gateway appliances to supported firmware builds.", "prio": "HIGH"},
            {"cat": "DETECTION", "title": "Monitor Outbound Large File Transfers", "action": "Alert on unusual outbound traffic volume from internal DB subnets to unknown ASN hosts.", "prio": "HIGH"}
        ]
    },
    {
        "title": "SYNTHETIC DEMO: Volt Typhoon Espionage Group Pre-Positions in Critical Energy Infrastructure",
        "org": "Midwest Regional Power & Electric Grid",
        "severity": "HIGH",
        "summary": "State-sponsored cyber group Volt Typhoon leveraged compromised SOHO routers and living-off-the-land techniques (LOTL) to establish persistent access into SCADA network management VLANs.",
        "root_cause": "Default manufacturer passwords on legacy edge network devices and unsegmented management network interfaces.",
        "initial_access": "Brute force and credential stuffing against edge Fortinet and Cisco routers.",
        "iocs": [
            {"type": "cve", "val": "CVE-2024-21762", "role": "Fortinet SSL-VPN Exploit"},
            {"type": "ipv4", "val": "45.154.255.88", "role": "KV-Botnet Pivot Node"},
            {"type": "domain", "val": "update-grid-controller.net", "role": "Command & Control Domain"}
        ],
        "ioas": [
            {
                "type": "LATERAL_MOVEMENT",
                "pattern": "Living-Off-The-Land (LOTL) Native Command Discovery",
                "tech": "T1059.003",
                "behavior": "Adversary avoided dropping custom malware; executed native wmic process, netsh portproxy, and ping to map internal SCADA subnets without triggering antivirus.",
                "detection": "Suspicious parent-child process execution where wmic.exe or netsh.exe is spawned by web server services or unusual service accounts.",
                "quote": "Adversary relied exclusively on legitimate built-in administrative binaries (LOTL) to perform subnet discovery."
            }
        ],
        "techniques": [
            {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access", "behavior": "Compromised VPN gateway access"},
            {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution", "behavior": "Living-off-the-land utility execution (wmic, netsh)"}
        ],
        "recommendations": [
            {"cat": "IMMEDIATE", "title": "Isolate Operational Technology VLANs", "action": "Enforce strict unidirectional firewalls between IT enterprise and OT SCADA networks.", "prio": "URGENT"},
            {"cat": "DETECTION", "title": "Audit Built-in Admin CLI Tool Usage", "action": "Enable process command-line logging (Event ID 4688) for cmd.exe, powershell.exe, and certutil.exe.", "prio": "HIGH"}
        ]
    }
]

async def seed_demo_data():
    async with AsyncSessionLocal() as db:
        for item in DEMO_INCIDENTS:
            existing = await db.execute(select(Incident).where(Incident.title == item["title"]))
            if existing.scalars().first():
                continue

            doc = SourceDocument(
                title=item["title"],
                canonical_url=f"https://cti-demo.internal/incidents/{abs(hash(item['title']))}",
                content_hash=f"hash_{abs(hash(item['title']))}",
                raw_content=item["summary"],
                extracted_text=f"{item['summary']}\n\nRoot Cause: {item['root_cause']}",
                processing_status="COMPLETED"
            )
            db.add(doc)
            await db.flush()

            inc = Incident(
                primary_source_doc_id=doc.id,
                title=item["title"],
                summary=item["summary"],
                affected_organization=item["org"],
                root_cause_analysis=item["root_cause"],
                initial_access_vector=item["initial_access"],
                severity=item["severity"],
                confidence_score=0.98,
                status="PUBLISHED",
                is_demo=True
            )
            db.add(inc)
            await db.flush()

            # IOCs
            for i in item["iocs"]:
                ioc_res = await db.execute(select(IOC).where(IOC.normalized_value == i["val"]))
                ioc_rec = ioc_res.scalars().first()
                if not ioc_rec:
                    from app.tools.tool_registry import defang_ioc
                    ioc_rec = IOC(
                        ioc_type=i["type"],
                        normalized_value=i["val"],
                        defanged_value=defang_ioc(i["type"], i["val"]),
                        threat_status="CONFIRMED_MALICIOUS"
                    )
                    db.add(ioc_rec)
                    await db.flush()

                assoc = IncidentIOC(
                    incident_id=inc.id,
                    ioc_id=ioc_rec.id,
                    context_role=i["role"],
                    confidence=1.0,
                    supporting_passage=item["summary"]
                )
                db.add(assoc)

            # Techniques
            for t in item["techniques"]:
                tech_res = await db.execute(select(AttackTechnique).where(AttackTechnique.id == t["id"]))
                tech_rec = tech_res.scalars().first()
                if not tech_rec:
                    tech_rec = AttackTechnique(
                        id=t["id"],
                        name=t["name"],
                        tactic=t["tactic"]
                    )
                    db.add(tech_rec)
                    await db.flush()

                inc_t = IncidentTechnique(
                    incident_id=inc.id,
                    technique_id=t["id"],
                    supporting_behavior=t["behavior"],
                    confidence=0.95,
                    is_confirmed=True
                )
                db.add(inc_t)

            # IOAs
            for a in item.get("ioas", []):
                ioa_rec = IOA(
                    incident_id=inc.id,
                    ioa_type=a["type"],
                    pattern_name=a["pattern"],
                    technique_id=a["tech"],
                    observed_behavior=a["behavior"],
                    detection_logic=a["detection"],
                    evidence_quote=a["quote"],
                    confidence=0.95
                )
                db.add(ioa_rec)

            # Recommendations
            for r in item["recommendations"]:
                rec = MitigationRecommendation(
                    incident_id=inc.id,
                    category=r["cat"],
                    title=r["title"],
                    action_items=r["action"],
                    priority=r["prio"]
                )
                db.add(rec)

            # Verification Review
            rev = VerificationReview(
                incident_id=inc.id,
                status="APPROVED",
                review_score=0.98,
                accepted_findings='["Corroborated CVE", "Verified C2 nodes"]',
                rejected_findings='[]',
                rejection_reasons='"Independent evidence check passed with high fidelity."'
            )
            db.add(rev)

            # Notification record
            notif = Notification(
                incident_id=inc.id,
                notification_type="INCIDENT_REPORT",
                recipient="security-analyst@example.com",
                subject=f"[{item['severity']} CTI ALERT] {item['title']}",
                html_content="<p>Demo alert</p>",
                plain_text_content="Demo alert",
                delivery_status="PREVIEW_ONLY",
                idempotency_key=f"demo-{inc.id}"
            )
            db.add(notif)

            # Add to Vector store for RAG
            vector_store.add_document(
                doc_id=inc.id,
                title=inc.title,
                content=f"{inc.title}\n{inc.summary}\n{inc.root_cause_analysis}",
                source_url=doc.canonical_url,
                doc_type="demo_incident",
                incident_id=inc.id
            )

        await db.commit()
