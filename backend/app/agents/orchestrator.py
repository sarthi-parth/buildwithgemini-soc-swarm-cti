import asyncio
import datetime
import json
import uuid
from typing import Dict, Any, Optional
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.database.session import AsyncSessionLocal
from app.database.models import (
    Incident, SourceDocument, IOC, IncidentIOC,
    IncidentTechnique, AttackTechnique, TimelineEvent,
    MitigationRecommendation, HistoricalCorrelation,
    AgentRun, ToolExecution, VerificationReview, Notification, IOA
)
from app.agents.specialized_agents import (
    BreachInvestigationAgent, IOCExtractionAgent,
    AttackChainAgent, HistoricalRAGAgent,
    DefensiveRecommendationsAgent, EvidenceVerificationAgent,
    ReportAndNotificationAgent
)
from app.rag.vector_store import vector_store
from app.services.gmail_service import gmail_service

class SwarmOrchestrator:
    @classmethod
    async def investigate_incident(cls, incident_id: str) -> Dict[str, Any]:
        """Coordinates the multi-agent investigation lifecycle."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Incident)
                .options(selectinload(Incident.primary_source_doc))
                .where(Incident.id == incident_id)
            )
            incident = result.scalars().first()
            if not incident:
                return {"error": "Incident not found"}

            source_doc = incident.primary_source_doc
            source_text = (source_doc.extracted_text or source_doc.raw_content or incident.summary or "") if source_doc else incident.summary
            source_url = source_doc.canonical_url if source_doc else "https://cisa.gov"
            title = incident.title

            # Step 1: State transition -> INVESTIGATING
            incident.status = "INVESTIGATING"
            await db.commit()

            # Record Orchestrator Agent Run
            run_record = AgentRun(
                incident_id=incident.id,
                agent_name="Swarm Orchestrator",
                status="RUNNING",
                inputs=json.dumps({"incident_id": incident.id, "title": title}),
                started_at=datetime.datetime.now(datetime.timezone.utc)
            )
            db.add(run_record)
            await db.commit()

            start_time = datetime.datetime.now(datetime.timezone.utc)

            # Step 2: Run Investigation, IOC Extraction & Attack Chain in parallel
            t1 = asyncio.create_task(BreachInvestigationAgent.run(title, source_text))
            t2 = asyncio.create_task(IOCExtractionAgent.run(source_text, {}))
            investigation_data, iocs_data = await asyncio.gather(t1, t2)

            t3 = asyncio.create_task(AttackChainAgent.run(investigation_data, source_text))
            attack_chain_result = await t3
            if isinstance(attack_chain_result, dict):
                techniques_data = attack_chain_result.get("techniques", [])
                ioas_data = attack_chain_result.get("ioas", [])
            else:
                techniques_data = attack_chain_result
                ioas_data = []

            # Step 3: Historical Intelligence & RAG Correlation
            t4 = asyncio.create_task(HistoricalRAGAgent.run(title, investigation_data.get("incident_summary", ""), iocs_data, vector_store))
            rag_data = await t4

            # Step 4: Defensive Recommendations
            t5 = asyncio.create_task(DefensiveRecommendationsAgent.run(investigation_data, techniques_data, iocs_data))
            recommendations_data = await t5

            # Step 5: Independent Evidence Verification & QC Reviewer
            t6 = asyncio.create_task(EvidenceVerificationAgent.run(source_text, investigation_data, iocs_data, techniques_data))
            verification_data = await t6

            # Step 6: Persist findings to Relational DB
            incident.summary = investigation_data.get("incident_summary", incident.summary)
            incident.affected_organization = investigation_data.get("affected_organization", incident.affected_organization)
            incident.affected_systems = investigation_data.get("affected_systems")
            incident.initial_access_vector = investigation_data.get("initial_access_vector")
            incident.root_cause_analysis = investigation_data.get("root_cause_analysis")
            incident.confidence_score = float(verification_data.get("review_score", 0.85))

            # Timeline events
            for idx, item in enumerate(investigation_data.get("timeline", [])):
                event = TimelineEvent(
                    incident_id=incident.id,
                    event_order=idx,
                    stage=item.get("stage", "Observed Activity"),
                    description=item.get("description", ""),
                    event_timestamp=None
                )
                db.add(event)

            # IOCs & Associations
            for item in iocs_data:
                norm_val = item["normalized_value"]
                existing_ioc_res = await db.execute(select(IOC).where(IOC.normalized_value == norm_val))
                ioc_record = existing_ioc_res.scalars().first()
                if not ioc_record:
                    ioc_record = IOC(
                        ioc_type=item["ioc_type"],
                        normalized_value=norm_val,
                        defanged_value=item["defanged_value"],
                        threat_status=item.get("threat_status", "SUSPICIOUS")
                    )
                    db.add(ioc_record)
                    await db.flush()

                assoc = IncidentIOC(
                    incident_id=incident.id,
                    ioc_id=ioc_record.id,
                    context_role=item.get("context_role", "Threat Indicator"),
                    confidence=item.get("confidence", 0.95),
                    supporting_passage=title
                )
                db.add(assoc)

            # Techniques
            for item in techniques_data:
                tid = item.get("technique_id", "T1000")
                existing_tech = await db.execute(select(AttackTechnique).where(AttackTechnique.id == tid))
                tech_record = existing_tech.scalars().first()
                if not tech_record:
                    tech_record = AttackTechnique(
                        id=tid,
                        tactic=item.get("tactic", "Technique"),
                        name=item.get("name", tid)
                    )
                    db.add(tech_record)
                    await db.flush()

                inc_tech = IncidentTechnique(
                    incident_id=incident.id,
                    technique_id=tid,
                    supporting_behavior=item.get("supporting_behavior", "Observed in report"),
                    confidence=item.get("confidence", 0.9),
                    is_confirmed=item.get("is_confirmed", True)
                )
                db.add(inc_tech)

            # Indicators of Attack (IOAs)
            for a in ioas_data:
                ioa_record = IOA(
                    incident_id=incident.id,
                    ioa_type=a.get("ioa_type", "EXECUTION"),
                    pattern_name=a.get("pattern_name", "Attack Pattern"),
                    technique_id=a.get("technique_id"),
                    observed_behavior=a.get("observed_behavior", ""),
                    detection_logic=a.get("detection_logic", ""),
                    evidence_quote=a.get("evidence_quote", ""),
                    confidence=float(a.get("confidence", 0.9))
                )
                db.add(ioa_record)

            # Recommendations
            for r in recommendations_data:
                rec = MitigationRecommendation(
                    incident_id=incident.id,
                    category=r.get("category", "PREVENTIVE"),
                    title=r.get("title", "Mitigation Action"),
                    action_items=r.get("action_items", ""),
                    priority=r.get("priority", "HIGH"),
                    implementation_effort=r.get("implementation_effort", "MEDIUM")
                )
                db.add(rec)

            # Verification Review
            verif_review = VerificationReview(
                incident_id=incident.id,
                status=verification_data.get("status", "APPROVED"),
                review_score=float(verification_data.get("review_score", 0.9)),
                accepted_findings=json.dumps(verification_data.get("verified_facts", [])),
                rejected_findings=json.dumps(verification_data.get("unsupported_claims", [])),
                rejection_reasons=json.dumps(verification_data.get("reasons", "Audit passed."))
            )
            db.add(verif_review)

            # Step 7: Index into RAG Vector Store
            ioa_summary_text = " ".join([f"{a.get('pattern_name')}: {a.get('observed_behavior')}" for a in ioas_data])
            vector_store.add_document(
                doc_id=incident.id,
                title=incident.title,
                content=f"{incident.title}\n{incident.summary}\n{incident.root_cause_analysis}\nIOAs: {ioa_summary_text}",
                source_url=source_url,
                doc_type="investigated_incident",
                incident_id=incident.id
            )

            # Step 8: Intelligence Report & Gmail Notification Agent
            incident_bundle = {
                "title": incident.title,
                "severity": incident.severity,
                "affected_organization": incident.affected_organization,
                "summary": incident.summary,
                "root_cause_analysis": incident.root_cause_analysis,
                "source_url": source_url,
                "iocs": iocs_data,
                "ioas": ioas_data,
                "techniques": techniques_data,
                "recommendations": recommendations_data
            }
            report_result = await ReportAndNotificationAgent.run(incident_bundle, gmail_service)

            # Persist notification
            email_pack = report_result["email_pack"]
            send_res = report_result["send_result"]
            notif = Notification(
                incident_id=incident.id,
                notification_type="INCIDENT_REPORT",
                recipient=email_pack["recipient"],
                subject=email_pack["subject"],
                html_content=email_pack["html"],
                plain_text_content=email_pack["plain"],
                delivery_status=send_res["status"],
                idempotency_key=f"notif-{incident.id}-{int(datetime.datetime.now().timestamp())}",
                error_message=send_res.get("error") or send_res.get("detail"),
                message_id=send_res.get("message_id")
            )
            db.add(notif)

            # Step 9: Final Status
            incident.status = "PUBLISHED" if verification_data.get("status") == "APPROVED" else "NEEDS_REVIEW"
            
            end_time = datetime.datetime.now(datetime.timezone.utc)
            duration = (end_time - start_time).total_seconds()
            run_record.status = "COMPLETED"
            run_record.completed_at = end_time
            run_record.duration_seconds = duration
            run_record.outputs = json.dumps({
                "investigation": investigation_data,
                "iocs_count": len(iocs_data),
                "ioas_count": len(ioas_data),
                "techniques_count": len(techniques_data),
                "verification": verification_data,
                "delivery": send_res
            })
            run_record.decision_summary = f"Completed in {duration:.1f}s. Extracted {len(iocs_data)} IOCs, {len(ioas_data)} IOAs. Verified score {verification_data.get('review_score')}. Notification: {send_res['status']}."

            await db.commit()

            return {
                "incident_id": incident.id,
                "status": incident.status,
                "duration_seconds": duration,
                "verification": verification_data,
                "iocs": iocs_data,
                "ioas": ioas_data,
                "techniques": techniques_data,
                "recommendations": recommendations_data,
                "notification": send_res
            }
