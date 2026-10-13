import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database.session import get_db
from app.database.models import (
    Incident, Source, SourceDocument, IOC, IncidentIOC,
    IncidentTechnique, AttackTechnique, MitigationRecommendation,
    VerificationReview, Notification, AgentRun, IOA
)
from app.agents.orchestrator import SwarmOrchestrator
from app.services.ingestion_service import poll_all_sources
from app.services.gmail_service import gmail_service
from app.rag.vector_store import vector_store
from app.config import settings

router = APIRouter()

# -------------------------------------------------------------
# HEALTH & DASHBOARD SUMMARY
# -------------------------------------------------------------
@router.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "gemini_model": settings.GEMINI_MODEL,
        "embedding_model": settings.EMBEDDING_MODEL
    }

@router.get("/dashboard/summary")
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    incidents_total = (await db.execute(select(Incident))).scalars().all()
    iocs_total = (await db.execute(select(IOC))).scalars().all()
    ioas_total = (await db.execute(select(IOA))).scalars().all()
    sources_total = (await db.execute(select(Source))).scalars().all()
    runs_total = (await db.execute(select(AgentRun))).scalars().all()
    notifs_total = (await db.execute(select(Notification))).scalars().all()

    investigated = [i for i in incidents_total if i.status in ("PUBLISHED", "READY_TO_PUBLISH", "NEEDS_REVIEW")]
    high_sev = [i for i in incidents_total if i.severity in ("HIGH", "CRITICAL")]
    unverified = [i for i in incidents_total if i.status == "NEEDS_REVIEW"]

    rag_stats = vector_store.count_stats()

    return {
        "total_incidents_discovered": len(incidents_total),
        "incidents_investigated": len(investigated),
        "total_iocs_extracted": len(iocs_total),
        "total_ioas_extracted": len(ioas_total),
        "high_severity_incidents": len(high_sev),
        "unverified_findings": len(unverified),
        "active_sources": len([s for s in sources_total if s.enabled]),
        "total_agent_runs": len(runs_total),
        "total_notifications": len(notifs_total),
        "knowledge_base_chunks": rag_stats["chunks"],
        "gmail_status": gmail_service.get_status()["mode"]
    }

# -------------------------------------------------------------
# INCIDENTS
# -------------------------------------------------------------
@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Incident).options(
        selectinload(Incident.iocs),
        selectinload(Incident.techniques),
        selectinload(Incident.primary_source_doc)
    ).order_by(Incident.created_at.desc())

    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)

    res = await db.execute(query)
    incidents = res.scalars().all()

    output = []
    for inc in incidents:
        output.append({
            "id": inc.id,
            "title": inc.title,
            "summary": inc.summary,
            "affected_organization": inc.affected_organization,
            "severity": inc.severity,
            "status": inc.status,
            "is_demo": inc.is_demo,
            "confidence_score": inc.confidence_score,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "iocs_count": len(inc.iocs),
            "techniques_count": len(inc.techniques),
            "source_url": inc.primary_source_doc.canonical_url if inc.primary_source_doc else None
        })
    return output

# -------------------------------------------------------------
# DAY-WISE REPORTS ENDPOINT (must precede /incidents/{incident_id})
# -------------------------------------------------------------
@router.get("/incidents/day-wise")
async def get_day_wise_incidents(db: AsyncSession = Depends(get_db)):
    """Groups all discovered and investigated threat intel reports by calendar day."""
    res = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.iocs),
            selectinload(Incident.ioas),
            selectinload(Incident.techniques),
            selectinload(Incident.primary_source_doc)
        )
        .order_by(Incident.created_at.desc())
    )
    incidents = res.scalars().all()

    grouped: Dict[str, Dict[str, Any]] = {}
    for inc in incidents:
        # Determine day string (YYYY-MM-DD)
        dt = inc.created_at or datetime.datetime.now(datetime.timezone.utc)
        day_key = dt.strftime("%Y-%m-%d")
        day_label = dt.strftime("%B %d, %Y")

        if day_key not in grouped:
            grouped[day_key] = {
                "date": day_key,
                "display_label": day_label,
                "total_reports": 0,
                "high_critical_count": 0,
                "total_iocs": 0,
                "total_ioas": 0,
                "reports": []
            }

        grouped[day_key]["total_reports"] += 1
        if inc.severity in ("HIGH", "CRITICAL"):
            grouped[day_key]["high_critical_count"] += 1
        grouped[day_key]["total_iocs"] += len(inc.iocs)
        grouped[day_key]["total_ioas"] += len(inc.ioas)

        grouped[day_key]["reports"].append({
            "id": inc.id,
            "title": inc.title,
            "summary": inc.summary,
            "affected_organization": inc.affected_organization,
            "severity": inc.severity,
            "status": inc.status,
            "is_demo": inc.is_demo,
            "confidence_score": inc.confidence_score,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "iocs_count": len(inc.iocs),
            "ioas_count": len(inc.ioas),
            "techniques_count": len(inc.techniques),
            "source_url": inc.primary_source_doc.canonical_url if inc.primary_source_doc else None
        })

    return list(grouped.values())

@router.get("/incidents/{incident_id}")
async def get_incident_detail(incident_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.primary_source_doc),
            selectinload(Incident.iocs).selectinload(IncidentIOC.ioc),
            selectinload(Incident.ioas),
            selectinload(Incident.techniques).selectinload(IncidentTechnique.technique),
            selectinload(Incident.recommendations),
            selectinload(Incident.timeline_events),
            selectinload(Incident.verification_reviews),
            selectinload(Incident.agent_runs)
        )
        .where(Incident.id == incident_id)
    )
    inc = res.scalars().first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "id": inc.id,
        "title": inc.title,
        "summary": inc.summary,
        "affected_organization": inc.affected_organization,
        "affected_systems": inc.affected_systems,
        "initial_access_vector": inc.initial_access_vector,
        "root_cause_analysis": inc.root_cause_analysis,
        "severity": inc.severity,
        "confidence_score": inc.confidence_score,
        "status": inc.status,
        "is_demo": inc.is_demo,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "source": {
            "title": inc.primary_source_doc.title if inc.primary_source_doc else "Direct Ingestion",
            "url": inc.primary_source_doc.canonical_url if inc.primary_source_doc else "",
            "extracted_text": (inc.primary_source_doc.extracted_text or "")[:1500] if inc.primary_source_doc else ""
        },
        "iocs": [
            {
                "id": assoc.ioc.id,
                "type": assoc.ioc.ioc_type,
                "value": assoc.ioc.normalized_value,
                "defanged": assoc.ioc.defanged_value,
                "context_role": assoc.context_role,
                "threat_status": assoc.ioc.threat_status,
                "confidence": assoc.confidence
            }
            for assoc in inc.iocs
        ],
        "ioas": [
            {
                "id": a.id,
                "type": a.ioa_type,
                "pattern_name": a.pattern_name,
                "technique_id": a.technique_id,
                "observed_behavior": a.observed_behavior,
                "detection_logic": a.detection_logic,
                "evidence_quote": a.evidence_quote,
                "confidence": a.confidence
            }
            for a in inc.ioas
        ],
        "techniques": [
            {
                "id": t.technique_id,
                "name": t.technique.name if t.technique else t.technique_id,
                "tactic": t.technique.tactic if t.technique else "Attack TTP",
                "supporting_behavior": t.supporting_behavior,
                "is_confirmed": t.is_confirmed
            }
            for t in inc.techniques
        ],
        "recommendations": [
            {
                "category": r.category,
                "title": r.title,
                "action_items": r.action_items,
                "priority": r.priority
            }
            for r in inc.recommendations
        ],
        "timeline": [
            {
                "order": ev.event_order,
                "stage": ev.stage,
                "description": ev.description
            }
            for ev in inc.timeline_events
        ],
        "verification_reviews": [
            {
                "status": v.status,
                "score": v.review_score,
                "reasons": v.rejection_reasons,
                "reviewed_at": v.reviewed_at.isoformat() if v.reviewed_at else None
            }
            for v in inc.verification_reviews
        ],
        "agent_runs": [
            {
                "id": ar.id,
                "agent_name": ar.agent_name,
                "status": ar.status,
                "duration_seconds": ar.duration_seconds,
                "decision_summary": ar.decision_summary,
                "started_at": ar.started_at.isoformat() if ar.started_at else None
            }
            for ar in inc.agent_runs
        ]
    }

@router.post("/incidents/{incident_id}/investigate")
async def trigger_investigation(incident_id: str, background_tasks: BackgroundTasks):
    result = await SwarmOrchestrator.investigate_incident(incident_id)
    return result

# -------------------------------------------------------------
# INDICATORS OF ATTACK (IOA) EXPLORER
# -------------------------------------------------------------
@router.get("/ioas")
async def list_ioas(
    ioa_type: Optional[str] = None,
    query: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(IOA).order_by(IOA.created_at.desc())
    if ioa_type:
        stmt = stmt.where(IOA.ioa_type == ioa_type)
    if query:
        stmt = stmt.where(
            (IOA.pattern_name.contains(query.strip())) |
            (IOA.observed_behavior.contains(query.strip())) |
            (IOA.technique_id.contains(query.strip()))
        )

    res = await db.execute(stmt)
    ioas = res.scalars().all()
    return [
        {
            "id": a.id,
            "incident_id": a.incident_id,
            "ioa_type": a.ioa_type,
            "pattern_name": a.pattern_name,
            "technique_id": a.technique_id,
            "observed_behavior": a.observed_behavior,
            "detection_logic": a.detection_logic,
            "evidence_quote": a.evidence_quote,
            "confidence": a.confidence,
            "created_at": a.created_at.isoformat() if a.created_at else None
        }
        for a in ioas
    ]

# -------------------------------------------------------------
# UNIFIED GLOBAL SEARCH (REPORTS, IOCS, IOAS, HISTORICAL RAG)
# -------------------------------------------------------------
@router.get("/search")
async def unified_search(
    q: str = Query(..., min_length=1, description="Search query"),
    type: str = Query("all", description="Filter: all, reports, iocs, ioas"),
    db: AsyncSession = Depends(get_db)
):
    q_clean = q.strip().lower()
    results = {
        "query": q,
        "reports": [],
        "iocs": [],
        "ioas": [],
        "historical_rag": []
    }

    # 1. Search Threat Reports / Incidents
    if type in ("all", "reports"):
        inc_res = await db.execute(
            select(Incident)
            .options(selectinload(Incident.iocs), selectinload(Incident.ioas))
            .where(
                (Incident.title.ilike(f"%{q_clean}%")) |
                (Incident.summary.ilike(f"%{q_clean}%")) |
                (Incident.affected_organization.ilike(f"%{q_clean}%")) |
                (Incident.root_cause_analysis.ilike(f"%{q_clean}%"))
            )
            .limit(20)
        )
        for inc in inc_res.scalars().all():
            results["reports"].append({
                "id": inc.id,
                "title": inc.title,
                "summary": inc.summary,
                "affected_organization": inc.affected_organization,
                "severity": inc.severity,
                "status": inc.status,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
                "iocs_count": len(inc.iocs),
                "ioas_count": len(inc.ioas)
            })

    # 2. Search IOCs
    if type in ("all", "iocs"):
        ioc_res = await db.execute(
            select(IOC)
            .where(
                (IOC.normalized_value.ilike(f"%{q_clean}%")) |
                (IOC.defanged_value.ilike(f"%{q_clean}%")) |
                (IOC.ioc_type.ilike(f"%{q_clean}%"))
            )
            .limit(30)
        )
        for i in ioc_res.scalars().all():
            results["iocs"].append({
                "id": i.id,
                "type": i.ioc_type,
                "value": i.normalized_value,
                "defanged": i.defanged_value,
                "threat_status": i.threat_status,
                "first_seen": i.first_seen.isoformat() if i.first_seen else None
            })

    # 3. Search IOAs (Indicators of Attack)
    if type in ("all", "ioas"):
        ioa_res = await db.execute(
            select(IOA)
            .where(
                (IOA.pattern_name.ilike(f"%{q_clean}%")) |
                (IOA.observed_behavior.ilike(f"%{q_clean}%")) |
                (IOA.technique_id.ilike(f"%{q_clean}%")) |
                (IOA.detection_logic.ilike(f"%{q_clean}%"))
            )
            .limit(30)
        )
        for a in ioa_res.scalars().all():
            results["ioas"].append({
                "id": a.id,
                "incident_id": a.incident_id,
                "type": a.ioa_type,
                "pattern_name": a.pattern_name,
                "technique_id": a.technique_id,
                "observed_behavior": a.observed_behavior,
                "detection_logic": a.detection_logic
            })

    # 4. Semantic Vector Store Search for Past Threat Knowledge
    if type in ("all", "reports"):
        try:
            rag_chunks = vector_store.similarity_search(q, top_k=4)
            results["historical_rag"] = rag_chunks
        except Exception as e:
            print(f"[Search API] RAG error: {e}")

    total_hits = (
        len(results["reports"]) +
        len(results["iocs"]) +
        len(results["ioas"]) +
        len(results["historical_rag"])
    )
    results["total_matches"] = total_hits
    return results

# -------------------------------------------------------------
# SCHEDULED SWEEP TRIGGER
# -------------------------------------------------------------
@router.post("/scheduler/sweep")
async def trigger_scheduled_sweep():
    """Immediately triggers a sweep across all CTI platforms and auto-investigates new disclosures."""
    result = await poll_all_sources(auto_investigate=True)
    return result

# -------------------------------------------------------------
# SOURCES & INGESTION
# -------------------------------------------------------------
@router.get("/sources")
async def list_sources(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Source).order_by(Source.created_at.asc()))
    sources = res.scalars().all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "source_type": s.source_type,
            "url": s.url,
            "enabled": s.enabled,
            "last_polled_at": s.last_polled_at.isoformat() if s.last_polled_at else None,
            "last_error": s.last_error
        }
        for s in sources
    ]

@router.post("/sources/poll")
async def run_source_polling():
    result = await poll_all_sources()
    return result

# -------------------------------------------------------------
# IOC EXPLORER
# -------------------------------------------------------------
@router.get("/iocs")
async def list_iocs(
    ioc_type: Optional[str] = None,
    query: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(IOC).order_by(IOC.first_seen.desc())
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    if query:
        stmt = stmt.where(IOC.normalized_value.contains(query.strip()))

    res = await db.execute(stmt)
    iocs = res.scalars().all()
    return [
        {
            "id": i.id,
            "type": i.ioc_type,
            "value": i.normalized_value,
            "defanged": i.defanged_value,
            "threat_status": i.threat_status,
            "enrichment_status": i.enrichment_status,
            "first_seen": i.first_seen.isoformat() if i.first_seen else None
        }
        for i in iocs
    ]

# -------------------------------------------------------------
# AGENT RUNS
# -------------------------------------------------------------
@router.get("/agents/runs")
async def list_agent_runs(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(AgentRun).order_by(AgentRun.started_at.desc()).limit(50))
    runs = res.scalars().all()
    return [
        {
            "id": r.id,
            "agent_name": r.agent_name,
            "status": r.status,
            "incident_id": r.incident_id,
            "decision_summary": r.decision_summary,
            "duration_seconds": r.duration_seconds,
            "started_at": r.started_at.isoformat() if r.started_at else None
        }
        for r in runs
    ]

# -------------------------------------------------------------
# KNOWLEDGE BASE & RAG
# -------------------------------------------------------------
@router.get("/knowledge/search")
async def search_knowledge(q: str = Query(..., min_length=2)):
    chunks = vector_store.similarity_search(q, top_k=5)
    return {
        "query": q,
        "results": chunks
    }

class DocumentUpload(BaseModel):
    title: str
    content: str
    source_url: Optional[str] = ""

@router.post("/knowledge/documents")
async def upload_document(doc: DocumentUpload):
    import uuid
    doc_id = str(uuid.uuid4())
    chunks_count = vector_store.add_document(
        doc_id=doc_id,
        title=doc.title,
        content=doc.content,
        source_url=doc.source_url or "",
        doc_type="analyst_upload"
    )
    return {"id": doc_id, "chunks_indexed": chunks_count, "title": doc.title}

# -------------------------------------------------------------
# NOTIFICATIONS & GMAIL
# -------------------------------------------------------------
@router.get("/notifications")
async def list_notifications(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Notification).order_by(Notification.created_at.desc()).limit(30))
    notifs = res.scalars().all()
    return [
        {
            "id": n.id,
            "incident_id": n.incident_id,
            "notification_type": n.notification_type,
            "recipient": n.recipient,
            "subject": n.subject,
            "delivery_status": n.delivery_status,
            "html_preview": n.html_content,
            "plain_preview": n.plain_text_content,
            "created_at": n.created_at.isoformat() if n.created_at else None,
            "error_message": n.error_message
        }
        for n in notifs
    ]

class TestEmailRequest(BaseModel):
    recipient: Optional[str] = None

@router.post("/notifications/test")
async def send_test_email(req: TestEmailRequest, db: AsyncSession = Depends(get_db)):
    recipient = req.recipient or settings.GMAIL_DEFAULT_RECIPIENT
    test_bundle = {
        "title": "SOC Swarm CTI: Live Notification Test",
        "severity": "MEDIUM",
        "affected_organization": "SOC Verification Testbed",
        "summary": "This is an automated verification message dispatched from SOC Swarm CTI multi-agent threat platform.",
        "root_cause_analysis": "Scheduled diagnostic test initiated by security analyst.",
        "iocs": [
            {"ioc_type": "ipv4", "defanged_value": "198.51.100[.]23", "context_role": "Synthetic Test Host"}
        ],
        "techniques": [
            {"technique_id": "T1082", "name": "System Information Discovery", "supporting_behavior": "Diagnostic telemetry ping"}
        ],
        "recommendations": [
            {"category": "PREVENTIVE", "title": "Maintain Monitoring", "action_items": "Verify email alert delivery regularly."}
        ],
        "source_url": "https://localhost:8000"
    }

    email_pack = gmail_service.create_incident_email(test_bundle, recipient=recipient)
    send_res = await gmail_service.send_email(
        recipient=email_pack["recipient"],
        subject=email_pack["subject"],
        html_content=email_pack["html"],
        plain_content=email_pack["plain"]
    )

    notif = Notification(
        notification_type="TEST",
        recipient=recipient,
        subject=email_pack["subject"],
        html_content=email_pack["html"],
        plain_text_content=email_pack["plain"],
        delivery_status=send_res["status"],
        idempotency_key=f"test-{int(datetime.datetime.now().timestamp())}",
        error_message=send_res.get("error") or send_res.get("detail"),
        message_id=send_res.get("message_id")
    )
    db.add(notif)
    await db.commit()

    return {
        "send_result": send_res,
        "notification_id": notif.id,
        "preview": email_pack["plain"]
    }

@router.get("/settings/integrations")
async def get_settings():
    return {
        "gemini_model": settings.GEMINI_MODEL,
        "embedding_model": settings.EMBEDDING_MODEL,
        "google_cloud_project": settings.GOOGLE_CLOUD_PROJECT,
        "gmail": gmail_service.get_status(),
        "polling_interval_minutes": settings.POLLING_INTERVAL_MINUTES,
        "max_parallel_investigations": settings.MAX_PARALLEL_INVESTIGATIONS
    }

# -------------------------------------------------------------
# DAILY NEWSLETTERS & HISTORICAL ARCHIVE
# -------------------------------------------------------------
@router.get("/newsletters/dates")
async def get_newsletter_dates():
    import sqlite3
    from app.services.newsletter_service import list_all_newsletter_dates
    db_file = settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "")
    con = sqlite3.connect(db_file)
    dates = list_all_newsletter_dates(con)
    con.close()
    return dates

@router.get("/newsletters/{report_date}")
async def get_newsletter_by_date(report_date: str):
    import sqlite3
    from app.services.newsletter_service import get_daily_newsletter, generate_daily_newsletter
    db_file = settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "")
    con = sqlite3.connect(db_file)
    nl = get_daily_newsletter(con, report_date)
    if not nl:
        nl = generate_daily_newsletter(con, target_date=report_date)
    con.close()
    if not nl:
        raise HTTPException(status_code=404, detail=f"No newsletter found for date {report_date}")
    return nl

@router.post("/newsletters/generate")
async def generate_newsletter_endpoint(target_date: Optional[str] = None):
    import sqlite3
    from app.services.newsletter_service import generate_daily_newsletter
    db_file = settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "")
    con = sqlite3.connect(db_file)
    nl = generate_daily_newsletter(con, target_date=target_date)
    con.close()
    return nl
