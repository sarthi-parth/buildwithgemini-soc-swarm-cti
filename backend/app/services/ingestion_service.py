import datetime
import hashlib
from typing import List, Dict, Any
from sqlalchemy.future import select

from app.database.session import AsyncSessionLocal
from app.database.models import Source, SourceDocument, Incident
from app.tools.tool_registry import fetch_rss_feed_entries, fetch_article_text, compute_content_hash, normalize_source_url
from app.agents.specialized_agents import ThreatDiscoveryAgent

DEFAULT_SOURCES = [
    {
        "name": "CISA Cybersecurity Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "source_type": "rss"
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "source_type": "rss"
    },
    {
        "name": "BleepingComputer Information Security",
        "url": "https://www.bleepingcomputer.com/feed/",
        "source_type": "rss"
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "source_type": "rss"
    }
]

async def seed_default_sources():
    async with AsyncSessionLocal() as db:
        for s in DEFAULT_SOURCES:
            existing = await db.execute(select(Source).where(Source.url == s["url"]))
            if not existing.scalars().first():
                source = Source(
                    name=s["name"],
                    url=s["url"],
                    source_type=s["source_type"],
                    enabled=True
                )
                db.add(source)
        await db.commit()

async def poll_all_sources(auto_investigate: bool = True) -> Dict[str, Any]:
    """Polls all active feeds, detects new advisories, creates incidents, and optionally auto-investigates."""
    from app.agents.orchestrator import SwarmOrchestrator

    new_docs = 0
    new_incidents = 0
    investigated_ids = []
    newly_created_ids = []

    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Source).where(Source.enabled == True))
        sources = res.scalars().all()

        for source in sources:
            try:
                entries = await fetch_rss_feed_entries(source.url, limit=5)
                source.last_polled_at = datetime.datetime.now(datetime.timezone.utc)
                source.last_error = None

                for item in entries:
                    raw_url = item.get("url", "")
                    if not raw_url:
                        continue
                    canon_url = normalize_source_url(raw_url)
                    chash = compute_content_hash(f"{item.get('title','')}\n{item.get('summary','')}")

                    # Check for duplicate doc
                    doc_check = await db.execute(select(SourceDocument).where(SourceDocument.canonical_url == canon_url))
                    if doc_check.scalars().first():
                        continue

                    # Classify with Threat Discovery Agent
                    disc_res = await ThreatDiscoveryAgent.run(item)
                    if not disc_res.get("is_incident", True):
                        continue

                    # Fetch fuller article text
                    try:
                        extracted = await fetch_article_text(canon_url)
                    except Exception:
                        extracted = item.get("summary", "")

                    doc = SourceDocument(
                        source_id=source.id,
                        title=item.get("title", "Untitled Advisory"),
                        canonical_url=canon_url,
                        content_hash=chash,
                        raw_content=item.get("summary"),
                        extracted_text=extracted,
                        processing_status="DISCOVERED"
                    )
                    db.add(doc)
                    await db.flush()
                    new_docs += 1

                    # Create Incident
                    incident = Incident(
                        primary_source_doc_id=doc.id,
                        title=item.get("title"),
                        summary=disc_res.get("summary") or item.get("summary"),
                        affected_organization=disc_res.get("affected_org"),
                        severity=disc_res.get("severity", "HIGH"),
                        status="DISCOVERED",
                        is_demo=False
                    )
                    db.add(incident)
                    await db.flush()
                    new_incidents += 1
                    newly_created_ids.append(incident.id)

                await db.commit()
            except Exception as e:
                source.last_error = str(e)
                await db.commit()

    # If auto_investigate is requested, trigger swarm on new incidents
    if auto_investigate and newly_created_ids:
        for inc_id in newly_created_ids:
            try:
                print(f"[Ingestion Service] Auto-investigating newly detected report {inc_id}...")
                await SwarmOrchestrator.investigate_incident(inc_id)
                investigated_ids.append(inc_id)
            except Exception as e:
                print(f"[Ingestion Service] Error auto-investigating {inc_id}: {e}")

    return {
        "new_documents": new_docs,
        "new_incidents": new_incidents,
        "auto_investigated_count": len(investigated_ids),
        "incident_ids": newly_created_ids
    }
