import streamlit as st
import sqlite3
import pandas as pd
import datetime
import hashlib
import json
import os
import sys
import re
import uuid
import feedparser
import urllib.request
from typing import List, Dict, Any, Optional

# Add backend directory to sys.path for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app.services.live_fetcher import PLATFORMS_CONFIG, fetch_live_items_from_platform, ingest_live_platform_items
    from app.services.newsletter_service import (
        init_newsletter_schema, generate_daily_newsletter, 
        list_all_newsletter_dates, get_daily_newsletter
    )
    from app.services.rule_generator import generate_siem_rules_for_incident
    from app.services.stix_service import generate_stix_bundle
    from app.services.asset_matcher import match_incident_to_assets, DEFAULT_ORG_STACK
    from app.services.webhook_service import build_slack_block_kit_payload, send_webhook_alert
except ImportError:
    from backend.app.services.live_fetcher import PLATFORMS_CONFIG, fetch_live_items_from_platform, ingest_live_platform_items
    from backend.app.services.newsletter_service import (
        init_newsletter_schema, generate_daily_newsletter, 
        list_all_newsletter_dates, get_daily_newsletter
    )
    from backend.app.services.rule_generator import generate_siem_rules_for_incident
    from backend.app.services.stix_service import generate_stix_bundle
    from backend.app.services.asset_matcher import match_incident_to_assets, DEFAULT_ORG_STACK
    from backend.app.services.webhook_service import build_slack_block_kit_payload, send_webhook_alert

# -------------------------------------------------------------
# PAGE CONFIGURATION & THEME
# -------------------------------------------------------------
st.set_page_config(
    page_title="SOC Swarm CTI - Daily Threat Intel Briefings & Newsletters",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = os.path.join(os.path.dirname(__file__), "backend", "cti_platform.db")
if not os.path.exists(DB_PATH):
    DB_PATH = os.path.join(os.path.dirname(__file__), "cti_platform.db")

# -------------------------------------------------------------
# DATABASE CONNECTION & HELPERS
# -------------------------------------------------------------
def get_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    cur = con.cursor()
    cols = [c[1] for c in cur.execute("PRAGMA table_info(incidents)").fetchall()]
    if 'category' not in cols:
        cur.execute("ALTER TABLE incidents ADD COLUMN category TEXT DEFAULT 'General Cybersecurity'")
    if 'is_updated' not in cols:
        cur.execute("ALTER TABLE incidents ADD COLUMN is_updated BOOLEAN DEFAULT 0")
    if 'publication_date' not in cols:
        cur.execute("ALTER TABLE incidents ADD COLUMN publication_date TEXT")
        cur.execute("UPDATE incidents SET publication_date = SUBSTR(created_at, 1, 10) WHERE publication_date IS NULL")
        
    cur.execute("""
    CREATE TABLE IF NOT EXISTS report_versions (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        version_number INTEGER NOT NULL,
        content_hash TEXT,
        title TEXT,
        summary TEXT,
        change_notes TEXT,
        diff_summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(incident_id) REFERENCES incidents(id)
    )
    """)
    con.commit()
    init_newsletter_schema(con)
    con.close()

init_db()

# -------------------------------------------------------------
# GEMINI CLIENT INITIALIZATION
# -------------------------------------------------------------
@st.cache_resource
def get_gemini_client():
    try:
        from google import genai
        project = os.environ.get("GOOGLE_CLOUD_PROJECT", "qwiklabs-gcp-03-fd05546dff54")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
        client = genai.Client(vertexai=True, project=project, location=location)
        return client
    except Exception as e:
        return None

# -------------------------------------------------------------
# SIDEBAR
# -------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ SOC SWARM CTI")
    st.caption("Autonomous Cyber Threat Intelligence & Daily Briefing Agent")
    st.divider()
    
    menu = st.radio(
        "Navigation",
        [
            "📰 Daily Threat Intel Digest & Newsletters",
            "📊 Executive Dashboard",
            "🛡️ SIEM & EDR Rule Synthesizer",
            "🎯 Tech Stack Watchdog & Runbooks",
            "📦 STIX 2.1 & TAXII Exporter",
            "💬 ChatOps & Slack Dispatcher",
            "🌐 Live Multi-Platform Fetcher",
            "📋 Threat Intelligence Feed",
            "🔍 IOC Explorer",
            "⚔️ IOA Explorer",
            "💬 Threat Intelligence Chat",
            "⚙️ Notifications & Settings"
        ],
        index=0 # default to daily newsletter
    )
    st.divider()
    
    st.markdown("#### ⚡ Autonomous Actions")
    if st.button("🚀 Publish Today's Newsletter", type="primary", use_container_width=True):
        with st.spinner("Crawling multi-source feeds, deduplicating, and synthesizing newsletter..."):
            con = sqlite3.connect(DB_PATH)
            total_new, total_upd = 0, 0
            for p in PLATFORMS_CONFIG[:8]:
                items = fetch_live_items_from_platform(p["id"], limit=3)
                n, u = ingest_live_platform_items(con, items)
                total_new += n
                total_upd += u
            client = get_gemini_client()
            nl = generate_daily_newsletter(con, target_date=datetime.date.today().isoformat(), gemini_client=client)
            con.close()
            st.success(f"Published! {nl['total_unique_reports']} unique reports synthesized.")
            st.rerun()
            
    st.markdown("---")
    st.markdown("**Platform Status:**")
    st.markdown("🟢 **Model**: `gemini-3.8-flash`")
    st.markdown("🟢 **Sources Configured**: `14 Active Feeds`")
    st.markdown("🟢 **Store**: `SQLite Local Engine`")
    st.markdown("🟡 **Gmail**: `OAuth Preview Mode`")

# -------------------------------------------------------------
# TAB 1: DAILY THREAT INTEL DIGEST & NEWSLETTERS
# -------------------------------------------------------------
if menu == "📰 Daily Threat Intel Digest & Newsletters":
    st.title("📰 Daily Threat Intelligence Digest & Published Newsletters")
    st.caption("Daily published briefings aggregating multi-source disclosures with deduplication and historical archive navigation")
    
    con = get_db()
    available_dates = list_all_newsletter_dates(con)
    today_str = datetime.date.today().isoformat()
    
    # Historical Date Selector
    col_d1, col_d2, col_d3 = st.columns([2, 2, 2])
    with col_d1:
        date_options = [d["date"] for d in available_dates] if available_dates else [today_str]
        if today_str not in date_options:
            date_options.insert(0, today_str)
        selected_date_str = st.selectbox(
            "📅 Select Threat Intelligence Publication Date:",
            options=date_options,
            index=0
        )
    with col_d2:
        st.markdown(f"**Available Historical Editions:** `{len(available_dates)} Dates Recorded`")
        st.caption("Select any past date above to review historical threat reports and newsletters.")
    with col_d3:
        if st.button("🔄 Refresh / Generate for Selected Date"):
            with st.spinner(f"Synthesizing newsletter for {selected_date_str}..."):
                client = get_gemini_client()
                nl_res = generate_daily_newsletter(con, target_date=selected_date_str, gemini_client=client)
                st.success(f"Briefing updated for {selected_date_str}!")
                st.rerun()
                
    st.divider()
    
    # Fetch newsletter for selected date
    newsletter = get_daily_newsletter(con, selected_date_str)
    if not newsletter:
        client = get_gemini_client()
        newsletter = generate_daily_newsletter(con, target_date=selected_date_str, gemini_client=client)
        
    # Render Executive Newsletter Card
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Unique Threat Reports", newsletter.get("total_unique_reports", 0))
    m2.metric("High & Critical Priority", newsletter.get("high_critical_count", 0))
    m3.metric("Defanged Safe IOCs", newsletter.get("total_iocs_count", 0))
    m4.metric("Behavioral IOAs", newsletter.get("total_ioas_count", 0))
    m5.metric("Sources Scanned", newsletter.get("total_sources_scanned", 8))
    
    # Download button for the briefing
    nl_content = newsletter.get("markdown_content", "")
    st.download_button(
        label="📥 Download Daily Threat Digest (Markdown)",
        data=nl_content.encode("utf-8"),
        file_name=f"threat_intel_newsletter_{selected_date_str}.md",
        mime="text/markdown"
    )
    
    st.markdown("---")
    
    # Newsletter Markdown Display
    tab_nl, tab_reports = st.tabs(["📑 Published Executive Newsletter", "📋 Filterable Unique Reports of the Day"])
    
    with tab_nl:
        st.markdown(nl_content)
        
    with tab_reports:
        st.subheader(f"Unique Threat Disclosures Discovered on {selected_date_str}")
        st.caption("Each incident has been cross-source deduplicated and normalized.")
        
        cur = con.cursor()
        incidents = cur.execute("""
            SELECT i.id, i.title, i.summary, i.category, i.severity, i.status, i.is_updated, 
                   i.affected_organization, i.initial_access_vector, i.root_cause_analysis, 
                   i.created_at, s.canonical_url, s.source_id
            FROM incidents i
            LEFT JOIN source_documents s ON i.primary_source_doc_id = s.id
            WHERE i.publication_date = ? OR SUBSTR(i.created_at, 1, 10) = ?
            ORDER BY CASE i.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END
        """, (selected_date_str, selected_date_str)).fetchall()
        
        if incidents:
            for inc in incidents:
                badge = "🔔 UPDATED (v2)" if inc["is_updated"] == 1 else "🆕 NEW"
                sev_color = "red" if inc["severity"] == "CRITICAL" else ("orange" if inc["severity"] == "HIGH" else "blue")
                
                with st.expander(f"[{inc['category']}] :{sev_color}[{inc['severity']}] {inc['title']} — {badge}"):
                    st.markdown(f"**Target Entity:** {inc['affected_organization'] or 'Undisclosed'}")
                    st.markdown(f"**Original Source:** [{inc['canonical_url'] or 'Direct Ingestion'}]({inc['canonical_url'] or '#'})")
                    st.markdown(f"**Executive Brief:** {inc['summary']}")
                    
                    c_a, c_b = st.columns(2)
                    with c_a:
                        st.info(f"**Initial Access:** {inc['initial_access_vector'] or 'Under Investigation'}")
                    with c_b:
                        st.warning(f"**Root Cause:** {inc['root_cause_analysis'] or 'Telemetry Under Analysis'}")
                        
                    # Extracted IOCs
                    iocs = cur.execute("""
                        SELECT c.ioc_type, c.defanged_value, c.normalized_value, ic.context_role, c.threat_status
                        FROM incident_iocs ic
                        JOIN iocs c ON ic.ioc_id = c.id
                        WHERE ic.incident_id = ?
                    """, (inc["id"],)).fetchall()
                    if iocs:
                        st.markdown("##### 🎯 Defanged Indicators of Compromise (IOC)")
                        st.dataframe(pd.DataFrame(iocs, columns=["Type", "Defanged Indicator", "Raw Normalized", "Context Role", "Status"]), use_container_width=True, hide_index=True)
                        
                    # Extracted IOAs
                    ioas = cur.execute("""
                        SELECT ioa_type, pattern_name, technique_id, observed_behavior, detection_logic
                        FROM indicators_of_attack
                        WHERE incident_id = ?
                    """, (inc["id"],)).fetchall()
                    if ioas:
                        st.markdown("##### ⚔️ Behavioral Indicators of Attack (IOA)")
                        st.dataframe(pd.DataFrame(ioas, columns=["Type", "Pattern Name", "MITRE Technique", "Observed Behavior", "Detection Logic"]), use_container_width=True, hide_index=True)
        else:
            st.info(f"No specific reports recorded for {selected_date_str}. Click 'Refresh / Generate' above to crawl feeds for this date.")
            
    con.close()

# -------------------------------------------------------------
# TAB 2: EXECUTIVE DASHBOARD
# -------------------------------------------------------------
elif menu == "📊 Executive Dashboard":
    st.title("Cyber Threat Intelligence Executive Dashboard")
    st.caption("Continuous Discovery, IOA/IOC Extraction, and Autonomous Telemetry Monitoring")
    
    con = get_db()
    cur = con.cursor()
    
    total_incidents = cur.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    updated_incidents = cur.execute("SELECT COUNT(*) FROM incidents WHERE is_updated = 1").fetchone()[0]
    ai_sec_count = cur.execute("SELECT COUNT(*) FROM incidents WHERE category = 'AI Security'").fetchone()[0]
    cyber_sec_count = cur.execute("SELECT COUNT(*) FROM incidents WHERE category = 'General Cybersecurity' OR category IS NULL").fetchone()[0]
    total_iocs = cur.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    total_ioas = cur.execute("SELECT COUNT(*) FROM indicators_of_attack").fetchone()[0]
    total_notifs = cur.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]
    
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Incidents", total_incidents, delta=f"{total_incidents} monitored")
    col2.metric("Updated Reports", updated_incidents, delta="Tracked & Versioned")
    col3.metric("Defanged IOCs", total_iocs, delta="Defensive Indicators")
    col4.metric("Extracted IOAs", total_ioas, delta="Behavioral Patterns")
    col5.metric("Gmail Alerts", total_notifs, delta="Notification Center")
    
    st.divider()
    
    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.subheader("Category Breakdown")
        cat_df = pd.DataFrame({
            "Category": ["General Cybersecurity", "AI Security"],
            "Incident Count": [cyber_sec_count, ai_sec_count]
        })
        st.bar_chart(cat_df.set_index("Category"))
        
    with col_right:
        st.subheader("Severity Distribution")
        sev_counts = cur.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity").fetchall()
        sev_df = pd.DataFrame(sev_counts, columns=["Severity", "Count"])
        st.dataframe(sev_df, use_container_width=True, hide_index=True)
        
    st.subheader("Recent Threat Disclosures & High-Severity Advisories")
    recent = cur.execute("""
        SELECT i.id, i.title, i.category, i.severity, i.status, i.is_updated, i.publication_date,
               (SELECT COUNT(*) FROM incident_iocs WHERE incident_id = i.id) as ioc_count,
               (SELECT COUNT(*) FROM indicators_of_attack WHERE incident_id = i.id) as ioa_count
        FROM incidents i
        ORDER BY i.created_at DESC
        LIMIT 10
    """).fetchall()
    
    if recent:
        df_recent = pd.DataFrame(recent, columns=[
            "ID", "Title", "Category", "Severity", "Status", "Updated", "Date", "IOCs", "IOAs"
        ])
        df_recent["Updated"] = df_recent["Updated"].apply(lambda x: "🔔 UPDATED (v2)" if x == 1 else "🆕 NEW")
        st.dataframe(df_recent[["Title", "Category", "Severity", "Updated", "Date", "IOCs", "IOAs"]], use_container_width=True, hide_index=True)
    con.close()

# -------------------------------------------------------------
# TAB 3: LIVE MULTI-PLATFORM FETCHER (10 CATEGORIES)
# -------------------------------------------------------------
elif menu == "🌐 Live Multi-Platform Fetcher":
    st.title("🌐 Live Multi-Platform Threat Intelligence Fetcher")
    st.caption("Comprehensive ingestion across 10 industry categories: Government KEVs, Botnet Trackers, Ransomware Syndicates, Research Blogs & AI Security")
    
    sections = sorted(list(set(p.get("section", "Other") for p in PLATFORMS_CONFIG)))
    selected_section = st.selectbox("Filter Platform by Category Section:", ["All Sections"] + sections)
    
    filtered_platforms = PLATFORMS_CONFIG if selected_section == "All Sections" else [p for p in PLATFORMS_CONFIG if p.get("section") == selected_section]
    
    col_ctrl1, col_ctrl2 = st.columns([3, 1])
    with col_ctrl1:
        selected_platforms = st.multiselect(
            "Select Platforms to Query Live:",
            options=[p["id"] for p in filtered_platforms],
            default=[p["id"] for p in filtered_platforms],
            format_func=lambda pid: next((f"{p['name']} [{p.get('section', '')}]" for p in PLATFORMS_CONFIG if p["id"] == pid), pid)
        )
    with col_ctrl2:
        fetch_limit = st.slider("Items Per Platform", min_value=1, max_value=10, value=3)
        
    if st.button("⚡ Execute Live Multi-Platform Ingestion Now", type="primary", use_container_width=True):
        if not selected_platforms:
            st.warning("Please select at least one threat intelligence platform to fetch from.")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            con = sqlite3.connect(DB_PATH)
            total_new, total_upd = 0, 0
            live_items_collected = []
            
            for idx, pid in enumerate(selected_platforms):
                plat_cfg = next((p for p in PLATFORMS_CONFIG if p["id"] == pid), None)
                pname = plat_cfg["name"] if plat_cfg else pid
                status_text.markdown(f"📡 *Querying {pname}...*")
                
                items = fetch_live_items_from_platform(pid, limit=fetch_limit)
                n, u = ingest_live_platform_items(con, items)
                total_new += n
                total_upd += u
                live_items_collected.extend(items)
                
                progress_bar.progress((idx + 1) / len(selected_platforms))
                
            con.close()
            status_text.empty()
            st.success(f"✅ Ingestion Complete! Successfully ingested {total_new} unique new incidents and detected {total_upd} updates across {len(selected_platforms)} platforms.")
            
            if live_items_collected:
                st.subheader(f"Captured Live Telemetry ({len(live_items_collected)} records)")
                df_live = pd.DataFrame([
                    {
                        "Platform": it["platform_name"],
                        "Category": it["category"],
                        "Severity": it["severity"],
                        "Title": it["title"],
                        "IOCs": len(it.get("iocs", [])),
                        "IOAs": len(it.get("ioas", [])),
                        "Date": it.get("publication_date")
                    }
                    for it in live_items_collected
                ])
                st.dataframe(df_live, use_container_width=True, hide_index=True)
                
    st.divider()
    
    st.subheader("Platform Directory & Live Telemetry Profiles")
    for p in filtered_platforms:
        with st.expander(f"🟢 {p['name']} — [{p.get('section', '')}] ({p['type']})"):
            st.markdown(f"**Endpoint / Source URL:** [{p['url']}]({p['url']})")
            st.markdown(f"**Section:** `{p.get('section', '')}` | **Category:** `{p['category']}` | **Focus:** `{p['type']}`")
            
            col_b1, col_b2 = st.columns([1, 4])
            with col_b1:
                if st.button(f"Fetch Live from {p['name']}", key=f"fetch_{p['id']}"):
                    with st.spinner(f"Fetching from {p['name']}..."):
                        con = sqlite3.connect(DB_PATH)
                        items = fetch_live_items_from_platform(p["id"], limit=5)
                        n, u = ingest_live_platform_items(con, items)
                        con.close()
                        st.success(f"Fetched {len(items)} items from {p['name']} ({n} unique new, {u} updated)!")
                        st.rerun()

# -------------------------------------------------------------
# TAB 4: THREAT INTELLIGENCE FEED
# -------------------------------------------------------------
elif menu == "📋 Threat Intelligence Feed":
    st.title("Threat Intelligence Feed & Incident Details")
    st.caption("Detailed incident triage with multi-version change detection, IOCs, and IOAs")
    
    con = get_db()
    cur = con.cursor()
    
    col_s1, col_s2, col_s3 = st.columns([2, 1, 1])
    with col_s1:
        search_kw = st.text_input("Search reports (title, summary, target)", "")
    with col_s2:
        cat_filter = st.selectbox("Category", ["All", "General Cybersecurity", "AI Security"])
    with col_s3:
        sev_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        
    query = """
        SELECT i.id, i.title, i.summary, i.category, i.severity, i.status, i.is_updated, 
               i.affected_organization, i.initial_access_vector, i.root_cause_analysis, 
               i.publication_date, i.created_at, i.updated_at, s.canonical_url
        FROM incidents i
        LEFT JOIN source_documents s ON i.primary_source_doc_id = s.id
        WHERE 1=1
    """
    params = []
    if search_kw:
        query += " AND (i.title LIKE ? OR i.summary LIKE ? OR i.affected_organization LIKE ?)"
        like_kw = f"%{search_kw}%"
        params.extend([like_kw, like_kw, like_kw])
    if cat_filter != "All":
        query += " AND i.category = ?"
        params.append(cat_filter)
    if sev_filter != "All":
        query += " AND i.severity = ?"
        params.append(sev_filter)
        
    query += " ORDER BY i.created_at DESC"
    incidents = cur.execute(query, params).fetchall()
    
    st.markdown(f"**Showing {len(incidents)} matched incidents:**")
    
    for inc in incidents:
        badge = "🔔 UPDATED (v2)" if inc["is_updated"] == 1 else "🆕 NEW"
        sev_color = "red" if inc["severity"] == "CRITICAL" else ("orange" if inc["severity"] == "HIGH" else "blue")
        
        with st.expander(f"[{inc['category']}] :{sev_color}[{inc['severity']}] {inc['title']} — {badge}"):
            st.markdown(f"**Target Organization:** {inc['affected_organization'] or 'Undisclosed'}")
            st.markdown(f"**Date:** `{inc['publication_date'] or inc['created_at'][:10]}` | **Source URL:** [{inc['canonical_url'] or 'Internal'}]({inc['canonical_url'] or '#'})")
            st.markdown(f"**Executive Summary:** {inc['summary']}")
            
            c_a, c_b = st.columns(2)
            with c_a:
                st.info(f"**Initial Access Vector:**\n{inc['initial_access_vector'] or 'Under Investigation'}")
            with c_b:
                st.warning(f"**Root Cause Analysis:**\n{inc['root_cause_analysis'] or 'Awaiting further telemetry'}")
                
            # Version History & Updates (Mandatory Feature 7)
            versions = cur.execute("""
                SELECT version_number, content_hash, title, summary, change_notes, diff_summary, created_at
                FROM report_versions
                WHERE incident_id = ?
                ORDER BY version_number ASC
            """, (inc["id"],)).fetchall()
            
            if versions:
                st.markdown("#### 📜 Incident Version History & Content Diff")
                v_tabs = st.tabs([f"Version {v['version_number']}" for v in versions])
                for idx, v in enumerate(versions):
                    with v_tabs[idx]:
                        st.markdown(f"**Recorded Hash:** `{v['content_hash']}` | **Timestamp:** {v['created_at']}")
                        st.markdown(f"**Change Notes:** {v['change_notes']}")
                        if v['diff_summary']:
                            st.code(v['diff_summary'], language="diff")
                            
            # IOCs Table
            iocs = cur.execute("""
                SELECT c.ioc_type, c.defanged_value, c.normalized_value, ic.context_role, c.threat_status
                FROM incident_iocs ic
                JOIN iocs c ON ic.ioc_id = c.id
                WHERE ic.incident_id = ?
            """, (inc["id"],)).fetchall()
            
            if iocs:
                st.markdown("#### 🎯 Extracted Indicators of Compromise (IOC)")
                st.dataframe(pd.DataFrame(iocs, columns=["Type", "Defanged Safe Value", "Raw Normalized", "Context Role", "Threat Status"]), use_container_width=True, hide_index=True)
                
            # IOAs Table
            ioas = cur.execute("""
                SELECT ioa_type, pattern_name, technique_id, observed_behavior, detection_logic, confidence
                FROM indicators_of_attack
                WHERE incident_id = ?
            """, (inc["id"],)).fetchall()
            
            if ioas:
                st.markdown("#### ⚔️ Indicators of Attack (IOA) & Behavioral Patterns")
                st.dataframe(pd.DataFrame(ioas, columns=["Type", "Pattern Name", "MITRE Technique", "Observed Behavior", "Detection Logic", "Confidence"]), use_container_width=True, hide_index=True)

    con.close()

# -------------------------------------------------------------
# TAB 5: IOC EXPLORER
# -------------------------------------------------------------
elif menu == "🔍 IOC Explorer":
    st.title("Indicators of Compromise (IOC) Explorer")
    st.caption("Searchable, normalized threat indicator repository with deterministic defanging")
    
    con = get_db()
    cur = con.cursor()
    
    col_t1, col_t2 = st.columns([3, 1])
    with col_t1:
        ioc_search = st.text_input("Filter indicators (IP, domain, hash, CVE)", "")
    with col_t2:
        type_filter = st.selectbox("Indicator Type", ["All", "ipv4", "ipv6", "domain", "url", "sha256", "md5", "cve", "email"])
        
    query = "SELECT id, ioc_type, defanged_value, normalized_value, threat_status, first_seen FROM iocs WHERE 1=1"
    params = []
    if ioc_search:
        query += " AND (normalized_value LIKE ? OR defanged_value LIKE ?)"
        params.extend([f"%{ioc_search}%", f"%{ioc_search}%"])
    if type_filter != "All":
        query += " AND ioc_type = ?"
        params.append(type_filter)
        
    query += " ORDER BY first_seen DESC"
    results = cur.execute(query, params).fetchall()
    
    if results:
        df_ioc = pd.DataFrame(results, columns=["ID", "Type", "Defanged Value", "Raw Normalized", "Threat Status", "First Seen"])
        st.dataframe(df_ioc[["Type", "Defanged Value", "Raw Normalized", "Threat Status", "First Seen"]], use_container_width=True, hide_index=True)
        
        csv_data = df_ioc.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export IOCs (CSV)",
            data=csv_data,
            file_name=f"soc_swarm_iocs_{datetime.date.today()}.csv",
            mime="text/csv"
        )
    else:
        st.info("No matching indicators found.")
        
    con.close()

# -------------------------------------------------------------
# TAB 6: IOA EXPLORER
# -------------------------------------------------------------
elif menu == "⚔️ IOA Explorer":
    st.title("Indicators of Attack (IOA) Explorer")
    st.caption("Observed adversary behavioral patterns, living-off-the-land techniques, and Sigma/EDR detection rules")
    
    con = get_db()
    cur = con.cursor()
    
    ioa_search = st.text_input("Filter behaviors, patterns, techniques, or detection queries", "")
    
    query = """
        SELECT a.id, a.ioa_type, a.pattern_name, a.technique_id, a.observed_behavior, 
               a.detection_logic, a.confidence, i.title as incident_title
        FROM indicators_of_attack a
        LEFT JOIN incidents i ON a.incident_id = i.id
        WHERE 1=1
    """
    params = []
    if ioa_search:
        query += " AND (a.pattern_name LIKE ? OR a.observed_behavior LIKE ? OR a.technique_id LIKE ? OR a.detection_logic LIKE ?)"
        params.extend([f"%{ioa_search}%", f"%{ioa_search}%", f"%{ioa_search}%", f"%{ioa_search}%"])
        
    query += " ORDER BY a.created_at DESC"
    ioas = cur.execute(query, params).fetchall()
    
    if ioas:
        df_ioa = pd.DataFrame(ioas, columns=["ID", "Stage", "Pattern Name", "Technique ID", "Observed Behavior", "Detection Logic", "Confidence", "Associated Incident"])
        st.dataframe(df_ioa[["Stage", "Pattern Name", "Technique ID", "Observed Behavior", "Detection Logic", "Associated Incident"]], use_container_width=True, hide_index=True)
        
        csv_ioa = df_ioa.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export IOAs (CSV)",
            data=csv_ioa,
            file_name=f"soc_swarm_ioas_{datetime.date.today()}.csv",
            mime="text/csv"
        )
    else:
        st.info("No IOAs recorded matching query.")
        
    con.close()

# -------------------------------------------------------------
# TAB 7: THREAT INTELLIGENCE CHAT (GEMINI-POWERED)
# -------------------------------------------------------------
elif menu == "💬 Threat Intelligence Chat":
    st.title("Threat Intelligence Analyst Chat")
    st.caption("Converse with the Gemini 3.8 Flash agent grounded in local SQLite knowledge, IOC records, and live multi-platform research")
    
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "👋 I am your **SOC Swarm CTI Agent**. Ask me about today's published threat newsletter, historical dates, active botnet C2s from Feodo Tracker, Indian threat intel from CERT-In/CSK, or specific IOCs."}
        ]
        
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            
    if user_prompt := st.chat_input("Ask about threat reports, AI security, CVEs, or indicators..."):
        st.session_state.messages.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)
            
        with st.chat_message("assistant"):
            with st.spinner("Analyzing threat knowledge base & querying platforms..."):
                con = get_db()
                cur = con.cursor()
                
                # Check for exact IOC match in DB first
                exact_ioc = cur.execute("SELECT ioc_type, defanged_value, threat_status FROM iocs WHERE normalized_value LIKE ?", (f"%{user_prompt.strip()}%",)).fetchone()
                
                # Check for relevant incidents in DB
                matched_incidents = cur.execute("""
                    SELECT title, summary, category, severity, initial_access_vector, root_cause_analysis, publication_date
                    FROM incidents 
                    WHERE title LIKE ? OR summary LIKE ? OR category LIKE ? OR publication_date LIKE ?
                    LIMIT 3
                """, (f"%{user_prompt}%", f"%{user_prompt}%", f"%{user_prompt}%", f"%{user_prompt}%")).fetchall()
                
                # Check for relevant IOAs
                matched_ioas = cur.execute("""
                    SELECT pattern_name, technique_id, observed_behavior, detection_logic
                    FROM indicators_of_attack
                    WHERE pattern_name LIKE ? OR observed_behavior LIKE ? OR technique_id LIKE ?
                    LIMIT 2
                """, (f"%{user_prompt}%", f"%{user_prompt}%", f"%{user_prompt}%")).fetchall()
                
                con.close()
                
                # Build context
                context_str = "KNOWLEDGE BASE FINDINGS:\n"
                if exact_ioc:
                    context_str += f"- Exact IOC Match: {exact_ioc['defanged_value']} (Type: {exact_ioc['ioc_type']}, Status: {exact_ioc['threat_status']})\n"
                for inc in matched_incidents:
                    context_str += f"- Incident: {inc['title']} [Date: {inc['publication_date']}, Category: {inc['category']}, Severity: {inc['severity']}]\n  Summary: {inc['summary']}\n  Root Cause: {inc['root_cause_analysis']}\n"
                for ioa in matched_ioas:
                    context_str += f"- IOA: {ioa['pattern_name']} ({ioa['technique_id']}): {ioa['observed_behavior']}\n  Detection: {ioa['detection_logic']}\n"
                    
                client = get_gemini_client()
                if client:
                    try:
                        response = client.models.generate_content(
                            model="gemini-3.8-flash",
                            contents=f"""You are SOC Swarm CTI Assistant. Respond professionally as a senior cyber threat intelligence analyst.
GROUNDING CONTEXT:
{context_str}

USER QUESTION:
{user_prompt}

Guidelines:
1. Clearly state what is verified from local stored knowledge vs live synthesized findings.
2. Defang any IP addresses, domains, and URLs.
3. If mentioning MITRE techniques, cite technique IDs.
4. If asked about AI security or general cyber incidents, cite the stored incidents accurately."""
                        )
                        reply = response.text
                    except Exception as e:
                        reply = f"**Stored Intelligence Findings:**\n\n{context_str}\n\n*(Gemini API synthesis unavailable: {e})*"
                else:
                    reply = f"**Stored Intelligence Findings:**\n\n{context_str}"
                    
                st.markdown(reply)
                st.session_state.messages.append({"role": "assistant", "content": reply})

# -------------------------------------------------------------
# TAB 8: NOTIFICATIONS & SETTINGS
# -------------------------------------------------------------
elif menu == "⚙️ Notifications & Settings":
    st.title("Notifications Audit Log & System Configuration")
    st.caption("Manage Gmail alerts, delivery preferences, and threat intelligence source schedules")
    
    con = get_db()
    cur = con.cursor()
    
    st.subheader("📬 Gmail Notification Center")
    notifs = cur.execute("""
        SELECT n.id, n.subject, n.notification_type, n.recipient, n.delivery_status, n.plain_text_content, n.created_at, i.title
        FROM notifications n
        LEFT JOIN incidents i ON n.incident_id = i.id
        ORDER BY n.created_at DESC
        LIMIT 10
    """).fetchall()
    
    if notifs:
        for n in notifs:
            with st.expander(f"[{n['delivery_status']}] {n['subject']} — {n['created_at']}"):
                st.markdown(f"**Recipient:** `{n['recipient']}` | **Type:** `{n['notification_type']}`")
                st.text_area("Alert Payload (Plain-Text / HTML Preview)", n['plain_text_content'], height=200, disabled=True)
    else:
        st.info("No notifications generated yet. Disclosures will trigger alerts automatically.")
        
    st.divider()
    
    st.subheader("🔧 Gmail Integration & Polling Settings")
    col_cfg1, col_cfg2 = st.columns(2)
    with col_cfg1:
        recipient = st.text_input("Default Alert Recipient", "security-analyst@example.com")
        polling_mins = st.number_input("Polling Interval (Minutes)", min_value=5, max_value=120, value=15)
        st.checkbox("Send Alerts for High & Critical Severity Only", value=False)
        if st.button("📨 Send Test Gmail Alert"):
            test_id = str(uuid.uuid4())
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cur.execute("""
                INSERT INTO notifications (id, incident_id, notification_type, recipient, subject, delivery_status, html_content, plain_text_content, created_at)
                VALUES (?, NULL, 'TEST_ALERT', ?, '[SOC SWARM][DIAGNOSTIC TEST] Verification Alert', 'PREVIEW_STORED', '<h3>Test Alert</h3>', 'Diagnostic verification alert from SOC Swarm CTI.', ?)
            """, (test_id, recipient, now))
            con.commit()
            st.success(f"Test alert generated and stored in Notification Center for {recipient}!")
            st.rerun()
            
    with col_cfg2:
        st.markdown("**Live Gmail OAuth 2.0 Setup:**")
        st.markdown("""
        1. Create an OAuth 2.0 Client ID in **Google Cloud Console**.
        2. Download credentials JSON and place in `soc-swarm-cti/backend/credentials.json`.
        3. Authorize with scope `https://www.googleapis.com/auth/gmail.send` to generate `token.json`.
        4. In preview mode, all HTML advisories are safely formatted and inspectable in the notification audit log above.
        """)
        
    con.close()

# -------------------------------------------------------------
# TAB: SIEM & EDR RULE SYNTHESIZER
# -------------------------------------------------------------
elif menu == "🛡️ SIEM & EDR Rule Synthesizer":
    st.title("🛡️ Autonomous SIEM & EDR Rule Synthesizer")
    st.caption("Translate discovered threat intelligence and active botnet C2s into production-grade detection and firewall rules")
    
    con = get_db()
    cur = con.cursor()
    incidents = cur.execute("SELECT id, title, severity, category FROM incidents ORDER BY created_at DESC LIMIT 60").fetchall()
    
    if not incidents:
        st.info("No threat incidents recorded yet.")
        con.close()
    else:
        incident_map = {f"[{i['severity']}] {i['title'][:70]}": i['id'] for i in incidents}
        selected_label = st.selectbox("Select Incident to Synthesize Rules", list(incident_map.keys()))
        selected_id = incident_map[selected_label]
        
        # Load incident, iocs, ioas
        inc_data = cur.execute("SELECT * FROM incidents WHERE id = ?", (selected_id,)).fetchone()
        iocs_data = cur.execute("""
            SELECT i.ioc_type, i.normalized_value, i.defanged_value 
            FROM iocs i 
            JOIN incident_iocs ii ON i.id = ii.ioc_id 
            WHERE ii.incident_id = ?
        """, (selected_id,)).fetchall()
        ioas_data = cur.execute("SELECT technique_id, pattern_name, observed_behavior FROM indicators_of_attack WHERE incident_id = ?", (selected_id,)).fetchall()
        con.close()
        
        inc_dict = dict(inc_data)
        iocs_list = [dict(r) for r in iocs_data]
        ioas_list = [dict(r) for r in ioas_data]
        
        rules = generate_siem_rules_for_incident(inc_dict, iocs_list, ioas_list)
        
        tab_sigma, tab_splunk, tab_elastic, tab_suricata, tab_waf, tab_yara = st.tabs([
            "Sigma Rule (YAML)", "Splunk (SPL)", "Elasticsearch (KQL)", 
            "Suricata / Snort (IDS)", "AWS WAF / Cloudflare (JSON)", "YARA Rule"
        ])
        
        with tab_sigma:
            st.markdown("#### 📜 Generic EDR / SIEM Sigma Rule")
            st.code(rules["sigma"], language="yaml")
            st.download_button(
                "📥 Download Sigma Rule (.yml)",
                rules["sigma"],
                file_name=f"sigma_{selected_id[:8]}.yml",
                mime="text/yaml"
            )
            
        with tab_splunk:
            st.markdown("#### ⚡ Splunk Enterprise Search Processing Language (SPL)")
            st.code(rules["splunk"], language="spl")
            
        with tab_elastic:
            st.markdown("#### 🔍 Elasticsearch & Kibana Query Language (KQL)")
            st.code(rules["elastic"], language="sql")
            
        with tab_suricata:
            st.markdown("#### 🌐 Suricata & Snort Network Intrusion Signatures")
            st.code(rules["suricata"], language="text")
            st.download_button(
                "📥 Download Suricata Rule (.rules)",
                rules["suricata"],
                file_name=f"suricata_{selected_id[:8]}.rules",
                mime="text/plain"
            )
            
        with tab_waf:
            st.markdown("#### 🧱 AWS WAF IPSet & Cloudflare Boundary Protection JSON")
            st.code(rules["aws_waf"], language="json")
            st.download_button(
                "📥 Download AWS WAF JSON (.json)",
                rules["aws_waf"],
                file_name=f"waf_block_{selected_id[:8]}.json",
                mime="application/json"
            )
            
        with tab_yara:
            st.markdown("#### 🧬 Host Memory & Artifact YARA Signature")
            st.code(rules["yara"], language="text")

# -------------------------------------------------------------
# TAB: TECH STACK WATCHDOG & RUNBOOKS
# -------------------------------------------------------------
elif menu == "🎯 Tech Stack Watchdog & Runbooks":
    st.title("🎯 Tech Stack Watchdog & Incident Impact Matcher")
    st.caption("Continuously cross-reference all incoming threat advisories against your organization's monitored infrastructure")
    
    col_w1, col_w2 = st.columns([2, 1])
    with col_w1:
        assets_input = st.text_area(
            "🏢 Monitored Technology Assets (Comma-separated)",
            "Linux, Ubuntu, Windows Server, Kubernetes, Docker, Apache, Nginx, PostgreSQL, AWS, Palo Alto, Cisco, Fortinet, Python, LangChain, Gemini",
            height=80
        )
        active_assets = [a.strip() for a in assets_input.split(",") if a.strip()]
        
    con = get_db()
    cur = con.cursor()
    all_incidents = cur.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100").fetchall()
    con.close()
    
    matches = []
    for inc in all_incidents:
        inc_dict = dict(inc)
        res = match_incident_to_assets(inc_dict, active_assets)
        if res["is_impacted"]:
            matches.append((inc_dict, res))
            
    with col_w2:
        st.metric("Monitored Assets", len(active_assets))
        st.metric("Direct Exposures Discovered", len(matches), delta=f"{len(matches)} At Risk", delta_color="inverse")
        
    st.divider()
    st.subheader(f"🚨 Exposed Asset Findings ({len(matches)} Incidents)")
    
    if not matches:
        st.success("✅ Clean Bill of Health: No direct matches found between current active tech stack and recent threat intelligence.")
    else:
        for inc_dict, res in matches:
            exposure_color = "red" if "CRITICAL" in res["exposure_level"] else "orange"
            with st.expander(f"⚠️ [{res['exposure_level']}] {inc_dict['title']} — Impacted: {', '.join(res['matched_assets'])}"):
                st.markdown(f"**Affected Monitored Technologies:** `{', '.join(res['matched_assets'])}`")
                st.markdown(f"**Severity:** `{inc_dict['severity']}` | **Category:** `{inc_dict['category']}`")
                st.markdown(f"**Summary:** {inc_dict['summary']}")
                
                st.markdown("#### 🛠️ Automated Emergency Remediation Runbook")
                for step in res["runbook"]:
                    st.markdown(f"- {step}")

# -------------------------------------------------------------
# TAB: STIX 2.1 & TAXII EXPORTER
# -------------------------------------------------------------
elif menu == "📦 STIX 2.1 & TAXII Exporter":
    st.title("📦 STIX 2.1 Standard Threat Intel Exporter")
    st.caption("Interoperable Threat Intelligence Sharing format compliant with Oasis STIX 2.1 & TAXII 2.1")
    
    con = get_db()
    cur = con.cursor()
    incidents = [dict(r) for r in cur.execute("SELECT id, title, summary, category, severity FROM incidents LIMIT 50").fetchall()]
    iocs = [dict(r) for r in cur.execute("SELECT id, ioc_type, normalized_value, defanged_value FROM iocs LIMIT 100").fetchall()]
    ioas = [dict(r) for r in cur.execute("SELECT id, technique_id, pattern_name, observed_behavior FROM indicators_of_attack LIMIT 50").fetchall()]
    con.close()
    
    bundle = generate_stix_bundle(incidents, iocs, ioas)
    bundle_json = json.dumps(bundle, indent=2)
    
    col_s1, col_s2, col_s3 = st.columns(3)
    col_s1.metric("STIX Objects Generated", len(bundle["objects"]))
    col_s2.metric("Spec Version", bundle["spec_version"])
    col_s3.metric("Bundle ID", bundle["id"][:18] + "...")
    
    st.download_button(
        "📥 Download Official STIX 2.1 Bundle (JSON)",
        bundle_json,
        file_name="soc_swarm_stix21_bundle.json",
        mime="application/json",
        type="primary"
    )
    
    st.markdown("#### 🔗 Automated TAXII 2.1 Server Endpoint")
    st.info("External enterprise SIEMs (Microsoft Sentinel, Cortex XSOAR, Splunk, MISP) can poll this endpoint directly: `https://soc-swarm-cti-235215015655.asia-south2.run.app/api/stix2/bundle`")
    
    with st.expander("🔍 Inspect Full STIX 2.1 JSON Payload", expanded=False):
        st.code(bundle_json, language="json")

# -------------------------------------------------------------
# TAB: CHATOPS & SLACK DISPATCHER
# -------------------------------------------------------------
elif menu == "💬 ChatOps & Slack Dispatcher":
    st.title("💬 SOC ChatOps & Slack Webhook Dispatcher")
    st.caption("Broadcast high-priority disclosures and defanged IOCs to Slack or Microsoft Teams channels")
    
    con = get_db()
    cur = con.cursor()
    incidents = cur.execute("SELECT id, title, severity, category, summary, affected_organization, initial_access_vector FROM incidents ORDER BY created_at DESC LIMIT 50").fetchall()
    
    if incidents:
        incident_map = {f"[{i['severity']}] {i['title'][:70]}": i['id'] for i in incidents}
        selected_label = st.selectbox("Select Incident to Dispatch", list(incident_map.keys()))
        selected_id = incident_map[selected_label]
        
        selected_inc = dict(cur.execute("SELECT * FROM incidents WHERE id = ?", (selected_id,)).fetchone())
        iocs_data = [dict(r) for r in cur.execute("""
            SELECT i.ioc_type, i.defanged_value 
            FROM iocs i 
            JOIN incident_iocs ii ON i.id = ii.ioc_id 
            WHERE ii.incident_id = ?
        """, (selected_id,)).fetchall()]
        con.close()
        
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            webhook_url = st.text_input("Slack Incoming Webhook URL (Optional)", "", placeholder="https://hooks.slack.com/services/...")
            channel = st.text_input("Target Channel", "#soc-threat-intel")
            
            payload = build_slack_block_kit_payload(selected_inc, iocs_data, channel=channel)
            
            if st.button("🚀 Dispatch Alert to Slack", type="primary"):
                res = send_webhook_alert(webhook_url, payload)
                if res["status"] == "DELIVERED":
                    st.success(f"Alert successfully broadcasted to Slack ({res['status_code']})!")
                else:
                    st.info(f"Payload generated & verified in preview mode! (Live dispatch requires configured incoming webhook URL).")
                    
        with col_c2:
            st.markdown("#### 📱 Slack Block-Kit Message Preview")
            st.json(payload)
    else:
        st.info("No incidents found to dispatch.")
        con.close()

