import sqlite3
import datetime
from app.services.newsletter_service import (
    init_newsletter_schema, generate_daily_newsletter, 
    list_all_newsletter_dates, get_daily_newsletter
)
from app.services.live_fetcher import is_similar_title, defang_val

def test_defang_val():
    assert defang_val("192.168.1.1", "ipv4") == "192[.]168[.]1[.]1"
    assert defang_val("malicious.com", "domain") == "malicious[.]com"
    assert defang_val("http://evil.com/payload", "url") == "hxxp://evil[.]com/payload"
    assert defang_val("attacker@evil.com", "email") == "attacker[@]evil[.]com"

def test_title_similarity_deduplication():
    t1 = "Critical Apache HTTP Server Vulnerability Disclosed (CVE-2026-1234)"
    t2 = "Urgent: Apache HTTP Server Vulnerability Disclosed CVE-2026-1234"
    assert is_similar_title(t1, t2) is True
    
    t3 = "Completely Unrelated Malware Syndicate Emerges in Region"
    assert is_similar_title(t1, t3) is False

def test_newsletter_generation_flow():
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    # Create incidents schema
    cur.execute("""
    CREATE TABLE incidents (
        id TEXT PRIMARY KEY,
        primary_source_doc_id TEXT,
        title TEXT,
        summary TEXT,
        affected_organization TEXT,
        affected_systems TEXT,
        initial_access_vector TEXT,
        root_cause_analysis TEXT,
        severity TEXT,
        confidence_score REAL,
        status TEXT,
        is_demo BOOLEAN,
        category TEXT,
        is_updated BOOLEAN,
        publication_date TEXT,
        created_at TIMESTAMP,
        updated_at TIMESTAMP
    )
    """)
    cur.execute("CREATE TABLE source_documents (id TEXT PRIMARY KEY, source_id TEXT, canonical_url TEXT)")
    cur.execute("CREATE TABLE iocs (id TEXT PRIMARY KEY, ioc_type TEXT, normalized_value TEXT, defanged_value TEXT, threat_status TEXT)")
    cur.execute("CREATE TABLE incident_iocs (id TEXT PRIMARY KEY, incident_id TEXT, ioc_id TEXT, context_role TEXT, confidence REAL)")
    cur.execute("CREATE TABLE indicators_of_attack (id TEXT PRIMARY KEY, incident_id TEXT, ioa_type TEXT, pattern_name TEXT, technique_id TEXT, observed_behavior TEXT, detection_logic TEXT, confidence REAL, created_at TIMESTAMP)")
    
    today = datetime.date.today().isoformat()
    cur.execute("""
        INSERT INTO incidents (id, title, summary, category, severity, affected_organization, publication_date, created_at)
        VALUES ('inc-1', 'CISA Advisory: Edge Exploitation', 'Active zero day targeting public edge.', 'General Cybersecurity', 'CRITICAL', 'Global Org', ?, ?)
    """, (today, today))
    con.commit()
    
    # Initialize and generate newsletter
    init_newsletter_schema(con)
    nl = generate_daily_newsletter(con, target_date=today, gemini_client=None)
    assert nl is not None
    assert nl["total_unique_reports"] == 1
    assert nl["high_critical_count"] == 1
    assert "CISA Advisory" in nl["markdown_content"]
    
    # Verify retrieval
    retrieved = get_daily_newsletter(con, today)
    assert retrieved is not None
    assert retrieved["title"] == nl["title"]
    
    con.close()
