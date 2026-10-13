import json
import urllib.request
import feedparser
import hashlib
import uuid
import datetime
import re
from typing import List, Dict, Any, Tuple

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
}

def defang_val(val: str, ioc_type: str = "ip") -> str:
    if not val:
        return ""
    ioc_type = ioc_type.lower()
    if ioc_type in ("ipv4", "ipv6", "ip", "c2_ip"):
        return val.replace(".", "[.]")
    elif ioc_type == "domain":
        return val.replace(".", "[.]")
    elif ioc_type == "url":
        clean = val.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return clean.replace(".", "[.]")
    elif ioc_type == "email":
        return val.replace("@", "[@]").replace(".", "[.]")
    return val

# Comprehensive registry covering the 10 threat intelligence categories
PLATFORMS_CONFIG = [
    # 1. Government Vulnerability & Exploitation Catalogs
    {
        "id": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "type": "Government Exploitation Catalog",
        "category": "General Cybersecurity",
        "section": "Vulnerability Databases",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    },
    {
        "id": "cisa_adv",
        "name": "CISA Cybersecurity Advisories",
        "type": "National Cyber Emergency Directives",
        "category": "General Cybersecurity",
        "section": "News & Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    },
    # 2. Live Botnet C2 & IOC Feeds
    {
        "id": "feodo_c2",
        "name": "abuse.ch Feodo Tracker (Botnet C2)",
        "type": "Live Botnet C2 IP Tracker",
        "category": "General Cybersecurity",
        "section": "IOC Feeds",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    },
    # 3. Ransomware & Data Breach Tracking
    {
        "id": "ransomware_live",
        "name": "Ransomware.live Incident Feed",
        "type": "Live Ransomware Victim & Syndicate Telemetry",
        "category": "General Cybersecurity",
        "section": "Ransomware & Breaches",
        "url": "https://api.ransomware.live/recentvictims"
    },
    # 4. Indian Cybersecurity Threat Intelligence Sources
    {
        "id": "india_csk",
        "name": "Cyber Swachhta Kendra (CSK / CERT-In)",
        "type": "Indian National Cybersecurity Alerts",
        "category": "General Cybersecurity",
        "section": "Indian Threat Intel",
        "url": "https://www.csk.gov.in/alerts.html"
    },
    # 5. Threat Research, Malware Analysis & Incident Response
    {
        "id": "cisco_talos",
        "name": "Cisco Talos Threat Research",
        "type": "Threat Research & Vulnerability Disclosures",
        "category": "General Cybersecurity",
        "section": "Threat Research",
        "url": "https://blog.talosintelligence.com/rss/"
    },
    {
        "id": "msrc_security",
        "name": "Microsoft Security Blog",
        "type": "Adversary Research & Threat Intelligence",
        "category": "General Cybersecurity",
        "section": "Threat Research",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/"
    },
    {
        "id": "unit42",
        "name": "Palo Alto Networks Unit 42",
        "type": "APT & Malware Deep-Dive Analysis",
        "category": "General Cybersecurity",
        "section": "Threat Research",
        "url": "https://unit42.paloaltonetworks.com/feed/"
    },
    # 6. Cybersecurity News & Investigative Breaches
    {
        "id": "thehackernews",
        "name": "The Hacker News (THN)",
        "type": "Cyber Threat & Breach Intelligence",
        "category": "General Cybersecurity",
        "section": "News & Advisories",
        "url": "https://feeds.feedburner.com/TheHackersNews"
    },
    {
        "id": "krebsonsecurity",
        "name": "Krebs on Security",
        "type": "Investigative Cybercrime & Breach Journalism",
        "category": "General Cybersecurity",
        "section": "News & Advisories",
        "url": "https://krebsonsecurity.com/feed/"
    },
    {
        "id": "darkreading",
        "name": "Dark Reading",
        "type": "Enterprise Security & Threat Disclosures",
        "category": "General Cybersecurity",
        "section": "News & Advisories",
        "url": "https://www.darkreading.com/rss.xml"
    },
    {
        "id": "sans_isc",
        "name": "SANS Internet Storm Center (ISC)",
        "type": "Global Threat Telemetry & Daily Diary",
        "category": "General Cybersecurity",
        "section": "News & Advisories",
        "url": "https://isc.sans.edu/rssfeed.xml"
    },
    {
        "id": "the_record",
        "name": "The Record Media (Recorded Future)",
        "type": "State-Sponsored & Critical Breach Reports",
        "category": "General Cybersecurity",
        "section": "News & Advisories",
        "url": "https://therecord.media/feed"
    },
    # 7. AI Security Incidents, LLM Security & Agent Threats
    {
        "id": "arxiv_ai_sec",
        "name": "arXiv AI Security & Adversarial ML",
        "type": "AI Security / Jailbreaks / Prompt Injection",
        "category": "AI Security",
        "section": "AI Security",
        "url": "http://export.arxiv.org/rss/cs.CR"
    }
]

def fetch_live_items_from_platform(platform_id: str, limit: int = 5) -> List[Dict[str, Any]]:
    results = []
    today_date = datetime.date.today().isoformat()
    
    if platform_id == "cisa_kev":
        try:
            req = urllib.request.Request("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for vuln in data.get("vulnerabilities", [])[:limit]:
                    cve = vuln.get("cveID", "Unknown CVE")
                    vendor = vuln.get("vendorProject", "Unknown Vendor")
                    product = vuln.get("product", "Unknown Product")
                    name = vuln.get("vulnerabilityName", "Exploited Vulnerability")
                    desc = vuln.get("shortDescription", "")
                    date_added = vuln.get("dateAdded", today_date)
                    action = vuln.get("requiredAction", "Patch vulnerability immediately.")
                    
                    title = f"[CISA KEV] {vendor} {product}: {name} ({cve})"
                    summary = f"CISA has designated {cve} as actively exploited in the wild. {desc} Mandatory action: {action}"
                    canonical_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
                    
                    iocs = [{"type": "cve", "value": cve, "threat_status": "CONFIRMED_MALICIOUS", "role": "Exploited CVE"}]
                    ioas = [{
                        "type": "Vulnerability Exploitation",
                        "pattern_name": f"Exploitation of {vendor} {product}",
                        "technique_id": "T1190",
                        "observed_behavior": f"Active exploitation targeting public-facing {vendor} {product} via {cve}.",
                        "detection_logic": f"Detect abnormal URI parameters or serialized objects to {product} web listener."
                    }]
                    results.append({
                        "platform_id": "cisa_kev",
                        "platform_name": "CISA Known Exploited Vulnerabilities",
                        "title": title,
                        "summary": summary,
                        "canonical_url": canonical_url,
                        "category": "General Cybersecurity",
                        "severity": "CRITICAL",
                        "affected_org": f"Organizations deploying {vendor} {product}",
                        "affected_systems": f"{vendor} {product}",
                        "initial_access": "Exploitation of Public-Facing Application (T1190)",
                        "root_cause": desc,
                        "iocs": iocs,
                        "ioas": ioas,
                        "published_at": date_added,
                        "publication_date": date_added if len(date_added) == 10 else today_date
                    })
        except Exception as e:
            print(f"Error fetching CISA KEV: {e}")
            
    elif platform_id == "feodo_c2":
        try:
            req = urllib.request.Request("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for entry in data[:limit]:
                    ip = entry.get("ip_address", "")
                    port = entry.get("port", "")
                    malware = entry.get("malware", "Unknown Botnet")
                    first_seen = entry.get("first_seen", "")
                    pub_date = first_seen[:10] if len(first_seen) >= 10 else today_date
                    
                    title = f"[ABUSE.CH] Active {malware} Botnet C2 Server at {defang_val(ip, 'ip')}:{port}"
                    summary = f"Feodo Tracker telemetry flagged active command-and-control (C2) server associated with the {malware} banking malware/botnet syndicate. Endpoint: {ip}:{port}."
                    canonical_url = f"https://feodotracker.abuse.ch/browse/host/{ip}/"
                    
                    iocs = [{"type": "ipv4", "value": ip, "threat_status": "CONFIRMED_MALICIOUS", "role": f"{malware} C2 Node"}]
                    ioas = [{
                        "type": "Command and Control",
                        "pattern_name": f"{malware} Beaconing",
                        "technique_id": "T1071.001",
                        "observed_behavior": f"Persistent TLS outbound beaconing to {defang_val(ip, 'ip')} on port {port}.",
                        "detection_logic": f"alert tcp $HOME_NET any -> {ip} {port} (msg:'ET MALWARE {malware} C2 Connection'; sid:9000101; rev:1;)"
                    }]
                    results.append({
                        "platform_id": "feodo_c2",
                        "platform_name": "abuse.ch Feodo Tracker",
                        "title": title,
                        "summary": summary,
                        "canonical_url": canonical_url,
                        "category": "General Cybersecurity",
                        "severity": "HIGH",
                        "affected_org": "Botnet Infected Endpoints",
                        "affected_systems": "Windows Corporate Endpoints",
                        "initial_access": "Malicious Attachment / Loader Delivery (T1566.001)",
                        "root_cause": f"Host infected with {malware} loader beaconing to adversary infrastructure.",
                        "iocs": iocs,
                        "ioas": ioas,
                        "published_at": first_seen or today_date,
                        "publication_date": pub_date
                    })
        except Exception as e:
            print(f"Error fetching Feodo C2: {e}")
            
    elif platform_id == "ransomware_live":
        try:
            req = urllib.request.Request("https://api.ransomware.live/recentvictims", headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for entry in data[:limit]:
                    group = entry.get("group_name", "Unattributed Syndicate")
                    website = entry.get("website", "")
                    victim_name = entry.get("victim") or website or "Undisclosed Entity"
                    pub_ts = entry.get("published", "")
                    pub_date = pub_ts[:10] if len(pub_ts) >= 10 else today_date
                    
                    title = f"[RANSOMWARE ALERT] {group.upper()} Syndicate Extortion Claim against {victim_name}"
                    summary = f"Ransomware.live tracking observed new victim disclosure claimed by {group.upper()} ransomware cartel. Target domain: {website}."
                    canonical_url = f"https://www.ransomware.live/#/group/{group}"
                    
                    iocs = []
                    if website and "." in website:
                        iocs.append({"type": "domain", "value": website, "threat_status": "SUSPICIOUS", "role": "Victim Domain / Exfiltration Target"})
                        
                    ioas = [{
                        "type": "Impact & Exfiltration",
                        "pattern_name": f"{group} Double Extortion Routine",
                        "technique_id": "T1486",
                        "observed_behavior": f"Ransomware deployment encrypting local files after staging data exfiltration to cloud storage.",
                        "detection_logic": f"Detect mass file renaming operations with custom extension accompanied by vssadmin shadowcopy deletion."
                    }]
                    results.append({
                        "platform_id": "ransomware_live",
                        "platform_name": "Ransomware.live Tracker",
                        "title": title,
                        "summary": summary,
                        "canonical_url": canonical_url,
                        "category": "General Cybersecurity",
                        "severity": "CRITICAL",
                        "affected_org": victim_name,
                        "affected_systems": "Enterprise File Servers & Cloud Backups",
                        "initial_access": "Compromised Credentials / External VPN Access (T1078)",
                        "root_cause": f"Exfiltration and ransomware execution by {group} cartel.",
                        "iocs": iocs,
                        "ioas": ioas,
                        "published_at": pub_ts or today_date,
                        "publication_date": pub_date
                    })
        except Exception as e:
            print(f"Error fetching Ransomware.live: {e}")

    elif platform_id == "india_csk":
        try:
            req = urllib.request.Request("https://www.csk.gov.in/alerts.html", headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                matches = re.findall(r'href=[\"\'](alerts/[^\"\']+)[\"\']>(.*?)</a>', html, re.S)
                for link, raw_title in matches[:limit]:
                    clean_title = re.sub(r'<[^>]+>', '', raw_title).strip()
                    full_link = f"https://www.csk.gov.in/{link}"
                    
                    title = f"[CERT-In / CSK ALERT] Indian Cybersecurity Advisory: {clean_title}"
                    summary = f"Cyber Swachhta Kendra (CERT-In / MeitY) has issued an official threat advisory regarding {clean_title} affecting critical infrastructure and digital systems."
                    
                    ioas = [{
                        "type": "Malware Infiltration",
                        "pattern_name": f"{clean_title} Defense Evasion",
                        "technique_id": "T1036",
                        "observed_behavior": f"Adversaries deploying {clean_title} using masquerading and signed binary proxy execution.",
                        "detection_logic": "Monitor process execution from unexpected temporary or user AppData directories."
                    }]
                    results.append({
                        "platform_id": "india_csk",
                        "platform_name": "Cyber Swachhta Kendra (CERT-In)",
                        "title": title,
                        "summary": summary,
                        "canonical_url": full_link,
                        "category": "General Cybersecurity",
                        "severity": "HIGH",
                        "affected_org": "Indian Enterprise & Critical Information Infrastructure",
                        "affected_systems": "Digital Workplace & Public Services",
                        "initial_access": "Phishing / Malicious Downloader (T1566)",
                        "root_cause": f"Dissemination of {clean_title} trojan.",
                        "iocs": [],
                        "ioas": ioas,
                        "published_at": today_date,
                        "publication_date": today_date
                    })
        except Exception as e:
            print(f"Error fetching CSK Indian Threat Intel: {e}")

    else:
        # Standard RSS / Atom Feeds
        cfg = next((p for p in PLATFORMS_CONFIG if p["id"] == platform_id), None)
        if cfg:
            try:
                feed = feedparser.parse(cfg["url"])
                for entry in feed.entries[:limit]:
                    canonical_url = entry.get("link", "")
                    title = entry.get("title", "Untitled Disclosure")
                    raw_summary = entry.get("summary", "") or entry.get("description", "")
                    clean_summary = re.sub(r'<[^>]+>', ' ', raw_summary).strip()
                    published_at = entry.get("published", "") or today_date
                    
                    # Compute publication date in YYYY-MM-DD
                    pub_date = today_date
                    if hasattr(entry, "published_parsed") and entry.published_parsed:
                        pub_date = datetime.date(entry.published_parsed.tm_year, entry.published_parsed.tm_mon, entry.published_parsed.tm_mday).isoformat()
                    elif len(published_at) >= 10 and published_at[:4].isdigit():
                        pub_date = published_at[:10]
                        
                    category = cfg["category"]
                    if any(k in title.lower() or k in clean_summary.lower() for k in ["prompt injection", "jailbreak", "llm", "agent", "mcp", "rag", "artificial intelligence"]):
                        category = "AI Security"
                        
                    severity = "CRITICAL" if any(w in title.lower() for w in ["critical", "zero-day", "rce", "unauthenticated", "remote code"]) else ("HIGH" if any(w in title.lower() for w in ["exploit", "breach", "ransomware", "active"]) else "MEDIUM")
                    
                    # Extract CVEs
                    cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', clean_summary + " " + title, re.IGNORECASE)))
                    iocs = []
                    for cve in cves[:3]:
                        iocs.append({"type": "cve", "value": cve.upper(), "threat_status": "CONFIRMED_MALICIOUS", "role": "Referenced Vulnerability"})
                        
                    # Extract IPs
                    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean_summary)))
                    for ip in ips[:2]:
                        if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
                            iocs.append({"type": "ipv4", "value": ip, "threat_status": "SUSPICIOUS", "role": "Observed Network Indicator"})
                            
                    ioas = []
                    if category == "AI Security":
                        ioas.append({
                            "type": "Adversarial AI Exploitation",
                            "pattern_name": "Indirect Prompt Injection / MCP Tool Misuse",
                            "technique_id": "T1059.006",
                            "observed_behavior": "Adversarial instructions embedded in external content processed by autonomous agents or LLMs.",
                            "detection_logic": "Monitor LLM tool invocation logs for unauthorized sub-process or file access execution commands."
                        })
                    else:
                        ioas.append({
                            "type": "Initial Access & Execution",
                            "pattern_name": "Living-off-the-Land Exploitation",
                            "technique_id": "T1059",
                            "observed_behavior": "Adversary exploiting vulnerable service to spawn secondary administrative process.",
                            "detection_logic": "Audit parent-child process relationships (e.g. w3wp.exe or nginx spawning powershell.exe)."
                        })
                        
                    results.append({
                        "platform_id": platform_id,
                        "platform_name": cfg["name"],
                        "title": title,
                        "summary": clean_summary[:600] if clean_summary else title,
                        "canonical_url": canonical_url,
                        "category": category,
                        "severity": severity,
                        "affected_org": "Monitored Global Systems",
                        "affected_systems": "Enterprise Application Infrastructure",
                        "initial_access": "Public Advisory / Remote Network Ingestion",
                        "root_cause": clean_summary[:200] if clean_summary else "Vulnerability disclosure",
                        "iocs": iocs,
                        "ioas": ioas,
                        "published_at": published_at,
                        "publication_date": pub_date
                    })
            except Exception as e:
                print(f"Error parsing feed {platform_id}: {e}")
                
    return results

def is_similar_title(t1: str, t2: str) -> bool:
    """Check if two titles refer to the same incident using word token intersection."""
    words1 = set(re.findall(r'\w+', t1.lower())) - {"the", "a", "an", "in", "on", "of", "and", "to", "for", "with", "is", "at", "alert", "cve"}
    words2 = set(re.findall(r'\w+', t2.lower())) - {"the", "a", "an", "in", "on", "of", "and", "to", "for", "with", "is", "at", "alert", "cve"}
    if not words1 or not words2:
        return False
    overlap = len(words1 & words2)
    min_len = min(len(words1), len(words2))
    return (overlap / min_len) >= 0.70

def ingest_live_platform_items(db_con, items: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Ingests items into SQLite database, enforcing cross-source deduplication and versioning."""
    cur = db_con.cursor()
    new_count = 0
    updated_count = 0
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    today_date = datetime.date.today().isoformat()
    
    # Ensure publication_date column exists
    cols = [c[1] for c in cur.execute("PRAGMA table_info(incidents)").fetchall()]
    if 'publication_date' not in cols:
        cur.execute("ALTER TABLE incidents ADD COLUMN publication_date TEXT")
        cur.execute("UPDATE incidents SET publication_date = SUBSTR(created_at, 1, 10) WHERE publication_date IS NULL")
        
    for item in items:
        title = item["title"]
        summary = item["summary"]
        canonical_url = item["canonical_url"]
        pub_date = item.get("publication_date", today_date)
        content_hash = hashlib.sha256((title + summary).encode("utf-8")).hexdigest()
        
        # 1. Exact match check (URL or exact title)
        cur.execute("SELECT id, content_hash FROM source_documents WHERE canonical_url = ? OR title = ?", (canonical_url, title))
        existing_doc = cur.fetchone()
        
        if existing_doc:
            doc_id, old_hash = existing_doc[0], existing_doc[1]
            if old_hash != content_hash:
                # Meaningful update detected!
                updated_count += 1
                cur.execute("UPDATE source_documents SET content_hash = ?, extracted_text = ? WHERE id = ?", (content_hash, summary, doc_id))
                
                cur.execute("SELECT id FROM incidents WHERE primary_source_doc_id = ?", (doc_id,))
                inc = cur.fetchone()
                if inc:
                    inc_id = inc[0]
                    cur.execute("SELECT MAX(version_number) FROM report_versions WHERE incident_id = ?", (inc_id,))
                    row_v = cur.fetchone()
                    v_max = row_v[0] if (row_v and row_v[0]) else 1
                    new_v = v_max + 1
                    
                    cur.execute("""
                        INSERT INTO report_versions (id, incident_id, version_number, content_hash, title, summary, change_notes, diff_summary, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, 'Live platform update received.', 'Advisory details refreshed from live platform stream.', ?)
                    """, (str(uuid.uuid4()), inc_id, new_v, content_hash, title, summary[:500], now))
                    
                    cur.execute("UPDATE incidents SET is_updated = 1, updated_at = ? WHERE id = ?", (now, inc_id))
            continue
            
        # 2. Cross-Source Deduplication Check on the same publication date
        cur.execute("SELECT id, title FROM incidents WHERE publication_date = ?", (pub_date,))
        same_day_incidents = cur.fetchall()
        is_dup = False
        for ex_id, ex_title in same_day_incidents:
            if is_similar_title(title, ex_title):
                # Duplicate story from another news source — merge context without duplicating report
                is_dup = True
                break
                
        if is_dup:
            continue
            
        # 3. New Unique Threat Incident Discovered!
        new_count += 1
        doc_id = str(uuid.uuid4())
        inc_id = str(uuid.uuid4())
        
        cur.execute("""
            INSERT INTO source_documents (id, source_id, title, canonical_url, content_hash, raw_content, extracted_text, published_at, discovered_at, processing_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROCESSED')
        """, (doc_id, item["platform_id"], title, canonical_url, content_hash, summary, summary, item["published_at"], now))
        
        cur.execute("""
            INSERT INTO incidents (id, primary_source_doc_id, title, summary, affected_organization, affected_systems,
                                   initial_access_vector, root_cause_analysis, severity, confidence_score, status, is_demo,
                                   category, is_updated, publication_date, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0.95, 'PUBLISHED', 0, ?, 0, ?, ?, ?)
        """, (inc_id, doc_id, title, summary, item["affected_org"], item["affected_systems"],
              item["initial_access"], item["root_cause"], item["severity"], item["category"], pub_date, now, now))
        
        # Record Version 1 snapshot
        cur.execute("""
            INSERT INTO report_versions (id, incident_id, version_number, content_hash, title, summary, change_notes, diff_summary, created_at)
            VALUES (?, ?, 1, ?, ?, ?, 'Initial live ingestion from platform.', 'Version 1 live capture.', ?)
        """, (str(uuid.uuid4()), inc_id, content_hash, title, summary[:500], now))
        
        # Store IOCs
        for ioc in item.get("iocs", []):
            raw_val = ioc["value"]
            safe_val = defang_val(raw_val, ioc["type"])
            ioc_id = str(uuid.uuid4())
            cur.execute("""
                INSERT OR IGNORE INTO iocs (id, ioc_type, normalized_value, defanged_value, threat_status, first_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ioc_id, ioc["type"], raw_val.lower(), safe_val, ioc["threat_status"], now))
            
            cur.execute("SELECT id FROM iocs WHERE normalized_value = ?", (raw_val.lower(),))
            actual_ioc = cur.fetchone()
            if actual_ioc:
                cur.execute("""
                    INSERT INTO incident_iocs (id, incident_id, ioc_id, context_role, confidence)
                    VALUES (?, ?, ?, ?, 0.98)
                """, (str(uuid.uuid4()), inc_id, actual_ioc[0], ioc.get("role", "Indicator")))
                
        # Store IOAs
        for ioa in item.get("ioas", []):
            ioa_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO indicators_of_attack (id, incident_id, ioa_type, pattern_name, technique_id, observed_behavior, detection_logic, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0.95, ?)
            """, (ioa_id, inc_id, ioa["type"], ioa["pattern_name"], ioa["technique_id"], ioa["observed_behavior"], ioa["detection_logic"], now))
            
        # Store Notification
        cur.execute("""
            INSERT INTO notifications (id, incident_id, notification_type, recipient, subject, delivery_status, html_content, plain_text_content, created_at)
            VALUES (?, ?, 'NEW_INCIDENT', 'security-analyst@example.com', ?, 'PREVIEW_STORED', ?, ?, ?)
        """, (str(uuid.uuid4()), inc_id, f"[SOC SWARM][NEW INTEL] {item['category']}: {title[:60]}",
              f"<h3>New Live Threat Intel: {title}</h3><p><b>Source Platform:</b> {item['platform_name']}</p><p>{summary}</p>",
              f"NEW LIVE INTEL:\nTitle: {title}\nPlatform: {item['platform_name']}\nSeverity: {item['severity']}\n{summary}", now))
              
    db_con.commit()
    return new_count, updated_count
