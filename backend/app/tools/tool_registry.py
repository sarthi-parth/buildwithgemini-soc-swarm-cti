import re
import hashlib
import ipaddress
import urllib.parse
from typing import List, Dict, Any, Optional
import httpx
import feedparser
from bs4 import BeautifulSoup

def defang_ioc(ioc_type: str, value: str) -> str:
    """Safe representation of IOCs so they cannot be clicked/accused of execution."""
    val = value.strip()
    if ioc_type in ("ipv4", "ipv6"):
        return val.replace(".", "[.]").replace(":", "[:]")
    elif ioc_type == "url":
        val = re.sub(r"^http://", "hxxp://", val, flags=re.IGNORECASE)
        val = re.sub(r"^https://", "hxxps://", val, flags=re.IGNORECASE)
        return val.replace(".", "[.]")
    elif ioc_type == "domain":
        return val.replace(".", "[.]")
    elif ioc_type == "email":
        return val.replace("@", "[at]").replace(".", "[.]")
    return val

def compute_content_hash(content: str) -> str:
    return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()

def normalize_source_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    # Strip tracking params like utm_*
    query_parts = urllib.parse.parse_qsl(parsed.query)
    clean_parts = [(k, v) for k, v in query_parts if not k.startswith("utm_")]
    clean_query = urllib.parse.urlencode(clean_parts)
    return urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/"),
        parsed.params,
        clean_query,
        ""
    ))

def validate_ioc_format(ioc_type: str, value: str) -> bool:
    val = value.strip()
    if ioc_type == "ipv4":
        try:
            ip = ipaddress.IPv4Address(val)
            return not ip.is_loopback
        except ValueError:
            return False
    elif ioc_type == "ipv6":
        try:
            ip = ipaddress.IPv6Address(val)
            return not ip.is_loopback
        except ValueError:
            return False
    elif ioc_type == "domain":
        return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$", val))
    elif ioc_type == "cve":
        return bool(re.match(r"^CVE-\d{4}-\d{4,8}$", val, re.IGNORECASE))
    elif ioc_type == "sha256":
        return bool(re.match(r"^[a-fA-F0-9]{64}$", val))
    elif ioc_type == "md5":
        return bool(re.match(r"^[a-fA-F0-9]{32}$", val))
    elif ioc_type == "url":
        return bool(re.match(r"^https?://[^\s/$.?#].[^\s]*$", val, re.IGNORECASE))
    elif ioc_type == "email":
        return bool(re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", val))
    elif ioc_type == "malware_family":
        return len(val) >= 2 and not val.isdigit()
    return True

def extract_deterministic_iocs(text: str) -> List[Dict[str, Any]]:
    """Extracts confirmed indicators via regex with exact provenance."""
    extracted = []
    seen = set()

    # CVEs
    for cve in re.findall(r"\bCVE-\d{4}-\d{4,8}\b", text, re.IGNORECASE):
        norm = cve.upper()
        if norm not in seen:
            seen.add(norm)
            extracted.append({
                "ioc_type": "cve",
                "normalized_value": norm,
                "defanged_value": norm,
                "confidence": 1.0,
                "context_role": "Vulnerability"
            })

    # SHA256
    for sha in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
        norm = sha.lower()
        if norm not in seen:
            seen.add(norm)
            extracted.append({
                "ioc_type": "sha256",
                "normalized_value": norm,
                "defanged_value": norm,
                "confidence": 1.0,
                "context_role": "Payload Hash"
            })

    # MD5
    for md5 in re.findall(r"\b[a-fA-F0-9]{32}\b", text):
        norm = md5.lower()
        if norm not in seen:
            seen.add(norm)
            extracted.append({
                "ioc_type": "md5",
                "normalized_value": norm,
                "defanged_value": norm,
                "confidence": 0.95,
                "context_role": "Payload Hash"
            })

    # IPv4
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        if validate_ioc_format("ipv4", ip) and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("127."):
            if ip not in seen:
                seen.add(ip)
                extracted.append({
                    "ioc_type": "ipv4",
                    "normalized_value": ip,
                    "defanged_value": defang_ioc("ipv4", ip),
                    "confidence": 0.9,
                    "context_role": "Network Infrastructure"
                })

    return extracted

async def fetch_rss_feed_entries(url: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Fetches and parses RSS/Atom feeds with safety checks."""
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        headers = {"User-Agent": "SOC-Swarm-CTI/1.0 (+https://github.com/cszhu/build-with-gemini)"}
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        content = resp.text

    feed = feedparser.parse(content)
    results = []
    for entry in feed.entries[:limit]:
        raw_summary = entry.get("summary") or entry.get("description") or ""
        soup = BeautifulSoup(raw_summary, "html.parser")
        clean_summary = soup.get_text(separator=" ", strip=True)

        results.append({
            "title": entry.get("title", "Untitled").strip(),
            "url": entry.get("link", "").strip(),
            "summary": clean_summary,
            "published": entry.get("published") or entry.get("updated") or "",
        })
    return results

async def fetch_article_text(url: str) -> str:
    """Retrieves full article text, stripping navigation and ads."""
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        html = resp.text

    soup = BeautifulSoup(html, "html.parser")
    for script_or_style in soup(["script", "style", "nav", "footer", "header", "aside"]):
        script_or_style.decompose()

    text = soup.get_text(separator="\n", strip=True)
    return text[:15000] # Safe upper bound to prevent oversized inputs
