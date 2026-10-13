import json
import urllib.request
from typing import Dict, Any, List

def build_slack_block_kit_payload(incident: Dict[str, Any], iocs: List[Dict[str, Any]] = None, channel: str = "#soc-threat-intel") -> Dict[str, Any]:
    """Constructs a production Slack Block-Kit message payload for SOC ChatOps."""
    title = incident.get("title", "Threat Incident")
    severity = incident.get("severity", "HIGH")
    category = incident.get("category", "General Cybersecurity")
    summary = incident.get("summary", "")[:300]
    
    icon = "🚨" if severity == "CRITICAL" else ("⚠️" if severity == "HIGH" else "ℹ️")
    
    ioc_lines = []
    if iocs:
        for ioc in iocs[:3]:
            ioc_lines.append(f"• `{ioc.get('ioc_type')}`: `{ioc.get('defanged_value')}`")
    ioc_text = "\n".join(ioc_lines) if ioc_lines else "None extracted."
    
    payload = {
        "channel": channel,
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{icon} SOC Swarm Alert: {severity} Incident Disclosed",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*\n{summary}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Category:*\n`{category}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n`{severity}`"},
                    {"type": "mrkdwn", "text": f"*Affected Org:*\n{incident.get('affected_organization') or 'Global'}"},
                    {"type": "mrkdwn", "text": f"*Initial Access:*\n{incident.get('initial_access_vector') or 'Unknown'}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Defanged IOCs:*\n{ioc_text}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🛡️ View in Dashboard"},
                        "style": "primary",
                        "url": "https://soc-swarm-cti-235215015655.asia-south2.run.app"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📋 Copy Sigma Rule"},
                        "value": "copy_rule"
                    }
                ]
            }
        ]
    }
    return payload

def send_webhook_alert(webhook_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatches webhook payload to Slack or Teams endpoint."""
    if not webhook_url or not webhook_url.startswith("http"):
        return {"status": "PREVIEW_READY", "detail": "Valid webhook URL not configured; payload preview stored."}
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return {"status": "DELIVERED", "status_code": resp.status}
    except Exception as e:
        return {"status": "FAILED", "error": str(e)}
