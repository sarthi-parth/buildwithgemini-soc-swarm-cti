import os
import base64
import json
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional

from app.config import settings

class GmailNotificationService:
    def __init__(self):
        self.credentials_file = settings.GMAIL_CREDENTIALS_FILE
        self.token_file = settings.GMAIL_TOKEN_FILE

    def is_configured(self) -> bool:
        return os.path.exists(self.token_file) or os.path.exists(self.credentials_file)

    def get_status(self) -> Dict[str, Any]:
        has_token = os.path.exists(self.token_file)
        has_creds = os.path.exists(self.credentials_file)
        return {
            "configured": has_token,
            "has_token": has_token,
            "has_credentials": has_creds,
            "enabled": settings.GMAIL_ENABLED,
            "default_recipient": settings.GMAIL_DEFAULT_RECIPIENT,
            "mode": "live_gmail" if (has_token and settings.GMAIL_ENABLED) else "preview_mode",
            "setup_instructions": (
                "To enable live Gmail notifications:\n"
                "1. Create a project in Google Cloud Console.\n"
                "2. Enable the Gmail API (https://mail.google.com/).\n"
                "3. Create OAuth 2.0 Client Credentials (Desktop app) and save to 'credentials.json'.\n"
                "4. Run the OAuth authorization script to generate 'token.json'.\n"
                "In preview mode, all HTML emails are stored and viewable in the Notification Center."
            )
        }

    def create_incident_email(self, incident_data: Dict[str, Any], recipient: Optional[str] = None) -> Dict[str, str]:
        recipient = recipient or settings.GMAIL_DEFAULT_RECIPIENT
        title = incident_data.get("title", "Cyber Threat Intelligence Advisory")
        severity = incident_data.get("severity", "MEDIUM")
        org = incident_data.get("affected_organization") or "Undisclosed Organization"
        summary = incident_data.get("summary") or "Investigation completed."
        root_cause = incident_data.get("root_cause_analysis") or "Under investigation."
        iocs = incident_data.get("iocs", [])
        ioas = incident_data.get("ioas", [])
        techniques = incident_data.get("techniques", [])
        recommendations = incident_data.get("recommendations", [])
        source_url = incident_data.get("source_url") or "https://cisa.gov"

        severity_color = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#16a34a"
        }.get(severity, "#2563eb")

        # HTML Email formatting
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }}
            .container {{ max-width: 680px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow: hidden; }}
            .header {{ background-color: #090d16; padding: 24px; border-bottom: 2px solid {severity_color}; }}
            .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; background-color: {severity_color}; color: #ffffff; }}
            .content {{ padding: 24px; }}
            h1 {{ font-size: 20px; margin: 12px 0 0 0; color: #ffffff; }}
            h2 {{ font-size: 16px; margin: 20px 0 10px 0; border-bottom: 1px solid #334155; padding-bottom: 6px; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px; }}
            p {{ line-height: 1.6; color: #cbd5e1; font-size: 14px; margin: 8px 0; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
            th, td {{ border: 1px solid #334155; padding: 8px 10px; text-align: left; }}
            th {{ background-color: #0f172a; color: #94a3b8; }}
            td {{ background-color: #1e293b; font-family: monospace; color: #e2e8f0; }}
            .footer {{ background-color: #090d16; padding: 16px 24px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #334155; }}
            .btn {{ display: inline-block; padding: 10px 18px; background-color: #2563eb; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: bold; margin-top: 16px; }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <span class="badge">{severity} SEVERITY</span>
              <h1>{title}</h1>
              <p style="color: #94a3b8; margin-top: 4px;">Target Entity: <strong style="color: #ffffff;">{org}</strong></p>
            </div>
            <div class="content">
              <h2>Executive Summary</h2>
              <p>{summary}</p>

              <h2>Root Cause & Attack Analysis</h2>
              <p>{root_cause}</p>

              <h2>Indicators of Attack (IOA) - Behavioral Patterns</h2>
              <table>
                <tr><th>Type</th><th>Adversary Behavior Pattern</th><th>Detection Logic</th></tr>
                {"".join(f"<tr><td><span style='color: #f59e0b; font-weight: bold;'>{a.get('ioa_type','')}</span></td><td style='font-family: sans-serif;'><strong>{a.get('pattern_name','')}</strong><br/><span style='color: #94a3b8; font-size: 11px;'>{a.get('observed_behavior','')}</span></td><td style='color: #38bdf8; font-size: 11px;'>{a.get('detection_logic','')}</td></tr>" for a in ioas) if ioas else "<tr><td colspan='3'>No distinct behavioral IOAs identified.</td></tr>"}
              </table>

              <h2>MITRE ATT&CK Mappings</h2>
              <table>
                <tr><th>Technique ID</th><th>Name / Behavior</th><th>Status</th></tr>
                {"".join(f"<tr><td>{t.get('technique_id','')}</td><td>{t.get('name', '')} - {t.get('supporting_behavior','')}</td><td>{'Confirmed' if t.get('is_confirmed') else 'Hypothetical'}</td></tr>" for t in techniques) if techniques else "<tr><td colspan='3'>No explicit ATT&CK techniques verified.</td></tr>"}
              </table>

              <h2>Extracted Indicators of Compromise (Defanged)</h2>
              <table>
                <tr><th>Type</th><th>Value (Safe)</th><th>Context</th></tr>
                {"".join(f"<tr><td>{i.get('ioc_type','').upper()}</td><td>{i.get('defanged_value','')}</td><td>{i.get('context_role','')}</td></tr>" for i in iocs[:15]) if iocs else "<tr><td colspan='3'>No network or host IOCs extracted.</td></tr>"}
              </table>

              <h2>Recommended Mitigations</h2>
              <ul>
                {"".join(f"<li style='color: #cbd5e1; margin-bottom: 6px;'><strong style='color: #38bdf8;'>[{r.get('category','GENERAL')}]</strong> {r.get('title','')}: {r.get('action_items','')}</li>" for r in recommendations) if recommendations else "<li>Apply standard vulnerability patching and credential rotation.</li>"}
              </ul>

              <p style="margin-top: 20px;"><strong>Verified Source Evidence:</strong> <a href="{source_url}" style="color: #38bdf8;">{source_url}</a></p>
            </div>
            <div class="footer">
              SOC Swarm CTI · Automated Multi-Agent Cybersecurity Intelligence · Provenance Verified
            </div>
          </div>
        </body>
        </html>
        """

        # Plain text alternative
        plain = f"""[SOC SWARM CTI ADVISORY]
==================================================
Title: {title}
Severity: {severity}
Target: {org}
Source URL: {source_url}
==================================================

EXECUTIVE SUMMARY:
{summary}

ROOT CAUSE & INITIAL ACCESS:
{root_cause}

INDICATORS OF ATTACK (IOA):
""" + "\n".join([f"- [{a.get('ioa_type','')}] {a.get('pattern_name','')}: {a.get('observed_behavior','')}\n  Detection: {a.get('detection_logic','')}" for a in ioas]) + """

MITRE ATT&CK TTPs:
""" + "\n".join([f"- [{t.get('technique_id','')}] {t.get('name','')}: {t.get('supporting_behavior','')}" for t in techniques]) + """

INDICATORS OF COMPROMISE (DEFANGED):
""" + "\n".join([f"- [{i.get('ioc_type','').upper()}] {i.get('defanged_value','')} ({i.get('context_role','')})" for i in iocs[:15]]) + """

DEFENSIVE RECOMMENDATIONS:
""" + "\n".join([f"- [{r.get('category','')}] {r.get('title','')}: {r.get('action_items','')}" for r in recommendations]) + """

==================================================
Generated by SOC Swarm CTI Multi-Agent Platform
"""
        subject = f"[{severity} CTI ALERT] {title}"
        return {
            "recipient": recipient,
            "subject": subject,
            "html": html,
            "plain": plain
        }

    async def send_email(self, recipient: str, subject: str, html_content: str, plain_content: str) -> Dict[str, Any]:
        """Sends email via Gmail API if token exists; otherwise logs preview mode."""
        if not os.path.exists(self.token_file):
            return {
                "status": "PREVIEW_ONLY",
                "message_id": f"preview-{int(datetime.datetime.now().timestamp())}",
                "detail": "Gmail token.json not configured. Email formatted and stored for interactive preview in Notification Center."
            }

        try:
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build

            creds = Credentials.from_authorized_user_file(self.token_file, ["https://www.googleapis.com/auth/gmail.send"])
            service = build("gmail", "v1", credentials=creds)

            message = MIMEMultipart("alternative")
            message["to"] = recipient
            message["subject"] = subject
            message.attach(MIMEText(plain_content, "plain"))
            message.attach(MIMEText(html_content, "html"))

            raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
            sent = service.users().messages().send(userId="me", body={"raw": raw}).execute()
            return {
                "status": "SENT",
                "message_id": sent.get("id"),
                "detail": "Successfully delivered via Gmail API."
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "error": str(e),
                "detail": f"Error delivering to Gmail API: {e}"
            }

gmail_service = GmailNotificationService()
