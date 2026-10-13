"""Incident Response Playbook Runner & Automation Service
Implements NIST SP 800-61 Rev. 2 standardized containment, eradication, and recovery playbooks.
"""
from typing import Dict, List, Any
import datetime

PLAYBOOK_CATALOG: Dict[str, Dict[str, Any]] = {
    "ransomware": {
        "id": "playbook-ransomware",
        "title": "Ransomware Outbreak & Encryption Neutralization",
        "severity": "CRITICAL",
        "standard": "NIST SP 800-61 (Ransomware)",
        "objective": "Halt autonomous encryption, sever active C2 persistence, isolate patient-zero, and preserve forensic artifacts.",
        "steps": [
            {
                "step_number": 1,
                "phase": "Containment",
                "action": "Immediate Endpoint Isolation",
                "details": "Sever all layer-2/3 network interfaces on affected endpoints to arrest lateral propagation over SMB (TCP 445) and WMI.",
                "command_type": "powershell",
                "command": 'Disable-NetAdapter -Name "*" -Confirm:$false; Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'
            },
            {
                "step_number": 2,
                "phase": "Containment",
                "action": "Active Directory krbtgt Password Rotation",
                "details": "Perform initial emergency reset of the Kerberos Ticket Granting Service account (krbtgt) to invalidate stolen Golden Tickets.",
                "command_type": "powershell",
                "command": 'Reset-KdsRootKey; Update-ActiveDirectoryKerberosServiceTicket'
            },
            {
                "step_number": 3,
                "phase": "Containment",
                "action": "Perimeter C2 Egress Quarantine",
                "details": "Deploy boundary border firewall DROP rules against identified C2 IP addresses.",
                "command_type": "iptables",
                "command": 'iptables -I FORWARD -d {target_ip} -j DROP; iptables -I OUTPUT -d {target_ip} -j DROP'
            },
            {
                "step_number": 4,
                "phase": "Eradication",
                "action": "Terminate Malicious Parent & Child Process Trees",
                "details": "Kill staging processes (`vssadmin.exe delete shadows`, `bcdedit`, `rundll32.exe`) and isolate binaries.",
                "command_type": "bash",
                "command": 'pkill -9 -f "ransomware|encryptor|beacon"'
            },
            {
                "step_number": 5,
                "phase": "Recovery",
                "action": "Immutable Backup Verification & Air-Gapped Restore",
                "details": "Audit offline snapshot integrity before triggering cold recovery onto sanitized isolated VLANs.",
                "command_type": "manual",
                "command": "# Verify SHA-256 hash checksums of offline cold storage snapshots"
            }
        ]
    },
    "zeroday_rce": {
        "id": "playbook-zeroday-rce",
        "title": "Zero-Day Public Exploitation (RCE) Response",
        "severity": "CRITICAL",
        "standard": "CISA KEV Mitigation Directive",
        "objective": "Deploy virtual WAF shields, isolate exposed edge daemons, and apply vendor emergency patches.",
        "steps": [
            {
                "step_number": 1,
                "phase": "Identification",
                "action": "Enumerate Perimeter Exposure & Asset Inventory",
                "details": "Identify all external-facing listening sockets on the vulnerable port across all DMZ subnets.",
                "command_type": "bash",
                "command": 'ss -tulpn | grep -E "(:80|:443|:8080|:8443)"'
            },
            {
                "step_number": 2,
                "phase": "Containment",
                "action": "Deploy WAF Virtual Patch Filter",
                "details": "Inject regex inspection signature at the reverse proxy (Cloudflare/AWS WAF/Nginx) to drop crafted payload headers.",
                "command_type": "nginx",
                "command": 'if ($request_uri ~* "(%00|\\.\\./|base64_decode|cmd\\.exe|/bin/sh)") { return 403; }'
            },
            {
                "step_number": 3,
                "phase": "Containment",
                "action": "Restrict Ingress to Authorized IP Allowlist",
                "details": "Limit management and web portal ingress strictly to internal VPN egress gateways.",
                "command_type": "iptables",
                "command": 'iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT; iptables -A INPUT -p tcp --dport 443 -j DROP'
            },
            {
                "step_number": 4,
                "phase": "Eradication",
                "action": "Emergency Vendor Binary Rebuild & Hotfix",
                "details": "Pull the certified vendor patch, compile or update package, and cycle application service workers.",
                "command_type": "bash",
                "command": 'apt-get update && apt-get --only-upgrade install -y nginx apache2 openssl'
            }
        ]
    },
    "botnet_c2": {
        "id": "playbook-botnet-c2",
        "title": "Botnet C2 Beaconing & Lateral Infection Triage",
        "severity": "HIGH",
        "standard": "SANS Incident Handler's Handbook",
        "objective": "Quarantine command-and-control communication channels, identify infected hosts, and clean persistence.",
        "steps": [
            {
                "step_number": 1,
                "phase": "Identification",
                "action": "Correlate Outbound Beaconing Jitter",
                "details": "Analyze DNS and NetFlow connection intervals to confirm recurring C2 polling cycles.",
                "command_type": "zeek",
                "command": 'zeek -r traffic.pcap conn-summary.zeek | grep "{target_ip}"'
            },
            {
                "step_number": 2,
                "phase": "Containment",
                "action": "DNS Sinkholing at Internal Resolvers",
                "details": "Re-point malicious domain queries to an internal sinkhole collector (127.0.0.1) to monitor infected endpoints.",
                "command_type": "bind",
                "command": 'zone "{target_domain}" {{ type master; file "/etc/bind/db.sinkhole"; }};'
            },
            {
                "step_number": 3,
                "phase": "Containment",
                "action": "Border Gateway Protocol (BGP) Null-Routing",
                "details": "Announce blackhole route to upstream ISP for bulletproof C2 ASN blocks.",
                "command_type": "cisco",
                "command": 'ip route {target_ip} 255.255.255.255 Null0'
            },
            {
                "step_number": 4,
                "phase": "Eradication",
                "action": "Purge Scheduled Tasks & Registry Run Keys",
                "details": "Remove persistence mechanisms registered under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
                "command_type": "powershell",
                "command": 'Get-CimInstance Win32_StartupCommand | Where-Object { $_.Command -like "*powershell*" } | Remove-CimInstance'
            }
        ]
    }
}

def list_available_playbooks() -> List[Dict[str, Any]]:
    return [
        {
            "id": p["id"],
            "key": k,
            "title": p["title"],
            "severity": p["severity"],
            "standard": p["standard"],
            "step_count": len(p["steps"]),
            "objective": p["objective"]
        }
        for k, p in PLAYBOOK_CATALOG.items()
    ]

def get_playbook_run(playbook_key: str, target_ip: str = "198.51.100.44", target_domain: str = "malicious-c2.net") -> Dict[str, Any]:
    key = playbook_key.lower().replace("-", "_")
    if key not in PLAYBOOK_CATALOG:
        key = "ransomware"
        
    pb = PLAYBOOK_CATALOG[key]
    rendered_steps = []
    
    for s in pb["steps"]:
        cmd = s["command"].replace("{target_ip}", target_ip).replace("{target_domain}", target_domain)
        rendered_steps.append({
            **s,
            "command": cmd,
            "status": "ready"
        })
        
    return {
        "id": pb["id"],
        "key": key,
        "title": pb["title"],
        "severity": pb["severity"],
        "standard": pb["standard"],
        "objective": pb["objective"],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target_ip": target_ip,
        "target_domain": target_domain,
        "steps": rendered_steps
    }
