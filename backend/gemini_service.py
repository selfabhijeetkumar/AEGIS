"""AEGIS Gemini Service — AI intelligence briefing generation (mock + real)."""
import os
import json
from typing import List

# Set to True when Gemini API key is available
USE_REAL_GEMINI = True
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyB0AHXd8NfIeofhYaGXlM8Cr1ULiM8AGFc")


def generate_commander_brief(scan_stats: dict) -> dict:
    """Generate 3-line military-tone commander's brief."""
    if USE_REAL_GEMINI and GEMINI_API_KEY:
        return _real_commander_brief(scan_stats)
    return _mock_commander_brief(scan_stats)


def generate_threat_explanation(threat: dict, use_mock: bool = False) -> dict:
    """Generate AI explanation + recommended actions for a threat."""
    if USE_REAL_GEMINI and GEMINI_API_KEY and not use_mock:
        return _real_threat_explanation(threat)
    return _mock_threat_explanation(threat)


def _mock_commander_brief(stats: dict) -> dict:
    """Generate realistic mock commander's brief."""
    total = stats.get("total_threats", 0)
    critical = stats.get("critical_count", 0)
    types = stats.get("attack_types", {})
    unique_ips = stats.get("unique_ips", 0)
    top_type = max(types, key=types.get) if types else "Unknown"

    lines = [
        f"Network analysis reveals {total} threat events across {len(types)} attack categories. "
        f"{critical} classified CRITICAL requiring immediate response.",
        f"Primary vector: {top_type} ({MITRE_CODES.get(top_type, 'T0000')}) from {unique_ips} "
        f"unique external IP addresses. Attack pattern consistent with coordinated reconnaissance operation.",
        f"Immediate containment recommended for all CRITICAL-classified source IPs. "
        f"Estimated compromise window: {stats.get('first_timestamp', '02:31')}–{stats.get('last_timestamp', '04:17')} UTC. "
        f"Lateral movement indicators detected — full network audit advised."
    ]
    return {"lines": lines}


def _mock_threat_explanation(threat: dict) -> dict:
    """Generate realistic mock AI explanation for a threat."""
    explanations = {
        "Brute Force": {
            "explanation": (
                f"Detected systematic credential access attempt from {threat.get('source_ip', 'unknown')} "
                f"targeting authentication services. The attack pattern shows {threat.get('bytes_transferred', 0):,} bytes "
                f"of traffic characteristic of automated password spraying tools. "
                f"Source IP geolocation indicates origin from {threat.get('country', 'unknown territory')}. "
                f"Attack velocity and pattern consistency suggest use of Hydra or similar brute-force framework. "
                f"This technique maps to MITRE ATT&CK {threat.get('mitre_code', 'T1110')} — {threat.get('mitre_technique', 'Brute Force')}."
            ),
            "actions": [
                "Immediately block source IP at perimeter firewall",
                "Force password reset for all targeted accounts",
                "Enable account lockout policy after 5 failed attempts",
                "Deploy multi-factor authentication on all external-facing services"
            ]
        },
        "Port Scan": {
            "explanation": (
                f"Network reconnaissance activity detected from {threat.get('source_ip', 'unknown')}. "
                f"Sequential port scanning pattern identified across multiple service ports. "
                f"Scan characteristics indicate use of Nmap SYN scan or equivalent tool with "
                f"{threat.get('bytes_transferred', 0):,} bytes of probe traffic. "
                f"This is typically a precursor to targeted exploitation attempts. "
                f"Technique classified as MITRE ATT&CK {threat.get('mitre_code', 'T1046')} — Network Service Scanning."
            ),
            "actions": [
                "Add source IP to network monitoring watchlist",
                "Review and restrict unnecessary open ports",
                "Enable IDS/IPS signatures for scan detection",
                "Conduct vulnerability assessment on discovered open services"
            ]
        },
        "Data Exfiltration": {
            "explanation": (
                f"Anomalous outbound data transfer detected to {threat.get('source_ip', 'unknown')}. "
                f"Transfer volume of {threat.get('bytes_transferred', 0):,} bytes significantly exceeds baseline "
                f"for this network segment. Data flow pattern suggests staged extraction via "
                f"established channel rather than bulk transfer. "
                f"Potential compromise of sensitive data assets. "
                f"Mapped to MITRE ATT&CK {threat.get('mitre_code', 'T1041')} — Exfiltration Over C2 Channel."
            ),
            "actions": [
                "Immediately isolate affected host from network",
                "Capture and preserve forensic disk image",
                "Analyze transferred data for classification level",
                "Initiate data breach response protocol"
            ]
        },
        "Protocol Anomaly": {
            "explanation": (
                f"Unusual protocol behavior detected involving {threat.get('source_ip', 'unknown')}. "
                f"Traffic pattern on non-standard port deviates from established baseline. "
                f"Analysis indicates potential covert channel or tunneling activity with "
                f"{threat.get('bytes_transferred', 0):,} bytes transferred. "
                f"Protocol anomalies may indicate command and control communications. "
                f"Classified under MITRE ATT&CK {threat.get('mitre_code', 'T1071')} — Application Layer Protocol."
            ),
            "actions": [
                "Deep packet inspection on flagged traffic flows",
                "Whitelist known legitimate protocol usage",
                "Monitor source IP for additional anomalous activity",
                "Update network baseline profiles"
            ]
        },
        "DDoS": {
            "explanation": (
                f"Volumetric attack detected from {threat.get('source_ip', 'unknown')} generating "
                f"excessive traffic volume of {threat.get('bytes_transferred', 0):,} bytes. "
                f"Attack pattern consistent with application-layer flooding technique. "
                f"Traffic analysis shows abnormal request rates targeting critical services. "
                f"Impact assessment indicates potential service degradation. "
                f"Mapped to MITRE ATT&CK {threat.get('mitre_code', 'T1498')} — Network Denial of Service."
            ),
            "actions": [
                "Activate DDoS mitigation protocols immediately",
                "Rate-limit traffic from identified source ranges",
                "Engage CDN/WAF anti-DDoS capabilities",
                "Notify upstream ISP for traffic scrubbing if volume escalates"
            ]
        },
        "Privilege Escalation": {
            "explanation": (
                f"Potential privilege escalation attempt detected from {threat.get('source_ip', 'unknown')}. "
                f"Exploit pattern targeting known vulnerability in exposed service. "
                f"Traffic analysis reveals {threat.get('bytes_transferred', 0):,} bytes of crafted payload data. "
                f"Successful exploitation could grant adversary elevated system access. "
                f"Immediate patching and access review required. "
                f"Technique classified as MITRE ATT&CK {threat.get('mitre_code', 'T1068')}."
            ),
            "actions": [
                "Patch vulnerable service immediately",
                "Audit all privileged account access logs",
                "Implement least-privilege access policies",
                "Deploy endpoint detection and response (EDR) on affected hosts"
            ]
        },
        "Lateral Movement": {
            "explanation": (
                f"Internal network traversal detected from compromised host {threat.get('source_ip', 'unknown')}. "
                f"Movement pattern using legitimate remote service protocols. "
                f"Data volume of {threat.get('bytes_transferred', 0):,} bytes across internal segments. "
                f"Adversary appears to be mapping internal network topology and accessing additional hosts. "
                f"Indicates post-exploitation phase of attack lifecycle. "
                f"Mapped to MITRE ATT&CK {threat.get('mitre_code', 'T1021')} — Remote Services."
            ),
            "actions": [
                "Isolate compromised hosts from network immediately",
                "Reset credentials for all accounts accessed from compromised hosts",
                "Implement network micro-segmentation",
                "Deploy deception technology (honeypots) on lateral movement paths"
            ]
        },
        "Reconnaissance": {
            "explanation": (
                f"Active reconnaissance activity detected from {threat.get('source_ip', 'unknown')}. "
                f"Probing pattern targets web application endpoints and exposed services. "
                f"Traffic volume of {threat.get('bytes_transferred', 0):,} bytes with scanning characteristics. "
                f"Adversary gathering intelligence on application stack and potential entry points. "
                f"Typically precedes targeted exploitation campaign. "
                f"Classified under MITRE ATT&CK {threat.get('mitre_code', 'T1595')} — Active Scanning."
            ),
            "actions": [
                "Enable web application firewall (WAF) rules",
                "Review and hide unnecessary server information headers",
                "Implement rate limiting on all public endpoints",
                "Monitor for follow-up exploitation attempts from same source range"
            ]
        }
    }

    threat_type = threat.get("threat_type", "Protocol Anomaly")
    data = explanations.get(threat_type, explanations["Protocol Anomaly"])

    return {
        "ai_explanation": data["explanation"],
        "recommended_actions": data["actions"]
    }


# Quick lookup for mock brief
MITRE_CODES = {
    "Brute Force": "T1110",
    "Port Scan": "T1046",
    "Data Exfiltration": "T1041",
    "Protocol Anomaly": "T1071",
    "Privilege Escalation": "T1068",
    "Lateral Movement": "T1021",
    "DDoS": "T1498",
    "Reconnaissance": "T1595"
}


def _real_commander_brief(stats: dict) -> dict:
    """Generate real commander's brief using Gemini API."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.0-flash")
        prompt = f"""You are AEGIS, a military-grade threat intelligence AI. Generate exactly 3 lines for a Commander's Brief based on these scan statistics. Use military tone — precise, factual, urgent. No exclamation points. Each line is one sentence.

Stats: {json.dumps(stats)}

Format: Return exactly 3 lines separated by newlines. No numbering, no bullets."""
        response = model.generate_content(prompt)
        lines = [l.strip() for l in response.text.strip().split("\n") if l.strip()][:3]
        return {"lines": lines}
    except Exception:
        return _mock_commander_brief(stats)


def _real_threat_explanation(threat: dict) -> dict:
    """Generate real threat explanation using Gemini API."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.0-flash")
        prompt = f"""You are AEGIS threat intelligence AI. Analyze this threat event and provide:
1. A 4-6 sentence plain English explanation of what happened, why it's suspicious, and potential impact.
2. A list of 3-4 recommended defensive actions.

Threat details: {json.dumps(threat)}

Format your response as JSON: {{"ai_explanation": "...", "recommended_actions": ["action1", "action2", ...]}}"""
        response = model.generate_content(prompt)
        return json.loads(response.text.strip().replace("```json", "").replace("```", ""))
    except Exception:
        return _mock_threat_explanation(threat)
