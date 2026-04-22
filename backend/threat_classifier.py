"""AEGIS Threat Classifier — MITRE ATT&CK mapping and severity scoring."""

# MITRE ATT&CK Lookup Table
MITRE_TECHNIQUES = {
    "Brute Force": {
        "code": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts to gain access by systematically trying passwords or credentials."
    },
    "Port Scan": {
        "code": "T1046",
        "technique": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversary scans for open ports and services to identify attack vectors."
    },
    "Data Exfiltration": {
        "code": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Data is exfiltrated from the network via command and control channels."
    },
    "Protocol Anomaly": {
        "code": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Unusual protocol activity suggesting command and control communication."
    },
    "Privilege Escalation": {
        "code": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversary exploits vulnerability to gain elevated privileges."
    },
    "Lateral Movement": {
        "code": "T1021",
        "technique": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversary moves through network using legitimate remote services."
    },
    "Reconnaissance": {
        "code": "T1595",
        "technique": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversary actively probes target infrastructure to gather information."
    },
    "DDoS": {
        "code": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversary attempts to overwhelm network resources to cause denial of service."
    }
}


def classify_threat(row: dict, anomaly_score: float) -> dict:
    """Classify a threat based on flow features and anomaly score."""
    threat_type = "Protocol Anomaly"  # default

    src_port = int(row.get("src_port", row.get("Source Port", 0)))
    dst_port = int(row.get("dst_port", row.get("Destination Port", 0)))
    protocol = str(row.get("protocol", row.get("Protocol", "TCP"))).upper()
    fwd_packets = int(row.get("fwd_packets", row.get("Total Fwd Packets", 0)))
    bwd_packets = int(row.get("bwd_packets", row.get("Total Backward Packets", 0)))
    flow_bytes = float(row.get("flow_bytes", row.get("Flow Bytes/s", 0)))
    flow_duration = float(row.get("flow_duration", row.get("Flow Duration", 0)))
    label = str(row.get("label", row.get("Label", "BENIGN"))).upper()

    # NEW: Extract fields for CRITICAL override (FIX-02)
    fwd_packets_per_s = float(row.get("Fwd Packets/s", row.get("fwd_packets_per_s", 0)))
    bwd_pkt_len_max = float(row.get("Bwd Packet Length Max", row.get("bwd_pkt_len_max", 0)))

    # Rule-based classification
    if "BRUTE" in label or "SSH" in label or "FTP" in label:
        threat_type = "Brute Force"
    elif "PORTSCAN" in label or "PORT" in label or "SCAN" in label:
        threat_type = "Port Scan"
    elif "EXFIL" in label or "INFILTRATION" in label:
        threat_type = "Data Exfiltration"
    elif "DOS" in label or "DDOS" in label or "HULK" in label or "SLOWLORIS" in label or "GOLDENEYE" in label:
        threat_type = "DDoS"
    elif "HEARTBLEED" in label:
        threat_type = "Privilege Escalation"
    elif "BOT" in label:
        threat_type = "Lateral Movement"
    elif "WEB" in label or "XSS" in label or "SQL" in label:
        threat_type = "Reconnaissance"
    else:
        # Feature-based classification for unknown labels
        if dst_port == 22 and fwd_packets > 10:
            threat_type = "Brute Force"
        elif fwd_packets > 50 and flow_duration < 1000:
            threat_type = "Port Scan"
        elif flow_bytes > 1000000:
            threat_type = "Data Exfiltration"
        else:
            threat_type = "Protocol Anomaly"

    mitre = MITRE_TECHNIQUES.get(threat_type, MITRE_TECHNIQUES["Protocol Anomaly"])

    # Severity scoring
    severity_score = calculate_severity(
        anomaly_score, threat_type, flow_bytes, fwd_packets,
        fwd_packets_per_s, bwd_pkt_len_max
    )

    # FIX-02: CRITICAL override — hard rules
    if fwd_packets_per_s > 10000 or bwd_pkt_len_max > 1500:
        severity_score = max(severity_score, 75)  # Force CRITICAL range

    severity = "LOW"
    if severity_score >= 66:
        severity = "CRITICAL"
    elif severity_score >= 31:
        severity = "MEDIUM"

    return {
        "threat_type": threat_type,
        "mitre_code": mitre["code"],
        "mitre_technique": mitre["technique"],
        "mitre_tactic": mitre["tactic"],
        "severity": severity,
        "severity_score": severity_score,
        "description": mitre["description"]
    }


def calculate_severity(
    anomaly_score: float, threat_type: str, flow_bytes: float,
    fwd_packets: int, fwd_packets_per_s: float = 0, bwd_pkt_len_max: float = 0
) -> int:
    """Calculate severity score 0-100 based on multiple factors."""
    base = abs(anomaly_score) * 60  # Increased from 50 to 60

    # Type multiplier — boosted for high-impact types
    type_weights = {
        "Brute Force": 1.6,
        "Data Exfiltration": 1.8,
        "DDoS": 1.7,
        "Privilege Escalation": 1.9,
        "Lateral Movement": 1.5,
        "Port Scan": 1.1,
        "Protocol Anomaly": 1.0,
        "Reconnaissance": 0.9
    }
    multiplier = type_weights.get(threat_type, 1.0)

    # Volume factor — increased caps
    volume_factor = min(flow_bytes / 300000, 1.0) * 20
    packet_factor = min(fwd_packets / 50, 1.0) * 15

    # NEW: High-velocity factor (Fwd Packets/s)
    velocity_factor = 0
    if fwd_packets_per_s > 10000:
        velocity_factor = 25
    elif fwd_packets_per_s > 5000:
        velocity_factor = 15
    elif fwd_packets_per_s > 1000:
        velocity_factor = 8

    # NEW: Large packet factor (Bwd Packet Length Max)
    large_pkt_factor = 0
    if bwd_pkt_len_max > 1500:
        large_pkt_factor = 20
    elif bwd_pkt_len_max > 800:
        large_pkt_factor = 10
    elif bwd_pkt_len_max > 400:
        large_pkt_factor = 5

    score = int(base * multiplier + volume_factor + packet_factor + velocity_factor + large_pkt_factor)
    return max(1, min(100, score))
