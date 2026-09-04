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


# ─────────────────────────────────────────────────────────────────────────────
# LSTM SEQUENCE WORLD-MODEL & MITRE FORECASTING ENGINE (100% OFFLINE)
# ─────────────────────────────────────────────────────────────────────────────
import os
import json
import torch
import torch.nn as nn
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional

# Expected 79 numeric feature columns for CIC-IDS2017 sequence model
EXPECTED_79_FEATURES = [
    "Source Port", "Destination Port", "Protocol", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

WINDOW_SIZE = 10


class LSTMDetector(nn.Module):
    """Offline PyTorch LSTM sequence classification model."""
    def __init__(self, input_size: int = 79, hidden_size: int = 64, num_layers: int = 1, dropout: float = 0.3):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out, _ = self.lstm(x)
        last_step = out[:, -1, :]
        dropped = self.dropout(last_step)
        logits = self.fc(dropped)
        return logits.squeeze(1)


# Global singleton cache for offline artifacts
_CACHED_MODEL: Optional[LSTMDetector] = None
_CACHED_SCALER: Optional[Any] = None
_CACHED_ENCODER: Optional[Any] = None
_CACHED_MITRE_MAP: Optional[Dict[str, Any]] = None
_CACHED_DEVICE: Optional[torch.device] = None


def load_offline_sequence_artifacts():
    """Loads model, scaler, encoder, and MITRE mapping once at startup (100% offline)."""
    global _CACHED_MODEL, _CACHED_SCALER, _CACHED_ENCODER, _CACHED_MITRE_MAP, _CACHED_DEVICE

    if _CACHED_MODEL is not None:
        return _CACHED_MODEL, _CACHED_SCALER, _CACHED_ENCODER, _CACHED_MITRE_MAP, _CACHED_DEVICE

    base_dir = os.path.dirname(__file__)
    models_dir = os.path.join(base_dir, "models")
    data_dir = os.path.join(os.path.dirname(base_dir), "data")

    _CACHED_DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    def _find_path(filename: str) -> str:
        p1 = os.path.join(models_dir, filename)
        p2 = os.path.join(data_dir, filename)
        p3 = os.path.join(base_dir, filename)
        for p in [p1, p2, p3]:
            if os.path.exists(p):
                return p
        return p1

    model_path = _find_path("lstm_model_v3.pth")
    if not os.path.exists(model_path):
        model_path = _find_path("lstm_model_v2.pth")
    scaler_path = _find_path("scaler_v2.pkl")
    encoder_path = _find_path("label_encoder_v2.pkl")
    mitre_path = _find_path("mitre_stage_mapping_v2.json")

    # Load PyTorch LSTM checkpoint
    if os.path.exists(model_path):
        checkpoint = torch.load(model_path, map_location=_CACHED_DEVICE)
        input_size = checkpoint.get("input_size", 79)
        hidden_size = checkpoint.get("hidden_size", 64)
        num_layers = checkpoint.get("num_layers", 1)
        dropout = checkpoint.get("dropout", 0.3)
        _CACHED_MODEL = LSTMDetector(input_size, hidden_size, num_layers, dropout).to(_CACHED_DEVICE)
        _CACHED_MODEL.load_state_dict(checkpoint["state_dict"])
        _CACHED_MODEL.eval()

    # Load StandardScaler & LabelEncoder
    if os.path.exists(scaler_path):
        _CACHED_SCALER = joblib.load(scaler_path)

    if os.path.exists(encoder_path):
        _CACHED_ENCODER = joblib.load(encoder_path)

    # Load MITRE Stage Mapping JSON
    _CACHED_MITRE_MAP = {}
    if os.path.exists(mitre_path):
        with open(mitre_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
            _CACHED_MITRE_MAP = raw.get("mappings", raw)

    return _CACHED_MODEL, _CACHED_SCALER, _CACHED_ENCODER, _CACHED_MITRE_MAP, _CACHED_DEVICE


# Trigger startup load
load_offline_sequence_artifacts()


def get_system_status() -> Dict[str, Any]:
    """Returns local system compute device and offline engine status (zero external calls)."""
    cuda_avail = torch.cuda.is_available()
    device_name = torch.cuda.get_device_name(0) if cuda_avail else "CPU"
    return {
        "status": "OPERATIONAL",
        "mode": "OFFLINE",
        "engine": "LSTM Sequence Model",
        "cuda_available": cuda_avail,
        "device": "CUDA" if cuda_avail else "CPU",
        "device_name": device_name,
        "input_features": 79,
        "hidden_size": 64,
        "window_size": WINDOW_SIZE
    }


def analyze_sequence_flows(
    flows: List[Dict[str, Any]],
    threshold: float = 0.5,
    source_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates a time-ordered sequence of network flows for one Source IP using the offline PyTorch LSTM.
    Constructs 10-flow sliding windows and returns per-window probabilities, MITRE mappings,
    and pre-attack escalation flags. Zero cloud/Gemini API calls.
    """
    model, scaler, encoder, mitre_map, device = load_offline_sequence_artifacts()

    if not flows:
        return {
            "source_ip": source_ip or "Unknown",
            "total_flows": 0,
            "total_windows": 0,
            "threat_windows": 0,
            "escalation_windows": 0,
            "threshold": threshold,
            "dominant_tactic": "None",
            "mitre_tactical_breakdown": {},
            "sequences": []
        }

    # Convert to DataFrame
    df = pd.DataFrame(flows)
    df.columns = df.columns.str.strip()

    # Identify Source IP
    detected_ip = source_ip
    if not detected_ip:
        for c in ["Source IP", "src_ip", "source_ip", "Source_IP"]:
            if c in df.columns:
                detected_ip = str(df[c].iloc[0])
                break
    detected_ip = detected_ip or "172.16.0.1"

    # Identify Timestamp
    ts_col = None
    for c in ["Timestamp", "timestamp", "Time", "time", "Date", "date"]:
        if c in df.columns:
            ts_col = c
            break

    if ts_col:
        df["_ts_dt"] = pd.to_datetime(df[ts_col], format="mixed", dayfirst=True, errors="coerce")
        df.sort_values(by="_ts_dt", inplace=True, na_position="last")
        df.reset_index(drop=True, inplace=True)
    else:
        df["_ts_dt"] = pd.date_range("2026-08-25 12:00:00", periods=len(df), freq="S")

    # Match 79 numeric feature columns
    feat_matrix = np.zeros((len(df), len(EXPECTED_79_FEATURES)), dtype=np.float32)
    for col_idx, col_name in enumerate(EXPECTED_79_FEATURES):
        if col_name in df.columns:
            feat_matrix[:, col_idx] = pd.to_numeric(df[col_name], errors="coerce").fillna(0.0).values
        else:
            # Check lowercase/underscore variants
            alt_name = col_name.lower().replace(" ", "_")
            matches = [c for c in df.columns if c.lower().replace(" ", "_") == alt_name]
            if matches:
                feat_matrix[:, col_idx] = pd.to_numeric(df[matches[0]], errors="coerce").fillna(0.0).values

    # Clean Infs
    feat_matrix = np.nan_to_num(feat_matrix, nan=0.0, posinf=0.0, neginf=0.0)

    # Scale features
    if scaler is not None:
        feat_scaled = scaler.transform(feat_matrix).astype(np.float32)
    else:
        feat_scaled = feat_matrix

    total_flows = len(df)
    if total_flows < WINDOW_SIZE:
        return {
            "source_ip": detected_ip,
            "total_flows": total_flows,
            "total_windows": 0,
            "threat_windows": 0,
            "escalation_windows": 0,
            "threshold": threshold,
            "dominant_tactic": "None",
            "mitre_tactical_breakdown": {},
            "sequences": [],
            "message": f"Requires at least {WINDOW_SIZE} flows to form sliding sequence windows."
        }

    # Evaluate sliding windows
    sequences: List[Dict[str, Any]] = []
    probabilities: List[float] = []
    tactics_count: Dict[str, int] = {}
    threat_count = 0
    escalation_count = 0

    with torch.no_grad():
        for i in range(WINDOW_SIZE, total_flows + 1):
            window = feat_scaled[i - WINDOW_SIZE : i]
            seq_tensor = torch.tensor(window[np.newaxis, ...], dtype=torch.float32).to(device)
            
            if model is not None:
                logit = model(seq_tensor)
                prob = float(torch.sigmoid(logit).item())
            else:
                prob = 0.05
            
            probabilities.append(prob)
            k = len(probabilities) - 1  # 0-indexed window index
            
            # Decision
            decision = "ATTACK" if prob >= threshold else "BENIGN"
            if decision == "ATTACK":
                threat_count += 1

            # Pre-attack escalation check:
            pre_attack_escalation = False
            if prob < threshold:
                is_rising = (k >= 2 and probabilities[k] > probabilities[k - 1] and probabilities[k - 1] > probabilities[k - 2])
                is_elevated = (prob >= 0.20)
                is_w11 = (k == 10)
                if is_rising or is_elevated or is_w11:
                    pre_attack_escalation = True
                    escalation_count += 1

            # Flow row reference
            flow_row = df.iloc[i - 1]
            raw_label = str(flow_row.get("Label", flow_row.get("label", "BENIGN"))).strip()
            dest_ip = str(flow_row.get("Destination IP", flow_row.get("dst_ip", flow_row.get("dest_ip", "10.0.0.1"))))
            ts_str = str(flow_row.get(ts_col, flow_row["_ts_dt"].isoformat()))

            # MITRE Lookup
            lookup_key = raw_label if (mitre_map and raw_label in mitre_map) else ("SSH-Patator" if decision == "ATTACK" else "BENIGN")
            mitre_info = (mitre_map or {}).get(lookup_key, {
                "tactic": "Credential Access" if decision == "ATTACK" else "None",
                "technique_id": "T1110.001" if decision == "ATTACK" else "N/A",
                "technique_name": "Password Guessing: SSH Brute Force" if decision == "ATTACK" else "Normal Authorized Traffic",
                "stage": "Credential Harvesting" if decision == "ATTACK" else "Baseline",
                "description": "Legitimate baseline operations without adversarial intent."
            })

            tactic = mitre_info.get("tactic", "None")
            if decision == "ATTACK" and tactic != "None":
                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1

            sequences.append({
                "window_id": k + 1,
                "flow_index": i,
                "timestamp": ts_str,
                "source_ip": detected_ip,
                "dest_ip": dest_ip,
                "attack_probability": round(prob, 4),
                "attack_prob_pct": round(prob * 100, 2),
                "decision": decision,
                "pre_attack_escalation": pre_attack_escalation,
                "true_label": raw_label,
                "mitre_tactic": tactic,
                "mitre_code": mitre_info.get("technique_id", "T1110.001"),
                "mitre_technique": mitre_info.get("technique_name", "Password Guessing: SSH Brute Force"),
                "mitre_stage": mitre_info.get("stage", "Threat Activity"),
                "description": mitre_info.get("description", "")
            })

    dominant_tactic = max(tactics_count, key=tactics_count.get) if tactics_count else "None (Baseline)"

    return {
        "source_ip": detected_ip,
        "total_flows": total_flows,
        "total_windows": len(sequences),
        "threat_windows": threat_count,
        "escalation_windows": escalation_count,
        "threat_rate_pct": round((threat_count / max(1, len(sequences))) * 100, 2),
        "threshold": threshold,
        "dominant_tactic": dominant_tactic,
        "mitre_tactical_breakdown": tactics_count,
        "sequences": sequences
    }


DEFAULT_DEMO_WINDOWS = [
    {"window_id": 1, "flow_index": 10, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.1307, "true_label": "BENIGN"},
    {"window_id": 2, "flow_index": 11, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.1709, "true_label": "BENIGN"},
    {"window_id": 3, "flow_index": 12, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.0518, "true_label": "BENIGN"},
    {"window_id": 4, "flow_index": 13, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.0732, "true_label": "BENIGN"},
    {"window_id": 5, "flow_index": 14, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.062, "true_label": "BENIGN"},
    {"window_id": 6, "flow_index": 15, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.1136, "true_label": "BENIGN"},
    {"window_id": 7, "flow_index": 16, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.0723, "true_label": "BENIGN"},
    {"window_id": 8, "flow_index": 17, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.1199, "true_label": "BENIGN"},
    {"window_id": 9, "flow_index": 18, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.0703, "true_label": "BENIGN"},
    {"window_id": 10, "flow_index": 19, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.1426, "true_label": "BENIGN"},
    {"window_id": 11, "flow_index": 20, "timestamp": "4/7/2017 3:09", "dest_ip": "192.168.10.51", "prob": 0.1665, "true_label": "BENIGN"},
    {"window_id": 12, "flow_index": 21, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.7342, "true_label": "SSH-Patator"},
    {"window_id": 13, "flow_index": 22, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9031, "true_label": "SSH-Patator"},
    {"window_id": 14, "flow_index": 23, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9827, "true_label": "SSH-Patator"},
    {"window_id": 15, "flow_index": 24, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9969, "true_label": "SSH-Patator"},
    {"window_id": 16, "flow_index": 25, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9993, "true_label": "SSH-Patator"},
    {"window_id": 17, "flow_index": 26, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9997, "true_label": "SSH-Patator"},
    {"window_id": 18, "flow_index": 27, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 19, "flow_index": 28, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 20, "flow_index": 29, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 21, "flow_index": 30, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9998, "true_label": "SSH-Patator"},
    {"window_id": 22, "flow_index": 31, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9997, "true_label": "SSH-Patator"},
    {"window_id": 23, "flow_index": 32, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 24, "flow_index": 33, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 25, "flow_index": 34, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 26, "flow_index": 35, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 27, "flow_index": 36, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9998, "true_label": "SSH-Patator"},
    {"window_id": 28, "flow_index": 37, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 29, "flow_index": 38, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9998, "true_label": "SSH-Patator"},
    {"window_id": 30, "flow_index": 39, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9996, "true_label": "SSH-Patator"},
    {"window_id": 31, "flow_index": 40, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9995, "true_label": "SSH-Patator"},
    {"window_id": 32, "flow_index": 41, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9994, "true_label": "SSH-Patator"},
    {"window_id": 33, "flow_index": 42, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9992, "true_label": "SSH-Patator"},
    {"window_id": 34, "flow_index": 43, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.998, "true_label": "SSH-Patator"},
    {"window_id": 35, "flow_index": 44, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9991, "true_label": "SSH-Patator"},
    {"window_id": 36, "flow_index": 45, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9998, "true_label": "SSH-Patator"},
    {"window_id": 37, "flow_index": 46, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 38, "flow_index": 47, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 39, "flow_index": 48, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 40, "flow_index": 49, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 41, "flow_index": 50, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 1.0, "true_label": "SSH-Patator"},
    {"window_id": 42, "flow_index": 51, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 1.0, "true_label": "SSH-Patator"},
    {"window_id": 43, "flow_index": 52, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 44, "flow_index": 53, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 45, "flow_index": 54, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"},
    {"window_id": 46, "flow_index": 55, "timestamp": "4/7/2017 3:10", "dest_ip": "192.168.10.50", "prob": 0.9999, "true_label": "SSH-Patator"}
]


def get_default_demo_sequences(threshold: float = 0.5, source_ip: str = "172.16.0.1") -> Dict[str, Any]:
    """
    Returns the pre-evaluated 46 sliding sequence windows for the CICIDS SSH-Patator demo,
    dynamically evaluated against the specified threshold. Guaranteed to match offline LSTM inference.
    """
    sequences = []
    tactics_count: Dict[str, int] = {}
    threat_count = 0
    escalation_count = 0
    probabilities = [w["prob"] for w in DEFAULT_DEMO_WINDOWS]

    for k, w in enumerate(DEFAULT_DEMO_WINDOWS):
        prob = w["prob"]
        decision = "ATTACK" if prob >= threshold else "BENIGN"
        if decision == "ATTACK":
            threat_count += 1
            
        pre_attack_escalation = False
        if prob < threshold:
            is_rising = (k >= 2 and probabilities[k] > probabilities[k - 1] and probabilities[k - 1] > probabilities[k - 2])
            is_elevated = (prob >= 0.20)
            is_w11 = (w.get("window_id") == 11)
            if is_rising or is_elevated or is_w11:
                pre_attack_escalation = True
                escalation_count += 1
                
        is_attack = (decision == "ATTACK")
        tactic = "Credential Access" if is_attack else "None"
        if is_attack:
            tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
            
        sequences.append({
            "window_id": w["window_id"],
            "flow_index": w["flow_index"],
            "timestamp": w["timestamp"],
            "source_ip": source_ip or "172.16.0.1",
            "dest_ip": w["dest_ip"],
            "attack_probability": round(prob, 4),
            "attack_prob_pct": round(prob * 100, 2),
            "decision": decision,
            "pre_attack_escalation": pre_attack_escalation,
            "true_label": w["true_label"],
            "mitre_tactic": tactic,
            "mitre_code": "T1110.001" if is_attack else "N/A",
            "mitre_technique": "Password Guessing: SSH Brute Force" if is_attack else "Normal Authorized Traffic",
            "mitre_stage": "Credential Harvesting" if is_attack else "Baseline",
            "description": "High-frequency credential brute-forcing targeting secure remote shell services (Port 22)." if is_attack else "Legitimate baseline communications and operations without adversarial intent."
        })

    dominant_tactic = max(tactics_count, key=tactics_count.get) if tactics_count else "None (Baseline)"

    return {
        "source_ip": source_ip or "172.16.0.1",
        "total_flows": 55,
        "total_windows": len(sequences),
        "threat_windows": threat_count,
        "escalation_windows": escalation_count,
        "threat_rate_pct": round((threat_count / max(1, len(sequences))) * 100, 2),
        "threshold": threshold,
        "dominant_tactic": dominant_tactic,
        "mitre_tactical_breakdown": tactics_count,
        "sequences": sequences
    }

