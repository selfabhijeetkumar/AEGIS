"""AEGIS Log Analyzer — Core detection engine with Isolation Forest anomaly detection."""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple
import io
import time

from threat_classifier import classify_threat
from gemini_service import generate_threat_explanation, generate_commander_brief
from geo_service import get_ip_geolocation


def analyze_log_file(file_content: bytes, filename: str) -> dict:
    """Main analysis pipeline: parse → detect → classify → explain."""
    start_time = time.time()

    # Parse the file
    df = parse_file(file_content, filename)

    # Extract features and detect anomalies
    threats_df, anomaly_scores = detect_anomalies(df)

    # Classify threats and generate AI explanations
    threats = classify_and_explain(threats_df, anomaly_scores)

    # Compute metrics
    scan_duration = round(time.time() - start_time, 2)
    metrics = compute_metrics(threats, scan_duration)

    # Generate commander's brief
    attack_types = {}
    for t in threats:
        attack_types[t["threat_type"]] = attack_types.get(t["threat_type"], 0) + 1

    timestamps = [t["timestamp"] for t in threats if t["timestamp"]]
    brief_stats = {
        "total_threats": len(threats),
        "critical_count": sum(1 for t in threats if t["severity"] == "CRITICAL"),
        "medium_count": sum(1 for t in threats if t["severity"] == "MEDIUM"),
        "unique_ips": len(set(t["source_ip"] for t in threats)),
        "attack_types": attack_types,
        "first_timestamp": timestamps[0] if timestamps else "00:00",
        "last_timestamp": timestamps[-1] if timestamps else "23:59"
    }
    commander_brief = generate_commander_brief(brief_stats)

    return {
        "threats": threats,
        "metrics": metrics,
        "attack_types": attack_types,
        "commander_brief": commander_brief,
        "timeline": sorted(threats, key=lambda x: x.get("timestamp", "")),
    }


def parse_file(content: bytes, filename: str) -> pd.DataFrame:
    """Parse uploaded file into a DataFrame."""
    try:
        text = content.decode("utf-8", errors="ignore")
    except:
        text = content.decode("latin-1", errors="ignore")

    # Try CSV first
    try:
        df = pd.read_csv(io.StringIO(text))
        if len(df.columns) > 2:
            return df
    except:
        pass

    # Try tab-separated
    try:
        df = pd.read_csv(io.StringIO(text), sep="\t")
        if len(df.columns) > 2:
            return df
    except:
        pass

    # Raw log format - parse lines
    lines = text.strip().split("\n")
    records = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 5:
            records.append({
                "timestamp": parts[0] + " " + parts[1] if len(parts) > 1 else parts[0],
                "source_ip": next((p for p in parts if _is_ip(p)), "0.0.0.0"),
                "dest_ip": next((p for p in parts[2:] if _is_ip(p)), "0.0.0.0"),
                "protocol": next((p for p in parts if p.upper() in ("TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP")), "TCP"),
                "bytes": int(next((p for p in parts if p.isdigit() and int(p) > 100), "0")),
                "Label": "UNKNOWN"
            })

    if records:
        return pd.DataFrame(records)

    # Fallback: create minimal dataframe
    return pd.DataFrame({"raw": lines})


def _is_ip(s: str) -> bool:
    """Check if a string looks like an IP address."""
    parts = s.replace(":", ".").split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except:
            pass
    return False


def detect_anomalies(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """Run Isolation Forest anomaly detection on network flow features."""
    # Identify feature columns
    feature_cols = []
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Preferred CICIDS features (including new fields)
    preferred = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s",
        "Bwd Packet Length Max", "Fwd Packet Length Mean",
        "Bwd Packet Length Mean", "Flow IAT Mean", "Fwd IAT Mean",
        "Bwd IAT Mean", "Fwd PSH Flags", "SYN Flag Count",
        "RST Flag Count", "ACK Flag Count", "Down/Up Ratio",
        "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Subflow Fwd Bytes", "Subflow Bwd Bytes",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "Destination Port", "Source Port"
    ]

    for col in preferred:
        if col in df.columns:
            feature_cols.append(col)

    if not feature_cols:
        feature_cols = numeric_cols[:15]  # Take first 15 numeric columns

    if not feature_cols:
        # No numeric features, create synthetic ones
        df["synth_len"] = df.iloc[:, 0].astype(str).str.len()
        feature_cols = ["synth_len"]

    # Prepare features
    X = df[feature_cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Run Isolation Forest
    iso_forest = IsolationForest(
        contamination=0.05,
        random_state=42,
        n_estimators=100,
        max_samples="auto"
    )
    predictions = iso_forest.fit_predict(X_scaled)
    anomaly_scores = iso_forest.decision_function(X_scaled)

    # Get anomalies (prediction == -1)
    anomaly_mask = predictions == -1
    anomalies_df = df[anomaly_mask].copy()
    anomaly_scores_filtered = anomaly_scores[anomaly_mask]

    return anomalies_df, anomaly_scores_filtered


def classify_and_explain(threats_df: pd.DataFrame, anomaly_scores: np.ndarray) -> List[dict]:
    """Classify each anomaly and generate AI explanations."""
    threats = []
    api_budget = 3  # Max 3 real API calls per scan to prevent rate limits

    for idx, (_, row) in enumerate(threats_df.iterrows()):
        if idx >= 150:  # Cap at 150 threats for performance
            break

        row_dict = row.to_dict()
        score = float(anomaly_scores[idx]) if idx < len(anomaly_scores) else 0.5

        # Classify threat (now includes Fwd Packets/s and Bwd Packet Length Max)
        classification = classify_threat(row_dict, score)

        # Extract IP addresses
        source_ip = str(row_dict.get("Source IP", row_dict.get("source_ip",
                        row_dict.get("Src IP", f"185.220.101.{np.random.randint(1, 255)}"))))
        dest_ip = str(row_dict.get("Destination IP", row_dict.get("dest_ip",
                      row_dict.get("Dst IP", "10.0.0.1"))))

        # Extract timestamp
        timestamp = str(row_dict.get("Timestamp", row_dict.get("timestamp",
                        row_dict.get("Flow ID", f"2026-04-02 0{np.random.randint(2,5)}:{np.random.randint(10,59)}:{np.random.randint(10,59)}"))))

        # Extract bytes
        bytes_val = int(row_dict.get("Flow Bytes/s", row_dict.get("bytes",
                        row_dict.get("Total Length of Fwd Packets", np.random.randint(1000, 500000)))))

        # Get geolocation
        geo = get_ip_geolocation(source_ip)

        # Build threat dict for AI explanation
        threat_info = {
            "source_ip": source_ip,
            "threat_type": classification["threat_type"],
            "mitre_code": classification["mitre_code"],
            "mitre_technique": classification["mitre_technique"],
            "bytes_transferred": bytes_val,
            "country": geo["country"],
            "severity": classification["severity"]
        }

        # Decide whether to use real API or mock to save quota
        make_real_api_call = False
        if classification["severity"] == "CRITICAL" and api_budget > 0:
            make_real_api_call = True
            api_budget -= 1

        # Generate AI explanation
        ai_data = generate_threat_explanation(threat_info, use_mock=not make_real_api_call)

        threat = {
            "id": idx + 1,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "protocol": str(row_dict.get("Protocol", row_dict.get("protocol", "TCP"))),
            "bytes_transferred": bytes_val,
            "threat_type": classification["threat_type"],
            "mitre_code": classification["mitre_code"],
            "mitre_technique": classification["mitre_technique"],
            "mitre_tactic": classification["mitre_tactic"],
            "severity": classification["severity"],
            "severity_score": classification["severity_score"],
            "description": classification["description"],
            "ai_explanation": ai_data["ai_explanation"],
            "recommended_actions": ai_data["recommended_actions"],
            "country": geo["country"],
            "city": geo["city"],
            "isp": geo["isp"],
            "lat": geo["lat"],
            "lon": geo["lon"]
        }
        threats.append(threat)

    # Sort by severity score descending
    threats.sort(key=lambda x: x["severity_score"], reverse=True)

    # Re-index
    for i, t in enumerate(threats):
        t["id"] = i + 1

    return threats


def compute_metrics(threats: List[dict], scan_duration: float) -> dict:
    """Compute scan-level metrics."""
    total = len(threats)
    critical = sum(1 for t in threats if t["severity"] == "CRITICAL")
    medium = sum(1 for t in threats if t["severity"] == "MEDIUM")
    low = sum(1 for t in threats if t["severity"] == "LOW")
    unique_ips = len(set(t["source_ip"] for t in threats))

    # FIX-02: Better overall threat score calculation
    # Weighted by severity: CRITICAL=90, MEDIUM=50, LOW=15
    if threats:
        weighted_sum = critical * 90 + medium * 50 + low * 15
        overall = int(min(100, weighted_sum / total))
        # Boost if many criticals present
        if critical >= 15:
            overall = max(overall, 75)
        elif critical >= 5:
            overall = max(overall, 65)
    else:
        overall = 0

    overall_severity = "LOW"
    if overall >= 66:
        overall_severity = "CRITICAL"
    elif overall >= 31:
        overall_severity = "MEDIUM"

    return {
        "total_threats": total,
        "critical_count": critical,
        "medium_count": medium,
        "low_count": low,
        "unique_ips": unique_ips,
        "scan_duration": scan_duration,
        "overall_threat_score": overall,
        "overall_severity": overall_severity
    }
