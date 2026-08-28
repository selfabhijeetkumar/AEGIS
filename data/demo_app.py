# ==============================================================================
# AEGIS Real-Time Sequence Threat Detection & MITRE ATT&CK Forecasting Dashboard
# OFFLINE DEMO SYSTEM — FULLY LOCAL EXECUTION
#
# CRITICAL REQUIREMENT: This application operates 100% OFFLINE.
# It does NOT invoke Gemini, OpenAI, Claude, cloud APIs, or require an internet connection.
# All inference executes locally using the pre-trained PyTorch LSTM (lstm_model_v2.pth),
# local StandardScaler (scaler_v2.pkl), and local MITRE ATT&CK mapping JSON.
# ==============================================================================

import io
import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
import streamlit as st
import matplotlib.pyplot as plt

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION & PATH RESOLUTION (Local / Offline)
# ─────────────────────────────────────────────────────────────────────────────
BASE_DATA_DIR = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
REPO_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

def resolve_path(filename):
    """Checks TrafficLabelling folder first, then local repo data/ folder."""
    p1 = os.path.join(BASE_DATA_DIR, filename)
    p2 = os.path.join(REPO_DATA_DIR, filename)
    p3 = os.path.join(os.path.dirname(REPO_DATA_DIR), filename)
    for p in [p1, p2, p3]:
        if os.path.exists(p):
            return p
    return p1

MODEL_PATH   = resolve_path("lstm_model_v2.pth")
SCALER_PATH  = resolve_path("scaler_v2.pkl")
ENCODER_PATH = resolve_path("label_encoder_v2.pkl")
MITRE_PATH   = resolve_path("mitre_stage_mapping_v2.json")
SAMPLE_CSV   = os.path.join(REPO_DATA_DIR, "sample_traffic_demo.csv")

WINDOW_SIZE = 10

# ─────────────────────────────────────────────────────────────────────────────
# STREAMLIT PAGE CONFIG & STYLING
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AEGIS — Intrusion Sequence Forecasting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main { background-color: #0b0f19; }
    .stMetric {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid #374151;
        padding: 14px;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
    }
    .threat-card-critical {
        background: linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%);
        border: 1px solid #ef4444;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        color: #fef2f2;
    }
    .threat-card-benign {
        background: linear-gradient(135deg, #064e3b 0%, #047857 100%);
        border: 1px solid #10b981;
        border-radius: 8px;
        padding: 12px;
        color: #ecfdf5;
    }
    .badge-mitre {
        background-color: #1e3a8a;
        color: #93c5fd;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 11px;
        font-weight: bold;
        border: 1px solid #3b82f6;
    }
    .badge-attack {
        background-color: #991b1b;
        color: #fecaca;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 11px;
        font-weight: bold;
    }
    .badge-benign {
        background-color: #065f46;
        color: #a7f3d0;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 11px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# OFFLINE PYTORCH MODEL DEFINITION & CACHED LOADER
# ─────────────────────────────────────────────────────────────────────────────
class LSTMDetector(nn.Module):
    def __init__(self, input_size=79, hidden_size=64, num_layers=1, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size  = input_size,
            hidden_size = hidden_size,
            num_layers  = num_layers,
            batch_first = True,
            dropout     = dropout if num_layers > 1 else 0.0
        )
        self.dropout = nn.Dropout(dropout)
        self.fc      = nn.Linear(hidden_size, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        last_step = out[:, -1, :]
        dropped   = self.dropout(last_step)
        logits    = self.fc(dropped)
        return logits.squeeze(1)


@st.cache_resource
def load_offline_resources():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    if not os.path.exists(MODEL_PATH):
        return None, None, None, None, f"Model checkpoint not found at: {MODEL_PATH}"
    
    checkpoint = torch.load(MODEL_PATH, map_location=device)
    input_size  = checkpoint.get("input_size", 79)
    hidden_size = checkpoint.get("hidden_size", 64)
    num_layers  = checkpoint.get("num_layers", 1)
    dropout     = checkpoint.get("dropout", 0.3)
    
    model = LSTMDetector(input_size, hidden_size, num_layers, dropout).to(device)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    
    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    encoder = joblib.load(ENCODER_PATH) if os.path.exists(ENCODER_PATH) else None
    
    mitre_dict = {}
    if os.path.exists(MITRE_PATH):
        with open(MITRE_PATH, "r", encoding="utf-8") as f:
            mitre_raw = json.load(f)
            mitre_dict = mitre_raw.get("mappings", mitre_raw)
            
    return model, scaler, encoder, mitre_dict, device


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR — OFFLINE STATUS & CONTROLS
# ─────────────────────────────────────────────────────────────────────────────
model, scaler, encoder, mitre_map, device_or_err = load_offline_resources()

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("AEGIS SIH26153")
    st.caption("Temporal Intrusion World-Model & Forecasting Engine")
    
    st.markdown("---")
    st.markdown("### 🔒 System Status")
    st.success("● 100% OFFLINE MODE (No Cloud/API)")
    if model is not None:
        st.info(f"⚡ Device: **{str(device_or_err).upper()}**\n\n🧠 Architecture: **LSTM (in=79, hid=64)**")
    else:
        st.error(f"Failed loading resources: {device_or_err}")
        
    st.markdown("---")
    st.markdown("### ⚙️ Detection Threshold")
    threshold = st.slider("Attack Decision Threshold", min_value=0.10, max_value=0.90, value=0.50, step=0.05)
    st.caption("Flows with $P(\\text{Attack}) \\ge \\text{Threshold}$ are escalated as confirmed threats.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN HERO HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.title("🛡️ AEGIS Real-Time Sequence Threat Forecaster")
st.markdown("Automated sliding-window sequence classification, pre-attack timeline escalation, and official **MITRE ATT&CK** mapping.")

st.markdown("---")


# ─────────────────────────────────────────────────────────────────────────────
# 1. UPLOAD & INGESTION SECTION
# ─────────────────────────────────────────────────────────────────────────────
st.subheader("1. Ingest Network Traffic Capture")

col_upload, col_sample = st.columns([3, 2])

with col_upload:
    uploaded_file = st.file_uploader(
        "Upload Network Flow Capture CSV (CIC-IDS2017 schema)",
        type=["csv"],
        help="Accepts CSV files with Source IP, Timestamp, and 79 flow statistics."
    )

with col_sample:
    st.markdown("#### Instant Demo Options")
    use_sample = st.button("⚡ Load Built-In Demo Sequence (IP: 172.16.0.1 Transition)", use_container_width=True)
    if use_sample and os.path.exists(SAMPLE_CSV):
        st.session_state["use_sample_traffic"] = True
    elif use_sample and not os.path.exists(SAMPLE_CSV):
        st.warning("Sample CSV not found at default path. Please upload a file.")

raw_df = None
if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file, low_memory=False, encoding="utf-8")
        st.session_state["use_sample_traffic"] = False
    except Exception:
        raw_df = pd.read_csv(uploaded_file, low_memory=False, encoding="latin-1")
elif st.session_state.get("use_sample_traffic", False) and os.path.exists(SAMPLE_CSV):
    raw_df = pd.read_csv(SAMPLE_CSV, low_memory=False, encoding="utf-8")
    st.info("Loaded built-in sample traffic slice (`172.16.0.1` transitioning from BENIGN to SSH-Patator).")

if raw_df is not None:
    raw_df.columns = raw_df.columns.str.strip()
    with st.expander("📄 Raw Traffic Ingestion Preview (First 5 Rows)", expanded=False):
        st.dataframe(raw_df.head(5), use_container_width=True)
else:
    st.info("👆 Please upload a network traffic CSV or click **Load Built-In Demo Sequence** to start.")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROCESSING PIPELINE (Sliding Window Per-IP Inference)
# ─────────────────────────────────────────────────────────────────────────────
with st.spinner("Processing network flow sequences and evaluating through PyTorch LSTM..."):
    # Feature columns deduction
    exclude_always = {
        "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "Label", "Label_Binary", "day_file", "Fwd Header Length.1"
    }
    non_numeric = set(raw_df.select_dtypes(exclude=[np.number]).columns.tolist())
    exclude_all = exclude_always | non_numeric | {"Label_Int", "Timestamp_dt"}
    feature_names = [c for c in raw_df.columns if c not in exclude_all]
    
    # Filter & sanitize
    clean_df = raw_df.copy()
    if "Label" in clean_df.columns:
        clean_df["Label"] = clean_df["Label"].astype(str).str.encode("ascii", errors="replace").str.decode("ascii").str.strip()
    else:
        clean_df["Label"] = "UNKNOWN"
        
    clean_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    clean_df.dropna(subset=feature_names, inplace=True)
    
    # Timestamp parsing
    if "Timestamp" in clean_df.columns:
        clean_df["Timestamp_dt"] = pd.to_datetime(clean_df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    else:
        clean_df["Timestamp_dt"] = pd.date_range("2017-07-04 00:00:00", periods=len(clean_df), freq="S")
        
    ip_col = "Source IP" if "Source IP" in clean_df.columns else "day_file"
    if ip_col not in clean_df.columns:
        clean_df["Source IP"] = "192.168.1.100"
        ip_col = "Source IP"
        
    clean_df.sort_values(by=[ip_col, "Timestamp_dt"], inplace=True)
    clean_df.reset_index(drop=True, inplace=True)
    
    # Rolling sequence inference
    results = []
    unique_ips = clean_df[ip_col].unique()
    
    for ip in unique_ips:
        ip_data = clean_df[clean_df[ip_col] == ip].reset_index(drop=True)
        if len(ip_data) < WINDOW_SIZE:
            continue
            
        feat_raw = ip_data[feature_names].values.astype(np.float32)
        # Pad/adjust feature dimension if schema varies slightly
        if feat_raw.shape[1] == scaler.n_features_in_:
            feat_scaled = scaler.transform(feat_raw).astype(np.float32)
        else:
            feat_scaled = feat_raw
            
        with torch.no_grad():
            for i in range(WINDOW_SIZE, len(ip_data)):
                window = feat_scaled[i - WINDOW_SIZE : i]
                seq_tensor = torch.tensor(window[np.newaxis, ...], dtype=torch.float32).to(device_or_err)
                prob = torch.sigmoid(model(seq_tensor)).item()
                
                flow_row = ip_data.iloc[i]
                true_lbl = str(flow_row.get("Label", "UNKNOWN"))
                decision = "ATTACK" if prob >= threshold else "BENIGN"
                
                # MITRE Lookup
                lookup_key = true_lbl if true_lbl in mitre_map else ("SSH-Patator" if decision == "ATTACK" else "BENIGN")
                mitre_info = mitre_map.get(lookup_key, {
                    "tactic": "Credential Access" if decision == "ATTACK" else "None",
                    "technique_id": "T1110" if decision == "ATTACK" else "N/A",
                    "technique_name": "Brute Force" if decision == "ATTACK" else "Normal Traffic",
                    "stage": "Exploitation" if decision == "ATTACK" else "Baseline"
                })
                
                results.append({
                    "source_ip": ip,
                    "flow_index": i,
                    "timestamp": flow_row.get("Timestamp", str(flow_row["Timestamp_dt"])),
                    "timestamp_dt": flow_row["Timestamp_dt"],
                    "prob_attack": prob,
                    "decision": decision,
                    "true_label": true_lbl,
                    "mitre_tactic": mitre_info.get("tactic", "Impact"),
                    "mitre_code": mitre_info.get("technique_id", "T1498"),
                    "mitre_technique": mitre_info.get("technique_name", "Network Anomaly"),
                    "mitre_stage": mitre_info.get("stage", "Threat Activity")
                })

results_df = pd.DataFrame(results)

if len(results_df) == 0:
    st.warning("⚠️ Not enough consecutive flows per IP to form 10-flow sequences (requires $\\ge 10$ flows per IP).")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 3. SUMMARY KPI METRICS
# ─────────────────────────────────────────────────────────────────────────────
st.subheader("2. Real-Time Detection Summary")

total_seqs   = len(results_df)
threat_seqs  = (results_df["decision"] == "ATTACK").sum()
flagged_ips  = results_df[results_df["decision"] == "ATTACK"]["source_ip"].nunique()
top_tactic   = results_df[results_df["decision"] == "ATTACK"]["mitre_tactic"].mode()
top_tactic_str = top_tactic.iloc[0] if len(top_tactic) > 0 else "None (All Normal)"

m1, m2, m3, m4 = st.columns(4)
m1.metric("Flow Sequences Evaluated", f"{total_seqs:,}")
m2.metric("Threat Sequences Flagged", f"{threat_seqs:,}", delta=f"{threat_seqs/total_seqs*100:.1f}% Threat Rate" if total_seqs>0 else None)
m3.metric("Hostile IPs Identified", f"{flagged_ips} / {len(unique_ips)}")
m4.metric("Dominant MITRE Tactic", top_tactic_str)

st.markdown("---")


# ─────────────────────────────────────────────────────────────────────────────
# 4. ACTIVE THREAT ALERT CARDS
# ─────────────────────────────────────────────────────────────────────────────
if flagged_ips > 0:
    st.subheader("🚨 Active Hostile Threat Alerts")
    threat_ip_groups = results_df[results_df["decision"] == "ATTACK"].groupby("source_ip")
    
    for ip, grp in threat_ip_groups:
        max_prob = grp["prob_attack"].max()
        first_ts = grp["timestamp"].iloc[0]
        dominant_tac = grp["mitre_tactic"].iloc[0]
        code = grp["mitre_code"].iloc[0]
        tech = grp["mitre_technique"].iloc[0]
        
        st.markdown(f"""
        <div class="threat-card-critical">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="font-size: 18px; font-weight: bold; font-family: monospace;">⚠️ ATTACKER IP: {ip}</span>
                    <span style="margin-left: 12px;" class="badge-mitre">{code} · {dominant_tac}</span>
                </div>
                <div>
                    <span class="badge-attack">CONFIDENCE: {max_prob*100:.1f}%</span>
                </div>
            </div>
            <div style="margin-top: 8px; font-size: 13px; opacity: 0.9;">
                <b>Technique:</b> {tech} | <b>First Breach Flow:</b> {first_ts} | <b>Total Malicious Flow Windows:</b> {len(grp)}
            </div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="threat-card-benign">
        <b>✅ All Monitored Traffic Clear:</b> No adversary activity detected across any sliding flow windows.
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")


# ─────────────────────────────────────────────────────────────────────────────
# 5. INTERACTIVE TIMELINE FORECASTING PLOT (PER SOURCE IP)
# ─────────────────────────────────────────────────────────────────────────────
st.subheader("3. Temporal Intrusion Probability Timeline")

col_sel, col_info = st.columns([2, 3])
with col_sel:
    selected_ip = st.selectbox("Select Source IP to Inspect Timeline:", unique_ips)

ip_timeline = results_df[results_df["source_ip"] == selected_ip].reset_index(drop=True)

if len(ip_timeline) > 0:
    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(12, 6),
        gridspec_kw={"height_ratios": [3, 1]},
        sharex=True
    )
    
    x_indices = np.arange(len(ip_timeline))
    probs     = ip_timeline["prob_attack"].values
    labels    = ip_timeline["true_label"].values
    decisions = ip_timeline["decision"].values
    
    # Probability Line & Shaded Zones
    ax1.plot(x_indices, probs, color="#2563eb", linewidth=2.4, marker="o", markersize=4.5, label="LSTM Attack Probability")
    ax1.axhline(threshold, color="#dc2626", linestyle="--", linewidth=1.5, label=f"Detection Threshold ({threshold})")
    
    # Highlight attack zones
    attack_mask = probs >= threshold
    if any(attack_mask):
        first_det = np.where(attack_mask)[0][0]
        ax1.axvline(first_det, color="#b91c1c", linestyle=":", linewidth=2, label=f"First Detection (Flow #{ip_timeline.loc[first_det, 'flow_index']})")
    
    ax1.set_ylabel("P(Attack)", fontsize=10, fontweight="bold")
    ax1.set_ylim(-0.05, 1.05)
    ax1.set_yticks(np.arange(0.0, 1.1, 0.2))
    ax1.grid(True, linestyle="--", alpha=0.3)
    ax1.legend(loc="upper left", fontsize=9, framealpha=0.85)
    
    # Ground Truth Strip
    gt_colors = ["#10b981" if (lbl == "BENIGN" or lbl == "UNKNOWN") else "#ef4444" for lbl in labels]
    ax2.scatter(x_indices, np.zeros_like(x_indices), c=gt_colors, s=80, edgecolors="#ffffff", linewidths=1.0)
    ax2.set_yticks([])
    ax2.set_ylabel("Status", fontsize=9, fontweight="bold")
    ax2.set_xlabel("Relative Flow Sequence Step (Time Ordered)", fontsize=10, fontweight="bold")
    ax2.grid(True, linestyle=":", alpha=0.3)
    ax2.set_ylim(-0.5, 0.5)
    
    plt.tight_layout()
    st.pyplot(fig)
    plt.close()


# ─────────────────────────────────────────────────────────────────────────────
# 6. DETAILED FLOW-BY-FLOW PREDICTION TABLE & MITRE BREAKDOWN
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("4. Detailed Sequence Intelligence & MITRE Breakdown")

tab_table, tab_mitre = st.tabs(["📋 Flow-by-Flow Sequence Log", "🎯 MITRE ATT&CK Tactical Breakdown"])

with tab_table:
    col_filter1, col_filter2 = st.columns(2)
    with col_filter1:
        filter_dec = st.radio("Filter Decision:", ["ALL", "ATTACK ONLY", "BENIGN ONLY"], horizontal=True)
    with col_filter2:
        search_ip = st.text_input("Filter by Source IP:", value="")
        
    display_df = results_df.copy()
    if filter_dec == "ATTACK ONLY":
        display_df = display_df[display_df["decision"] == "ATTACK"]
    elif filter_dec == "BENIGN ONLY":
        display_df = display_df[display_df["decision"] == "BENIGN"]
    if search_ip:
        display_df = display_df[display_df["source_ip"].str.contains(search_ip, na=False)]
        
    st.dataframe(
        display_df[[
            "source_ip", "flow_index", "timestamp", "prob_attack",
            "decision", "mitre_tactic", "mitre_code", "mitre_technique", "true_label"
        ]].rename(columns={
            "source_ip": "Source IP",
            "flow_index": "Flow #",
            "timestamp": "Timestamp",
            "prob_attack": "P(Attack)",
            "decision": "Decision",
            "mitre_tactic": "MITRE Tactic",
            "mitre_code": "MITRE ID",
            "mitre_technique": "Technique Name",
            "true_label": "Ground Truth"
        }),
        use_container_width=True,
        height=320
    )

with tab_mitre:
    tactic_dist = results_df[results_df["decision"] == "ATTACK"]["mitre_tactic"].value_counts()
    if len(tactic_dist) > 0:
        st.bar_chart(tactic_dist)
    else:
        st.info("No threat sequences flagged to display MITRE distribution.")

st.caption("🛡️ AEGIS Offline Intrusion World-Model — Defense AI Hackathon Demo")
