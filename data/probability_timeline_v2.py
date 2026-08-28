"""
Step 5 (v2) — Real-Time Rolling Probability Timeline & Pre-Attack Forecasting Demo
===================================================================================
Simulates live streaming traffic for a specific Source IP that transitions from
normal BENIGN operations into an active ATTACK phase.
Runs rolling 10-flow sequence inference at each time step, tracks attack probability
trajectory, detects pre-attack escalation, and plots a publication-ready timeline chart.

Outputs saved:
  TrafficLabelling/probability_timeline_demo.png  — high-res visualization chart
  c:/CODE CLASH HACKATHON/AEGIS/probability_timeline_demo.png — workspace copy
"""

import io
import os
import sys
import warnings
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# ── Force UTF-8 stdout on Windows ─────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR     = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
MODEL_PATH   = os.path.join(DATA_DIR, "lstm_model_v2.pth")
SCALER_PATH  = os.path.join(DATA_DIR, "scaler_v2.pkl")
ENCODER_PATH = os.path.join(DATA_DIR, "label_encoder_v2.pkl")
CSV_PATH     = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")

OUTPUT_CHART_DATA = os.path.join(DATA_DIR, "probability_timeline_demo.png")
OUTPUT_CHART_ROOT = r"c:\CODE CLASH HACKATHON\AEGIS\probability_timeline_demo.png"

WINDOW_SIZE  = 10
LEAD_IN_BENIGN = 20     # Number of benign flows before the attack transition to include
ATTACK_FLOWS   = 35     # Number of attack flows after the transition to include
DIVIDER = "=" * 75


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD MODEL, SCALER & METADATA
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load LSTM Checkpoint & Feature Scaler")
print(DIVIDER)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"  Compute Device : {device}")

if not os.path.exists(MODEL_PATH):
    print(f"  [ERROR] Model checkpoint not found at: {MODEL_PATH}")
    sys.exit(1)

checkpoint  = torch.load(MODEL_PATH, map_location=device)
input_size  = checkpoint.get("input_size", 79)
hidden_size = checkpoint.get("hidden_size", 64)
num_layers  = checkpoint.get("num_layers", 1)
dropout     = checkpoint.get("dropout", 0.3)

class LSTMDetector(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, dropout):
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

model = LSTMDetector(input_size, hidden_size, num_layers, dropout).to(device)
model.load_state_dict(checkpoint["state_dict"])
model.eval()

scaler  = joblib.load(SCALER_PATH)
encoder = joblib.load(ENCODER_PATH)
classes = list(encoder.classes_)

print(f"  ✓ LSTM Model loaded (in={input_size}, hidden={hidden_size}, layers={num_layers})")
print(f"  ✓ Scaler and Label Encoder loaded ({len(classes)} classes)")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — FIND CANDIDATE TRANSITION IPs
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Discover Candidate Attack Transition Timelines")
print(DIVIDER)

print(f"  Reading dataset for Source IP flow progressions ...")
peek = pd.read_csv(CSV_PATH, nrows=1, low_memory=False, encoding="utf-8")
peek.columns = peek.columns.str.strip()

exclude_always = {
    "Flow ID", "Source IP", "Destination IP", "Timestamp",
    "Label", "Label_Binary", "day_file", "Fwd Header Length.1"
}
non_numeric = set(peek.select_dtypes(exclude=[np.number]).columns.tolist())
exclude_all = exclude_always | non_numeric | {"Label_Int", "Timestamp_dt"}
feature_names = [c for c in peek.columns if c not in exclude_all]

dtypes = {col: np.float32 for col in feature_names}
usecols = ["Source IP", "Timestamp", "Label"] + feature_names

df = pd.read_csv(CSV_PATH, usecols=usecols, dtype=dtypes, low_memory=False, encoding="utf-8")
df.columns = df.columns.str.strip()

# Clean data
df = df[df["Label"].notna() & (df["Label"] != "nan")].reset_index(drop=True)
df["Label"] = df["Label"].astype(str).str.encode("ascii", errors="replace").str.decode("ascii").str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df.reset_index(drop=True, inplace=True)

df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
df = df[df["Timestamp_dt"].notna()].reset_index(drop=True)

print(f"  Clean flows loaded: {len(df):,}")

# Scan candidate transition sequences
candidate_ips = ["172.16.0.1", "192.168.10.14", "192.168.10.15", "192.168.10.8", "192.168.10.5"]
transition_records = []

print(f"\n  Scanning candidate transition profiles:")
print(f"  {'#':>2} | {'Source IP':<16} | {'Total Flows':>11} | {'Transition Index':>16} | {'Attack Class':<22} | {'Pattern'}")
print(f"  {'-'*2}-+-{'-'*16}-+-{'-'*11}-+-{'-'*16}-+-{'-'*22}-+-{'-'*25}")

cand_idx = 1
for ip in candidate_ips:
    ip_df = df[df["Source IP"] == ip].sort_values("Timestamp_dt").reset_index(drop=True)
    is_atk = (ip_df["Label"] != "BENIGN").astype(int).values
    transitions = np.where((is_atk[:-1] == 0) & (is_atk[1:] == 1))[0]

    for t_idx in transitions:
        # Find transitions with good benign lead-in (>= 15 benign) and good attack follow-up (>= 15 attack)
        pre_benign = (is_atk[max(0, t_idx - LEAD_IN_BENIGN + 1) : t_idx + 1] == 0).sum()
        post_attack = (is_atk[t_idx + 1 : min(len(is_atk), t_idx + 1 + ATTACK_FLOWS)] == 1).sum()

        if pre_benign >= 15 and post_attack >= 15:
            atk_type = ip_df.loc[t_idx + 1, "Label"]
            transition_records.append({
                "ip": ip,
                "df": ip_df,
                "t_idx": t_idx,
                "atk_type": atk_type,
                "pre_benign": pre_benign,
                "post_attack": post_attack,
                "total": len(ip_df)
            })
            print(f"  {cand_idx:>2} | {ip:<16} | {len(ip_df):>11,} | Flow #{t_idx:>11,} | {atk_type:<22} | {pre_benign} Benign → {post_attack} {atk_type}")
            cand_idx += 1
            if cand_idx > 8:
                break

if not transition_records:
    # Fallback to first available transition
    ip = "172.16.0.1"
    ip_df = df[df["Source IP"] == ip].sort_values("Timestamp_dt").reset_index(drop=True)
    is_atk = (ip_df["Label"] != "BENIGN").astype(int).values
    transitions = np.where((is_atk[:-1] == 0) & (is_atk[1:] == 1))[0]
    t_idx = transitions[0] if len(transitions) > 0 else 10
    transition_records.append({
        "ip": ip,
        "df": ip_df,
        "t_idx": t_idx,
        "atk_type": ip_df.loc[min(len(ip_df)-1, t_idx + 1), "Label"],
        "pre_benign": 10,
        "post_attack": 20,
        "total": len(ip_df)
    })

# Select the best profile (e.g. Profile #1: clean SSH-Patator or Bot or PortScan transition)
selected_case = transition_records[0]
chosen_ip     = selected_case["ip"]
chosen_t_idx  = selected_case["t_idx"]
chosen_df     = selected_case["df"]
chosen_attack = selected_case["atk_type"]

print(f"\n  ► SELECTED CASE FOR TIMELINE DEMO:")
print(f"    Source IP        : {chosen_ip}")
print(f"    Transition Index : Flow #{chosen_t_idx}")
print(f"    Attack Type      : {chosen_attack}")
print(f"    Timestamp        : {chosen_df.loc[chosen_t_idx, 'Timestamp_dt']}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — EXTRACT SEQUENCE SEGMENT & RUN ROLLING WINDOW INFERENCE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Rolling Window Temporal Prediction (Window = 10 Flows)")
print(DIVIDER)

# Slice a clean window around transition: [t_idx - LEAD_IN_BENIGN : t_idx + ATTACK_FLOWS]
start_idx = max(0, chosen_t_idx - LEAD_IN_BENIGN + 1)
end_idx   = min(len(chosen_df), chosen_t_idx + 1 + ATTACK_FLOWS)

segment_df = chosen_df.iloc[start_idx:end_idx].reset_index(drop=True)
transition_pos_in_segment = chosen_t_idx - start_idx  # index where last BENIGN flow occurs

# Extract & scale features
feat_raw    = segment_df[feature_names].values.astype(np.float32)
feat_scaled = scaler.transform(feat_raw).astype(np.float32)

print(f"  Segment Size     : {len(segment_df)} consecutive time-ordered flows")
print(f"  Benign Flows     : {transition_pos_in_segment + 1} flows (Indices 0 .. {transition_pos_in_segment})")
print(f"  Attack Flows     : {len(segment_df) - transition_pos_in_segment - 1} flows (Indices {transition_pos_in_segment+1} .. {len(segment_df)-1})")
print(f"  Running rolling inference starting at flow #{WINDOW_SIZE} ...\n")

timeline_data = []

with torch.no_grad():
    for i in range(WINDOW_SIZE, len(segment_df)):
        # Sliding 10-flow window ending immediately before flow i
        window_feats = feat_scaled[i - WINDOW_SIZE : i]   # shape: (10, 79)
        seq_tensor   = torch.tensor(window_feats[np.newaxis, ...], dtype=torch.float32).to(device)

        logits = model(seq_tensor)
        prob_attack = torch.sigmoid(logits).item()

        flow_info = segment_df.iloc[i]
        true_label = flow_info["Label"]
        is_true_attack = 0 if true_label == "BENIGN" else 1
        pred_label = "ATTACK" if prob_attack >= 0.5 else "BENIGN"

        timeline_data.append({
            "rel_idx": i - transition_pos_in_segment,     # <= 0 is Benign phase, > 0 is Attack phase
            "segment_idx": i,
            "timestamp": flow_info["Timestamp_dt"],
            "timestamp_str": str(flow_info["Timestamp"]),
            "true_label": true_label,
            "is_true_attack": is_true_attack,
            "prob_attack": prob_attack,
            "pred_label": pred_label
        })

tl_df = pd.DataFrame(timeline_data)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — PRINT TERMINAL TIMELINE REPORT
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print(f"STEP 4 — Real-Time Streaming Timeline Table for IP: {chosen_ip}")
print(DIVIDER)

print(f"\n  {'Step':>4} | {'Rel Pos':>7} | {'Timestamp':<19} | {'Ground Truth Label':<24} | {'P(Attack)':>9} | {'Decision':<8} | {'Status / Lead-up'}")
print(f"  {'-'*4}-+-{'-'*7}-+-{'-'*19}-+-{'-'*24}-+-{'-'*9}-+-{'-'*8}-+-{'-'*30}")

for _, row in tl_df.iterrows():
    rel = row["rel_idx"]
    rel_str = f"T{rel:+d}" if rel != 0 else "T=0 (Onset)"
    prob_str = f"{row['prob_attack']*100:>6.2f}%"

    if rel < 0:
        if row["prob_attack"] < 0.2:
            status = "Normal baseline state"
        else:
            status = "⚡ PRE-ATTACK ELEVATION (Forecasting signal)"
    elif rel == 0:
        status = "◄─── TRANSITION POINT (Last Benign Flow)"
    else:
        if row["prob_attack"] >= 0.8:
            status = "★ HIGH-CONFIDENCE ATTACK DETECTED"
        else:
            status = "Attack detection active"

    bar = "█" * int(row["prob_attack"] * 10)
    print(f"  {row['segment_idx']:>4} | {rel_str:>7} | {str(row['timestamp'])[:19]:<19} | {row['true_label']:<24} | {prob_str:>9} | {row['pred_label']:<8} | {status} {bar}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — PLOT & SAVE PUBLICATION-QUALITY TIMELINE VISUALIZATION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Generate & Save Timeline Demonstration Chart")
print(DIVIDER)

fig, (ax1, ax2) = plt.subplots(
    2, 1, figsize=(14, 8),
    gridspec_kw={"height_ratios": [3, 1]},
    sharex=True
)

x_vals = tl_df["rel_idx"].values
probs  = tl_df["prob_attack"].values
labels = tl_df["true_label"].values

# ── Upper Plot: Probability Curve ─────────────────────────────────────────────
# Shaded background zones
ax1.axvspan(x_vals.min() - 0.5, 0.5, color="#e8f5e9", alpha=0.8, label="Ground Truth: BENIGN Phase")
ax1.axvspan(0.5, x_vals.max() + 0.5, color="#ffebee", alpha=0.8, label=f"Ground Truth: ATTACK Phase ({chosen_attack})")

# Transition Vertical Line
ax1.axvline(0.5, color="#c62828", linestyle="--", linewidth=2.2, label="Attack Transition Point (T=0)")

# Threshold Line
ax1.axhline(0.5, color="#78909c", linestyle=":", linewidth=1.5, label="Decision Threshold (0.5)")

# Probability Line & Points
ax1.plot(x_vals, probs, color="#1565c0", linewidth=2.5, marker="o", markersize=6, label="LSTM P(Attack | 10-Flow History)")

# Annotations
first_attack_idx = np.where(x_vals == 1)[0]
if len(first_attack_idx) > 0:
    p_first_atk = probs[first_attack_idx[0]]
    ax1.annotate(
        f"Attack Inception\nP={p_first_atk*100:.1f}%",
        xy=(1, p_first_atk),
        xytext=(3, max(0.2, p_first_atk - 0.25)),
        arrowprops=dict(facecolor="#d32f2f", shrink=0.08, width=1.5, headwidth=7),
        fontsize=10, fontweight="bold", color="#b71c1c",
        bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#d32f2f", lw=1.2)
    )

# Pre-attack check (forecasting)
pre_attack_mask = (x_vals < 0) & (x_vals >= -3)
if any(pre_attack_mask) and max(probs[pre_attack_mask]) > 0.3:
    peak_pre = np.argmax(probs[pre_attack_mask])
    peak_x = x_vals[pre_attack_mask][peak_pre]
    peak_p = probs[pre_attack_mask][peak_pre]
    ax1.annotate(
        f"Pre-Attack Escalation\nP={peak_p*100:.1f}%",
        xy=(peak_x, peak_p),
        xytext=(peak_x - 4, peak_p + 0.2),
        arrowprops=dict(facecolor="#f57c00", shrink=0.08, width=1.5, headwidth=7),
        fontsize=9, fontweight="bold", color="#e65100",
        bbox=dict(boxstyle="round,pad=0.3", fc="#fff8e1", ec="#f57c00", lw=1)
    )

ax1.set_title(
    f"AEGIS Temporal Intrusion Forecasting & Transition Timeline\nSource IP: {chosen_ip}  |  Attack Progression: BENIGN → {chosen_attack}",
    fontsize=13, fontweight="bold", pad=12
)
ax1.set_ylabel("Predicted Attack Probability P(Attack)", fontsize=11, fontweight="semibold")
ax1.set_ylim(-0.05, 1.05)
ax1.set_yticks(np.arange(0.0, 1.1, 0.2))
ax1.grid(True, linestyle="--", alpha=0.5)
ax1.legend(loc="upper left", framealpha=0.9, fontsize=9.5)

# ── Lower Plot: Ground Truth Strip ────────────────────────────────────────────
gt_colors = ["#43a047" if lbl == "BENIGN" else "#e53935" for lbl in labels]
ax2.scatter(x_vals, np.zeros_like(x_vals), c=gt_colors, s=120, edgecolors="#ffffff", linewidths=1.2, zorder=3)
ax2.axvline(0.5, color="#c62828", linestyle="--", linewidth=2.2)

ax2.set_yticks([])
ax2.set_ylabel("Ground Truth", fontsize=10, fontweight="semibold")
ax2.set_xlabel("Relative Flow Sequence Position (T=0 marks transition to attack)", fontsize=11, fontweight="semibold")
ax2.set_xticks(x_vals[::2])
ax2.set_xticklabels([f"T{v:+d}" if v != 0 else "T=0" for v in x_vals[::2]], fontsize=9)
ax2.grid(True, linestyle=":", alpha=0.4)
ax2.set_ylim(-0.5, 0.5)

plt.tight_layout()

# Save chart to both locations
plt.savefig(OUTPUT_CHART_DATA, dpi=300, bbox_inches="tight")
print(f"  ✓ Saved visualization → {OUTPUT_CHART_DATA}")

try:
    plt.savefig(OUTPUT_CHART_ROOT, dpi=300, bbox_inches="tight")
    print(f"  ✓ Saved visualization copy in project root → {OUTPUT_CHART_ROOT}")
except Exception as e:
    pass

plt.close()

print(f"\n{DIVIDER}")
print("Done! Timeline demonstration generated successfully.")
print(DIVIDER)
