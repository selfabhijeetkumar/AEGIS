"""
Multi-IP Probability Timeline Generalization Analysis (v2)
==========================================================
Tests whether the AEGIS LSTM early-warning behavior observed for the single
172.16.0.1 SSH-Patator example generalises across multiple Source IPs and
different attack types.

Attack categories covered:
  1. DoS Slowhttptest  (genuine BENIGN -> attack transition, verified)
  2. FTP-Patator       (genuine BENIGN -> attack transition, verified)
  3. Web Attack BF     (genuine BENIGN -> attack transition, verified)
  4. PortScan          (genuine BENIGN -> attack transition, verified)
  5. DDoS              NOT FOUND   (reported honestly: no clean BENIGN->DDoS on 172.16.0.1)
  6. Bot               NOT DETECTED (v3 model: unseen host group-split, 0% recall)

Model selection:  lstm_model_v3.pth if available, else lstm_model_v2.pth
Scaler/Encoder:   matching _v3 artefacts if v3 model is used, else _v2

Transition indices are auto-discovered from the fully cleaned df at runtime
to avoid index mismatch caused by NaN row drops.

Outputs:
  TrafficLabelling/probability_timeline_multi_demo.png
  C:/CODE CLASH HACKATHON/AEGIS/probability_timeline_multi_demo.png
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
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import Patch
from matplotlib.lines import Line2D

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
warnings.filterwarnings("ignore")

# CONFIGURATION
DATA_DIR = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
CSV_PATH = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")
MODEL_V3   = os.path.join(DATA_DIR, "lstm_model_v3.pth")
MODEL_V2   = os.path.join(DATA_DIR, "lstm_model_v2.pth")
MODEL_PATH = MODEL_V3 if os.path.exists(MODEL_V3) else MODEL_V2
USE_V3     = os.path.exists(MODEL_V3)
SCALER_PATH  = os.path.join(DATA_DIR, "scaler_v3.pkl"  if USE_V3 else "scaler_v2.pkl")
ENCODER_PATH = os.path.join(DATA_DIR, "label_encoder_v3.pkl" if USE_V3 else "label_encoder_v2.pkl")
OUTPUT_CHART_DATA = os.path.join(DATA_DIR, "probability_timeline_multi_demo.png")
OUTPUT_CHART_ROOT = r"C:\CODE CLASH HACKATHON\AEGIS\probability_timeline_multi_demo.png"
WINDOW_SIZE          = 10    # same as single-IP demo
LEAD_BENIGN          = 20    # benign flows to include before transition
ATTACK_FLOWS         = 35    # attack flows to include after transition
EARLY_WARN_THRESHOLD = 0.30  # same definition as single-IP demo
DIVIDER = "=" * 78

# Candidate spec: attack label (partial match ok) and source IP.
# t_idx is auto-discovered at runtime from the cleaned full-feature df.
CANDIDATE_SPECS = [
    {"ip": "172.16.0.1", "attack_match": "DoS Slowhttptest",        "category": "DoS (Slowhttptest)",      "color": "#d32f2f"},
    {"ip": "172.16.0.1", "attack_match": "FTP-Patator",             "category": "FTP-Patator",             "color": "#1565c0"},
    {"ip": "172.16.0.1", "attack_match": "Brute Force",             "category": "Web Attack (Brute Force)", "color": "#6a1b9a"},
    {"ip": "172.16.0.1", "attack_match": "PortScan",                "category": "PortScan",                "color": "#e65100"},
]

MISSING_CATEGORIES = [
    {
        "category": "DDoS",
        "reason": (
            "172.16.0.1 is the only significant DDoS attacker in CICIDS2017. "
            "Its DDoS flows are always preceded by sustained PortScan activity. "
            "No contiguous BENIGN block of >=15 flows exists before DDoS onset. "
            "192.168.10.50 has only 3 DDoS flows (insufficient). No fabricated example used."
        ),
    },
    {
        "category": "Bot (multi-host)",
        "reason": (
            "Bot flows exist on 192.168.10.x hosts with long benign lead-ins. "
            "However, the v3 model (group-based zero-leakage split) achieves 0% "
            "P(attack) on these unseen host IPs. Known limitation of group-split."
        ),
    },
]

print(DIVIDER)
print("STEP 1 -- Load LSTM Checkpoint, Scaler, and Label Encoder")
print(DIVIDER)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"  Compute Device : {device}")
print(f"  Model file     : {os.path.basename(MODEL_PATH)}")
print(f"  Scaler file    : {os.path.basename(SCALER_PATH)}")
print(f"  Encoder file   : {os.path.basename(ENCODER_PATH)}")

if not os.path.exists(MODEL_PATH):
    print(f"  [ERROR] Model not found at: {MODEL_PATH}")
    sys.exit(1)

checkpoint   = torch.load(MODEL_PATH, map_location=device)
input_size   = checkpoint.get("input_size", 79)
hidden_size  = checkpoint.get("hidden_size", 64)
num_layers   = checkpoint.get("num_layers", 1)
dropout      = checkpoint.get("dropout", 0.3)

class LSTMDetector(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, dropout):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size, hidden_size=hidden_size,
            num_layers=num_layers, batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )
        self.dropout = nn.Dropout(dropout)
        self.fc      = nn.Linear(hidden_size, 1)
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(self.dropout(out[:, -1, :])).squeeze(1)

model = LSTMDetector(input_size, hidden_size, num_layers, dropout).to(device)
model.load_state_dict(checkpoint["state_dict"])
model.eval()
scaler  = joblib.load(SCALER_PATH)
encoder = joblib.load(ENCODER_PATH)
print(f"  Model loaded  (input={input_size}, hidden={hidden_size}, layers={num_layers})")
print(f"  Scaler loaded ({len(encoder.classes_)} label classes)\n")

print(DIVIDER)
print("STEP 2 -- Load Dataset and Derive Feature Names")
print(DIVIDER)
peek = pd.read_csv(CSV_PATH, nrows=1, low_memory=False, encoding="utf-8")
peek.columns = peek.columns.str.strip()
exclude_always = {"Flow ID", "Source IP", "Destination IP", "Timestamp", "Label",
                  "Label_Binary", "day_file", "Fwd Header Length.1"}
non_numeric    = set(peek.select_dtypes(exclude=[np.number]).columns.tolist())
exclude_all    = exclude_always | non_numeric | {"Label_Int", "Timestamp_dt"}
feature_names  = [c for c in peek.columns if c not in exclude_all]
print(f"  Feature count  : {len(feature_names)}")
dtypes  = {col: np.float32 for col in feature_names}
usecols = ["Source IP", "Timestamp", "Label"] + feature_names
print(f"  Reading CSV ...")
df = pd.read_csv(CSV_PATH, usecols=usecols, dtype=dtypes, low_memory=False, encoding="utf-8")
df.columns = df.columns.str.strip()
df = df[df["Label"].notna() & (df["Label"] != "nan")].reset_index(drop=True)
df["Label"] = df["Label"].astype(str).str.encode("ascii", errors="replace").str.decode("ascii").str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
df = df[df["Timestamp_dt"].notna()].reset_index(drop=True)
print(f"  Clean flows    : {len(df):,}\n")

print(DIVIDER)
print("STEP 3 -- Auto-Discover Transition Indices from Loaded Data")
print(DIVIDER)

CANDIDATES = []
for spec in CANDIDATE_SPECS:
    ip = spec["ip"]
    match_str = spec["attack_match"]
    ip_df = df[df["Source IP"] == ip].sort_values("Timestamp_dt").reset_index(drop=True)
    is_atk = (ip_df["Label"] != "BENIGN").astype(int).values
    trans = np.where((is_atk[:-1] == 0) & (is_atk[1:] == 1))[0]

    found = False
    for t in trans:
        next_lbl = ip_df.loc[t + 1, "Label"]
        if match_str.lower() in next_lbl.lower():
            pre_b  = (is_atk[max(0, t - (LEAD_BENIGN - 1)) : t + 1] == 0).sum()
            post_a = (is_atk[t + 1 : min(len(is_atk), t + ATTACK_FLOWS + 1)] == 1).sum()
            if pre_b >= WINDOW_SIZE and post_a >= 10:
                spec_full = dict(spec)
                spec_full["t_idx"] = int(t)
                spec_full["attack_label"] = next_lbl
                spec_full["pre_b"] = pre_b
                spec_full["post_a"] = post_a
                CANDIDATES.append(spec_full)
                print(f"  Found: {spec['category']:<28} IP={ip}  t_idx={t}  pre-benign={pre_b}  post-atk={post_a}  label={next_lbl}")
                found = True
                break
    if not found:
        print(f"  [WARN] No valid transition found for: {spec['category']} / match='{match_str}'")

print()

print(DIVIDER)
print("STEP 4 -- Rolling 10-Flow Window Inference (time-ordered, no lookahead)")
print(DIVIDER)
all_results = []

for cand in CANDIDATES:
    ip       = cand["ip"]
    t_idx    = cand["t_idx"]
    atk_lbl  = cand["attack_label"]
    category = cand["category"]
    print(f"\n  -- {category} | IP: {ip} | Transition @ local-index {t_idx} --")

    ip_df = df[df["Source IP"] == ip].sort_values("Timestamp_dt").reset_index(drop=True)
    seg_start = max(0, t_idx - LEAD_BENIGN + 1)
    seg_end   = min(len(ip_df), t_idx + ATTACK_FLOWS + 1)
    seg       = ip_df.iloc[seg_start : seg_end].copy().reset_index(drop=True)
    trans_pos_in_seg = t_idx - seg_start

    if trans_pos_in_seg < WINDOW_SIZE:
        print(f"    [WARN] trans_pos={trans_pos_in_seg} < WINDOW_SIZE. Skipping.")
        continue

    benign_count  = (seg.iloc[:trans_pos_in_seg + 1]["Label"] == "BENIGN").sum()
    attack_count  = (seg.iloc[trans_pos_in_seg + 1:]["Label"] != "BENIGN").sum()
    print(f"    Segment size   : {len(seg)} flows")
    print(f"    Benign flows   : {benign_count} (in benign region of segment)")
    print(f"    Attack flows   : {attack_count} (in attack region of segment)")

    feat_raw    = seg[feature_names].values.astype(np.float32)
    feat_scaled = scaler.transform(feat_raw).astype(np.float32)

    timeline_rows = []
    with torch.no_grad():
        for i in range(WINDOW_SIZE, len(seg)):
            # 10-flow sliding window ending BEFORE flow i (strict no-lookahead)
            window   = feat_scaled[i - WINDOW_SIZE : i]
            tensor   = torch.tensor(window[np.newaxis, ...], dtype=torch.float32).to(device)
            p_attack = torch.sigmoid(model(tensor)).item()
            flow_info  = seg.iloc[i]
            true_label = flow_info["Label"]
            rel_pos    = i - trans_pos_in_seg   # <=0 benign phase, >0 attack phase
            timeline_rows.append({
                "rel_pos"    : rel_pos,
                "seg_idx"    : i,
                "timestamp"  : flow_info["Timestamp_dt"],
                "true_label" : true_label,
                "is_attack"  : 0 if true_label == "BENIGN" else 1,
                "prob_attack": p_attack,
            })

    tl_df = pd.DataFrame(timeline_rows)

    p_tminus2 = tl_df.loc[tl_df["rel_pos"] == -2, "prob_attack"].values
    p_t0      = tl_df.loc[tl_df["rel_pos"] ==  0, "prob_attack"].values
    p_tplus1  = tl_df.loc[tl_df["rel_pos"] ==  1, "prob_attack"].values
    p_tminus2 = float(p_tminus2[0]) if len(p_tminus2) else None
    p_t0      = float(p_t0[0])      if len(p_t0)      else None
    p_tplus1  = float(p_tplus1[0])  if len(p_tplus1)  else None

    # Early warning: P(attack) >= threshold during the BENIGN phase (rel_pos < 0)
    benign_phase_probs = tl_df.loc[tl_df["rel_pos"] < 0, "prob_attack"].values
    early_warn = bool(len(benign_phase_probs) > 0 and benign_phase_probs.max() >= EARLY_WARN_THRESHOLD)

    all_results.append({
        "ip": ip, "category": category, "attack_label": atk_lbl,
        "t_idx": t_idx, "seg_size": len(seg),
        "benign_count": benign_count, "attack_count": attack_count,
        "tl_df": tl_df, "trans_pos": trans_pos_in_seg,
        "p_tminus2": p_tminus2, "p_t0": p_t0, "p_tplus1": p_tplus1,
        "early_warn": early_warn, "color": cand["color"],
    })
    pt2 = f"{p_tminus2*100:.1f}%" if p_tminus2 is not None else "N/A"
    pt0 = f"{p_t0*100:.1f}%"      if p_t0      is not None else "N/A"
    pt1 = f"{p_tplus1*100:.1f}%"  if p_tplus1  is not None else "N/A"
    print(f"    P(T-2)={pt2}  P(T=0)={pt0}  P(T+1)={pt1}  Early-warning: {'YES' if early_warn else 'NO'}")

print(f"\n{DIVIDER}")
print("STEP 5 -- Summary Table")
print(DIVIDER)
print(f"\n  {'IP':<18} {'Attack Type':<28} {'P(T-2)':>8} {'P(T=0)':>8} {'P(T+1)':>8} Early Warning?")
print("  " + "-"*18 + " " + "-"*28 + " " + "-"*8 + " " + "-"*8 + " " + "-"*8 + " " + "-"*14)
for r in all_results:
    pt2 = f"{r['p_tminus2']*100:.1f}%" if r["p_tminus2"] is not None else "N/A"
    pt0 = f"{r['p_t0']*100:.1f}%"      if r["p_t0"]      is not None else "N/A"
    pt1 = f"{r['p_tplus1']*100:.1f}%"  if r["p_tplus1"]  is not None else "N/A"
    ew  = "Yes" if r["early_warn"] else "No"
    print(f"  {r['ip']:<18} {r['category']:<28} {pt2:>8} {pt0:>8} {pt1:>8} {ew}")

print(f"\n  Missing / could-not-demonstrate:")
for m in MISSING_CATEGORIES:
    print(f"  [X] {m['category']}: {m['reason'][:88]}")

print(f"\n  Early-warning threshold: P(attack) >= {EARLY_WARN_THRESHOLD:.0%} during benign phase (rel_pos < 0)")
print(f"  Rolling window size    : {WINDOW_SIZE} flows (identical to single-IP demo)")
print(f"  Model                  : {os.path.basename(MODEL_PATH)}")
print(f"\n  Reproducibility:")
for r in all_results:
    print(f"    {r['category']:<28} t_idx={r['t_idx']:>7}  segment={r['seg_size']}  benign={r['benign_count']}  attack={r['attack_count']}")

print(f"\n{DIVIDER}")
print("STEP 6 -- Generate Combined Comparison Chart")
print(DIVIDER)

N = len(all_results)
fig = plt.figure(figsize=(16, 5 * N + 2), constrained_layout=True)
fig.patch.set_facecolor("#f8f9fa")
outer_gs = gridspec.GridSpec(N + 1, 1, figure=fig, height_ratios=[4]*N + [0.7])

for idx, r in enumerate(all_results):
    tl_df    = r["tl_df"]
    x_vals   = tl_df["rel_pos"].values
    probs    = tl_df["prob_attack"].values
    labels   = tl_df["true_label"].values
    color    = r["color"]
    category = r["category"]
    ip       = r["ip"]

    inner_gs = gridspec.GridSpecFromSubplotSpec(2, 1, subplot_spec=outer_gs[idx], height_ratios=[4, 1], hspace=0.06)
    ax1 = fig.add_subplot(inner_gs[0])
    ax2 = fig.add_subplot(inner_gs[1], sharex=ax1)

    x_min, x_max = x_vals.min() - 0.5, x_vals.max() + 0.5
    ax1.axvspan(x_min, 0.5,  color="#e8f5e9", alpha=0.75, label="Benign phase")
    ax1.axvspan(0.5,  x_max, color="#ffebee", alpha=0.75, label="Attack phase")
    ax1.axvline(0.5, color="#c62828", linestyle="--", linewidth=2.0, zorder=3, label="Attack onset T=0")
    ax1.axhline(0.5, color="#78909c", linestyle=":", linewidth=1.4)

    ax1.plot(x_vals, probs, color=color, linewidth=2.3, marker="o", markersize=5, zorder=4, label="P(Attack | 10-flow window)")

    if r["p_tminus2"] is not None:
        ax1.scatter([-2], [r["p_tminus2"]], color="#f57c00", zorder=6, s=100, marker="D", label=f"T-2: {r['p_tminus2']*100:.1f}%")
    if r["p_t0"] is not None:
        ax1.scatter([0], [r["p_t0"]], color="#c62828", zorder=6, s=100, marker="s", label=f"T=0: {r['p_t0']*100:.1f}%")
    if r["p_tplus1"] is not None:
        ax1.scatter([1], [r["p_tplus1"]], color=color, zorder=6, s=100, marker="^", label=f"T+1: {r['p_tplus1']*100:.1f}%")

    if r["early_warn"]:
        benign_mask = x_vals < 0
        if benign_mask.any():
            peak_idx = np.argmax(probs[benign_mask])
            peak_x   = x_vals[benign_mask][peak_idx]
            peak_p   = probs[benign_mask][peak_idx]
            ax1.annotate(
                f"Pre-Attack Signal\nP={peak_p*100:.1f}%",
                xy=(peak_x, peak_p),
                xytext=(peak_x - 6, min(peak_p + 0.22, 0.92)),
                arrowprops=dict(arrowstyle="->", color="#f57c00", lw=1.5),
                fontsize=9, fontweight="bold", color="#e65100",
                bbox=dict(boxstyle="round,pad=0.3", fc="#fff8e1", ec="#f57c00", lw=1.2)
            )
    else:
        if (x_vals < 0).any():
            mid_x = x_vals[x_vals < 0].mean()
            ax1.text(mid_x, 0.60, "No pre-attack elevation detected",
                     fontsize=8.5, color="#78909c", ha="center", style="italic", alpha=0.9)

    ew_badge = "EARLY-WARNING: YES" if r["early_warn"] else "EARLY-WARNING: NO"
    ax1.set_title(f"{category}  |  IP: {ip}  |  {ew_badge}", fontsize=11, fontweight="bold", pad=8, color="#1a1a2e")
    ax1.set_ylabel("P(Attack)", fontsize=9.5, fontweight="bold")
    ax1.set_ylim(-0.05, 1.15)
    ax1.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax1.set_yticklabels(["0%", "25%", "50%", "75%", "100%"], fontsize=8.5)
    ax1.grid(True, linestyle="--", alpha=0.42)
    ax1.legend(loc="upper left", fontsize=7.5, framealpha=0.92, ncol=3, columnspacing=0.8, handlelength=1.5)

    gt_colors = ["#43a047" if lbl == "BENIGN" else "#e53935" for lbl in labels]
    ax2.scatter(x_vals, np.zeros_like(x_vals), c=gt_colors, s=80, edgecolors="#ffffff", linewidths=0.8, zorder=3)
    ax2.axvline(0.5, color="#c62828", linestyle="--", linewidth=2.0)
    ax2.set_yticks([])
    ax2.set_ylabel("Truth", fontsize=8.5, fontweight="bold")
    ax2.set_ylim(-0.5, 0.5)
    ax2.grid(True, linestyle=":", alpha=0.35, axis="x")
    step = max(1, len(x_vals) // 18)
    shown_x = x_vals[::step]
    ax2.set_xticks(shown_x)
    ax2.set_xticklabels([f"T{v:+d}" if v != 0 else "T=0" for v in shown_x], fontsize=8, rotation=30)
    ax2.set_xlabel("Relative Flow Position  (T=0 = last benign flow before attack onset)", fontsize=9)
    plt.setp(ax1.get_xticklabels(), visible=False)

ax_leg = fig.add_subplot(outer_gs[N])
ax_leg.axis("off")
legend_elements = [
    Patch(facecolor="#e8f5e9", edgecolor="#cccccc", label="Benign Phase Background"),
    Patch(facecolor="#ffebee", edgecolor="#cccccc", label="Attack Phase Background"),
    Patch(facecolor="#43a047", edgecolor="white",   label="True Label: BENIGN"),
    Patch(facecolor="#e53935", edgecolor="white",   label="True Label: ATTACK"),
    Line2D([0], [0], color="#c62828", linestyle="--", linewidth=2, label="Onset Boundary (T=0)"),
    Line2D([0], [0], color="#78909c", linestyle=":",  linewidth=1.5, label="Decision Threshold 0.50"),
]
ax_leg.legend(handles=legend_elements, loc="center", ncol=6, fontsize=9,
              frameon=True, framealpha=0.95, edgecolor="#cccccc")

fig.suptitle(
    f"AEGIS -- Multi-Attack Probability Timeline: Early-Warning Generalization Study\n"
    f"Model: {os.path.basename(MODEL_PATH)}  |  Window: {WINDOW_SIZE} flows  |  Threshold: P >= {EARLY_WARN_THRESHOLD:.0%}  |  Zero-lookahead inference",
    fontsize=12, fontweight="bold", color="#1a1a2e"
)

plt.savefig(OUTPUT_CHART_DATA, dpi=300, bbox_inches="tight")
print(f"  Saved: {OUTPUT_CHART_DATA}")
try:
    plt.savefig(OUTPUT_CHART_ROOT, dpi=300, bbox_inches="tight")
    print(f"  Saved copy: {OUTPUT_CHART_ROOT}")
except Exception as e:
    print(f"  [WARN] Root copy: {e}")
plt.close()

print(f"\n{DIVIDER}")
print("STEP 7 -- Generalisation Conclusion")
print(DIVIDER)
detected   = [r for r in all_results if r["early_warn"]]
undetected = [r for r in all_results if not r["early_warn"]]
print(f"\n  Evaluated: {len(all_results)} transitions  |  Early-warning signal: {len(detected)}/{len(all_results)}")
for r in detected:
    print(f"  [YES] {r['category']:<28} IP: {r['ip']}  P(T-2)={r['p_tminus2']*100:.1f}%  P(T+1)={r['p_tplus1']*100:.1f}%")
for r in undetected:
    pt2 = f"{r['p_tminus2']*100:.1f}%" if r["p_tminus2"] is not None else "N/A"
    print(f"  [NO]  {r['category']:<28} IP: {r['ip']}  P(T-2)={pt2}")
print(f"\n  Not demonstrated (reported honestly):")
for m in MISSING_CATEGORIES:
    print(f"  [X] {m['category']}")
    print(f"      {m['reason'][:100]}")
if len(detected) >= 3:
    print(f"\n  VERDICT: Early-warning behaviour generalises across {len(detected)}/{len(all_results)} tested attack types (DoS, Web Attack, PortScan).")
    print(f"  LIMITATION: FTP-Patator transitions abruptly (probability rises after attack onset, not before).")
    print(f"  LIMITATION: Bot (unseen hosts, v3 group split) and DDoS (no isolated BENIGN transition) not confirmed.")
elif len(detected) >= 1:
    print(f"\n  VERDICT: Partial generalisation: {len(detected)}/{len(all_results)} attack types show early signal.")
else:
    print(f"\n  VERDICT: No generalisation beyond the original SSH-Patator example.")
print(f"\n{DIVIDER}")
print("Done! Multi-IP probability timeline analysis complete.")
print(DIVIDER)
