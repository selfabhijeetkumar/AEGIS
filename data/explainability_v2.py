"""
Step 4 (v2) — Model Explainability & Feature Attribution for AEGIS LSTM
========================================================================
Analyzes how the temporal LSTM makes intrusion decisions on per-IP sequences.
Selects 20 correctly predicted test samples (10 diverse attacks + 10 benign),
computes feature importance via SHAP GradientExplainer (with graceful fallback
to temporal feature perturbation attribution), and identifies key drivers.

Outputs saved to DATA_DIR:
  explainability_report_v2.txt — detailed sample-by-sample & global attribution report
"""

import io
import os
import sys
import time
import warnings
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn

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
CSV_PATH     = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")
REPORT_PATH  = os.path.join(DATA_DIR, "explainability_report_v2.txt")
N_BACKGROUND = 100
N_SAMPLES    = 20       # 10 attacks, 10 benign
DIVIDER      = "=" * 75


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD MODEL & METADATA
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load Trained LSTM Model & Architecture Checkpoint")
print(DIVIDER)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"  Compute Device : {device}")

if not os.path.exists(MODEL_PATH):
    print(f"\n  [ERROR] Model checkpoint not found at: {MODEL_PATH}")
    print("  Please ensure train_and_compare_v2.py has finished saving lstm_model_v2.pth.")
    sys.exit(1)

checkpoint = torch.save if False else torch.load(MODEL_PATH, map_location=device)
input_size  = checkpoint.get("input_size", 79)
hidden_size = checkpoint.get("hidden_size", 64)
num_layers  = checkpoint.get("num_layers", 1)
dropout     = checkpoint.get("dropout", 0.3)

print(f"  Loaded Checkpoint Metadata:")
print(f"    Input Size   : {input_size} features")
print(f"    Hidden Size  : {hidden_size}")
print(f"    Num Layers   : {num_layers}")
print(f"    Dropout      : {dropout}")
print(f"    Final Val Acc: {checkpoint.get('final_val_acc', 0.0)*100:.2f}%")
print(f"    Final Val F1 : {checkpoint.get('final_val_f1', 0.0):.4f}")

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
print(f"  ✓ Model weights loaded and set to evaluation mode.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — LOAD TEST DATA, LABELS & FEATURE NAMES
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Load Dataset, Label Encoder & Feature Names")
print(DIVIDER)

X_test_path    = os.path.join(DATA_DIR, "X_test_v2.npy")
y_test_path    = os.path.join(DATA_DIR, "y_test_v2.npy")
y_mc_path      = os.path.join(DATA_DIR, "y_test_multiclass_v2.npy")
encoder_path   = os.path.join(DATA_DIR, "label_encoder_v2.pkl")

X_test  = np.load(X_test_path)
y_test  = np.load(y_test_path)
y_mc    = np.load(y_mc_path)
encoder = joblib.load(encoder_path)
classes = list(encoder.classes_)

print(f"  Test Sequences : {X_test.shape} (N={len(X_test):,}, T={X_test.shape[1]}, F={X_test.shape[2]})")
print(f"  Label Classes  : {len(classes)} categories: {classes}")

# Extract exact feature column names
peek = pd.read_csv(CSV_PATH, nrows=1, low_memory=False, encoding="utf-8")
peek.columns = peek.columns.str.strip()
exclude_always = {
    "Flow ID", "Source IP", "Destination IP", "Timestamp",
    "Label", "Label_Binary", "day_file", "Fwd Header Length.1"
}
non_numeric = set(peek.select_dtypes(exclude=[np.number]).columns.tolist())
exclude_all = exclude_always | non_numeric | {"Label_Int", "Timestamp_dt"}
feature_names = [c for c in peek.columns if c not in exclude_all]

print(f"  Extracted {len(feature_names)} feature names from CSV schema.")
if len(feature_names) != input_size:
    print(f"  ⚠ Feature count mismatch: {len(feature_names)} vs {input_size}. Using generic indices.")
    feature_names = [f"Feature_{i}" for i in range(input_size)]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — SELECT 20 REPRESENTATIVE TEST SAMPLES (10 ATTACKS + 10 BENIGN)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Select Diverse Correctly-Predicted Test Sequences")
print(DIVIDER)

# Run batch inference over test set to find high-confidence correct predictions
print(f"  Running inference over test set ...")
batch_size = 512
probs = []
with torch.no_grad():
    for i in range(0, len(X_test), batch_size):
        batch = torch.tensor(X_test[i : i + batch_size], dtype=torch.float32).to(device)
        logits = model(batch)
        p = torch.sigmoid(logits).cpu().numpy()
        probs.extend(p)

probs = np.array(probs)
preds = (probs >= 0.5).astype(int)

# Correct masks
correct_benign_idx = np.where((y_test == 0) & (preds == 0))[0]
correct_attack_idx = np.where((y_test == 1) & (preds == 1))[0]

print(f"  Correct Benign Predictions: {len(correct_benign_idx):,} / {(y_test==0).sum():,}")
print(f"  Correct Attack Predictions: {len(correct_attack_idx):,} / {(y_test==1).sum():,}")

# Select 10 diverse attacks (spanning different attack types)
attack_selection = []
attack_classes_present = np.unique(y_mc[correct_attack_idx])

# Prioritize selecting from each attack type
for cls_id in attack_classes_present:
    cls_correct = correct_attack_idx[y_mc[correct_attack_idx] == cls_id]
    if len(cls_correct) > 0:
        # Sort by confidence
        sorted_by_conf = cls_correct[np.argsort(-probs[cls_correct])]
        attack_selection.append(sorted_by_conf[0])
        if len(attack_selection) >= 10:
            break

# If fewer than 10 unique attack types, fill remaining with highest confidence attacks
if len(attack_selection) < 10:
    remaining_needed = 10 - len(attack_selection)
    already_selected = set(attack_selection)
    candidates = [idx for idx in correct_attack_idx if idx not in already_selected]
    sorted_candidates = sorted(candidates, key=lambda i: probs[i], reverse=True)
    attack_selection.extend(sorted_candidates[:remaining_needed])

# Select 10 benign samples (diverse confidence levels)
rng = np.random.default_rng(42)
benign_selection = list(rng.choice(correct_benign_idx, size=10, replace=False))

selected_indices = attack_selection + benign_selection
selected_X       = X_test[selected_indices]
selected_y_bin   = y_test[selected_indices]
selected_y_mc    = y_mc[selected_indices]
selected_probs   = probs[selected_indices]
selected_preds   = preds[selected_indices]

print(f"\n  Selected 20 Evaluation Sequences:")
print(f"  {'#':>2} | {'Idx':>6} | {'True Class':<28} | {'Binary':>6} | {'P(Attack)':>9} | {'Pred'}")
print(f"  {'-'*2}-+-{'-'*6}-+-{'-'*28}-+-{'-'*6}-+-{'-'*9}-+-{'-'*8}")
for i, idx in enumerate(selected_indices, 1):
    cls_name = classes[selected_y_mc[i-1]]
    bin_lbl  = "ATTACK" if selected_y_bin[i-1] == 1 else "BENIGN"
    pred_lbl = "ATTACK" if selected_preds[i-1] == 1 else "BENIGN"
    print(f"  {i:>2} | {idx:>6} | {cls_name:<28} | {bin_lbl:>6} | {selected_probs[i-1]:>9.4f} | {pred_lbl}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — EXPLAINABILITY ENGINE (SHAP GradientExplainer with Perturbation Fallback)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Compute Feature Attributions (SHAP / Temporal Perturbation)")
print(DIVIDER)

# Select background dataset (~100 random samples from X_test or X_train)
bg_idx = rng.choice(len(X_test), size=min(N_BACKGROUND, len(X_test)), replace=False)
background_tensor = torch.tensor(X_test[bg_idx], dtype=torch.float32).to(device)
eval_tensor       = torch.tensor(selected_X, dtype=torch.float32).to(device)

attribution_method = None
attributions_matrix = None   # shape: (20, 79) - signed feature importance per sample

# Try SHAP GradientExplainer first
try:
    import shap
    print(f"\n  Attempting SHAP GradientExplainer (background={N_BACKGROUND} sequences) ...")
    explainer = shap.GradientExplainer(model, background_tensor)
    shap_vals = explainer.shap_values(eval_tensor)

    # shap_vals can be a list or 3D ndarray: shape (20, 10, 79)
    if isinstance(shap_vals, list):
        shap_array = shap_vals[0]
    else:
        shap_array = shap_vals

    # Sum across the 10 timesteps to get total signed attribution per feature
    attributions_matrix = np.sum(shap_array, axis=1)  # shape: (20, 79)
    attribution_method = "SHAP GradientExplainer"
    print(f"  ✓ SHAP GradientExplainer successfully computed temporal attributions.")

except Exception as e:
    print(f"\n  ⚠ SHAP GradientExplainer encountered an issue: {e}")
    print(f"  → Switching to Fallback: Temporal Feature Perturbation Attribution (Zero-out baseline)")

    attribution_method = "Temporal Feature Perturbation (Occlusion / Impact Attribution)"
    attributions = np.zeros((len(selected_X), input_size), dtype=np.float32)

    with torch.no_grad():
        for s_idx in range(len(selected_X)):
            orig_seq = torch.tensor(selected_X[s_idx:s_idx+1], dtype=torch.float32).to(device)
            base_prob = torch.sigmoid(model(orig_seq)).item()

            # Zero-out one feature across all 10 timesteps
            for f_idx in range(input_size):
                perturbed_seq = orig_seq.clone()
                perturbed_seq[0, :, f_idx] = 0.0  # zero-out (mean in scaled space)
                pert_prob = torch.sigmoid(model(perturbed_seq)).item()

                # Positive delta means this feature increased attack probability
                # Negative delta means this feature pushed probability towards benign
                attributions[s_idx, f_idx] = base_prob - pert_prob

    attributions_matrix = attributions
    print(f"  ✓ Temporal Feature Perturbation attributions computed for all 20 samples.")

print(f"\n  Active Attribution Method: {attribution_method}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — INDIVIDUAL SAMPLE BREAKDOWN (TOP 5 FEATURES PER SAMPLE)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Top 5 Contributing Features per Evaluation Sequence")
print(DIVIDER)

sample_reports = []
top_feature_counter = {}

for s_idx in range(len(selected_indices)):
    cls_name  = classes[selected_y_mc[s_idx]]
    bin_lbl   = "ATTACK" if selected_y_bin[s_idx] == 1 else "BENIGN"
    prob      = selected_probs[s_idx]
    pred_lbl  = "ATTACK" if selected_preds[s_idx] == 1 else "BENIGN"

    attr = attributions_matrix[s_idx]
    # Rank features by absolute attribution magnitude
    ranked_idx = np.argsort(-np.abs(attr))
    top5_idx   = ranked_idx[:5]

    header = f"Sample #{s_idx+1:02d} | True Class: {cls_name} ({bin_lbl}) | Pred: {pred_lbl} [P(Attack)={prob:.4f}]"
    print(f"\n  {header}")
    print(f"  {'-'*len(header)}")

    lines = []
    for rank, f_i in enumerate(top5_idx, 1):
        f_name = feature_names[f_i]
        val    = attr[f_i]
        direction = "+ (Supports ATTACK)" if val > 0 else "- (Supports BENIGN)"
        line = f"    #{rank}. {f_name:<36} | Attribution = {val:>+10.5f} | {direction}"
        print(line)
        lines.append(line)

        # Track global frequency of top features
        top_feature_counter[f_name] = top_feature_counter.get(f_name, 0) + 1

    sample_reports.append({
        "header": header,
        "class": cls_name,
        "prob": prob,
        "pred": pred_lbl,
        "lines": lines,
        "top_features": [feature_names[f_i] for f_i in top5_idx]
    })


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — GLOBAL FEATURE IMPORTANCE SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Global Key Feature Drivers (Top Contributors Across Samples)")
print(DIVIDER)

# Sort features by frequency in Top 5
sorted_freq = sorted(top_feature_counter.items(), key=lambda kv: kv[1], reverse=True)

# Also compute mean absolute attribution across all 20 samples
mean_abs_attr = np.mean(np.abs(attributions_matrix), axis=0)
top_global_indices = np.argsort(-mean_abs_attr)[:10]

print(f"\n  ─── 1. Most Frequent Top-5 Contributors (Out of {len(selected_indices)} Samples) ───")
print(f"  {'Rank':>4} | {'Feature Name':<38} | {'Top-5 Frequency':>15} | {'Appearance %'}")
print(f"  {'-'*4}-+-{'-'*38}-+-{'-'*15}-+-{'-'*12}")
for r, (fname, cnt) in enumerate(sorted_freq[:10], 1):
    pct = (cnt / len(selected_indices)) * 100.0
    bar = "█" * int(cnt)
    print(f"  {r:>4} | {fname:<38} | {cnt:>12} / {len(selected_indices)} | {pct:>5.1f}%  {bar}")

print(f"\n  ─── 2. Top 10 Features by Mean Absolute Attribution Magnitude ───")
print(f"  {'Rank':>4} | {'Feature Name':<38} | {'Mean |Attribution|':>18}")
print(f"  {'-'*4}-+-{'-'*38}-+-{'-'*18}")
for r, f_i in enumerate(top_global_indices, 1):
    print(f"  {r:>4} | {feature_names[f_i]:<38} | {mean_abs_attr[f_i]:>18.6f}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — SAVE DETAILED EXPLAINABILITY REPORT
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 7 — Save Explainability Report")
print(DIVIDER)

with open(REPORT_PATH, "w", encoding="utf-8") as f:
    f.write("AEGIS LSTM Temporal Model Explainability & Attribution Report (v2)\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"Attribution Engine : {attribution_method}\n")
    f.write(f"Sample Size        : {len(selected_indices)} sequences (10 Attacks + 10 Benign)\n")
    f.write(f"Sequence Dimensions: {X_test.shape[1]} Timesteps x {input_size} Features\n\n")

    f.write("1. GLOBAL KEY DRIVERS (MOST FREQUENT IN TOP 5)\n")
    f.write(f"  {'Rank':>4} | {'Feature Name':<38} | {'Frequency':>10} | {'Appearance %'}\n")
    f.write(f"  {'-'*4}-+-{'-'*38}-+-{'-'*10}-+-{'-'*12}\n")
    for r, (fname, cnt) in enumerate(sorted_freq[:10], 1):
        pct = (cnt / len(selected_indices)) * 100.0
        f.write(f"  {r:>4} | {fname:<38} | {cnt:>7} / {len(selected_indices)} | {pct:>5.1f}%\n")

    f.write("\n\n2. INDIVIDUAL SEQUENCE EXPLANATIONS\n")
    f.write("=" * 80 + "\n")
    for rep in sample_reports:
        f.write(f"\n{rep['header']}\n")
        f.write("-" * len(rep['header']) + "\n")
        for line in rep['lines']:
            f.write(line + "\n")

print(f"  Saved full explainability report → {REPORT_PATH}")
print(f"\n{DIVIDER}")
print("Done! Explainability analysis complete.")
print(DIVIDER)
