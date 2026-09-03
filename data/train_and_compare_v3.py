"""
Step 3 (v3) — Train & Compare: Logistic Regression vs LSTM (Group-Based Zero-Leakage Split)
==========================================================================================
Loads true time-ordered per-IP sequences from the GroupShuffleSplit (v3),
trains baseline LR and LSTM under strict Source IP group isolation (0.00% leakage),
evaluates overall binary metrics and per-attack-class detection recall,
and outputs a rigorous, side-by-side comparison against the v2 split.

Outputs saved to DATA_DIR:
  lstm_model_v3.pth        — LSTM state_dict + architecture metadata
  training_summary_v3.txt  — full benchmark & per-class evaluation report (v3 vs v2)
"""

import io
import os
import sys
import time
import warnings
import numpy as np
import joblib
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix
)

# ── Force UTF-8 stdout on Windows ─────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION (Identical to train_and_compare_v2.py)
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR    = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
BATCH_SIZE  = 512       # 512 provides fast throughput on CPU/GPU
EPOCHS      = 15
LR          = 0.001
LSTM_HIDDEN = 64
LSTM_LAYERS = 1
DROPOUT     = 0.3
DIVIDER     = "=" * 78


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD v3 DATA & CLASS MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load v3 Group-Based Data & Class Mappings")
print(DIVIDER)

def load(name):
    path = os.path.join(DATA_DIR, name)
    arr  = np.load(path)
    size_mb = os.path.getsize(path) / (1024 ** 2)
    print(f"  Loaded {name:<35} shape={str(arr.shape):<22} ({size_mb:.1f} MB)")
    return arr

print()
X_train      = load("X_train_v3.npy")
X_test       = load("X_test_v3.npy")
y_train      = load("y_train_v3.npy")
y_test       = load("y_test_v3.npy")
y_train_mc   = load("y_train_multiclass_v3.npy")
y_test_mc    = load("y_test_multiclass_v3.npy")
X_bl_train   = load("X_baseline_train_v3.npy")
X_bl_test    = load("X_baseline_test_v3.npy")

encoder_path  = os.path.join(DATA_DIR, "label_encoder_v3.pkl")
label_encoder = joblib.load(encoder_path)
classes       = list(label_encoder.classes_)
n_classes     = len(classes)

N_train, T, F = X_train.shape
N_test        = X_test.shape[0]

print(f"\n  Sequence Dataset (v3) : Train={N_train:,} | Test={N_test:,} | Timesteps={T} | Features={F}")
print(f"  Baseline Dataset (v3) : Train=({N_train:,}, {F}) | Test=({N_test:,}, {F})")
print(f"  Binary Class Ratio    : Train 0={int((y_train==0).sum()):,} ({((y_train==0).mean()*100):.2f}%) | 1={int((y_train==1).sum()):,} ({((y_train==1).mean()*100):.2f}%)")
print(f"                        : Test  0={int((y_test==0).sum()):,} ({((y_test==0).mean()*100):.2f}%) | 1={int((y_test==1).sum()):,} ({((y_test==1).mean()*100):.2f}%)")

print(f"\n  Label Encoder ({n_classes} classes):")
for idx, name in enumerate(classes):
    cnt_tr = int((y_train_mc == idx).sum())
    cnt_te = int((y_test_mc == idx).sum())
    print(f"    [{idx:>2}] {name:<40} Train={cnt_tr:>9,} | Test={cnt_te:>9,}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — BASELINE: LOGISTIC REGRESSION (v3 Split)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Train Baseline: Logistic Regression (on v3 Split)")
print(DIVIDER)

print(f"\n  Training LogisticRegression (class_weight='balanced', solver='saga') ...")
t0 = time.time()
lr_model = LogisticRegression(
    class_weight="balanced",
    max_iter=500,
    solver="saga",
    n_jobs=-1,
    random_state=42
)
lr_model.fit(X_bl_train, y_train)
lr_train_time = time.time() - t0

lr_preds = lr_model.predict(X_bl_test)

lr_acc  = accuracy_score(y_test, lr_preds)
lr_prec = precision_score(y_test, lr_preds, zero_division=0)
lr_rec  = recall_score(y_test, lr_preds, zero_division=0)
lr_f1   = f1_score(y_test, lr_preds, zero_division=0)
lr_cm   = confusion_matrix(y_test, lr_preds)

print(f"  Training completed in {lr_train_time:.1f}s")
print(f"\n  Confusion Matrix (Binary LR):")
print(f"                Pred BENIGN (0)    Pred ATTACK (1)")
print(f"  Actual BENIGN   {lr_cm[0,0]:>12,}      {lr_cm[0,1]:>12,}")
if lr_cm.shape[0] > 1:
    print(f"  Actual ATTACK   {lr_cm[1,0]:>12,}      {lr_cm[1,1]:>12,}")

print(f"\n  Overall Baseline Metrics (v3):")
print(f"    Accuracy  : {lr_acc:.4f} ({lr_acc*100:.2f}%)")
print(f"    Precision : {lr_prec:.4f}")
print(f"    Recall    : {lr_rec:.4f}")
print(f"    F1 Score  : {lr_f1:.4f}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — PER-CLASS BASELINE EVALUATION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Per-Class Baseline Evaluation (Recall by Attack Type)")
print(DIVIDER)

def compute_per_class_recall(y_true_multiclass, binary_preds, class_names):
    """
    Computes per-class detection recall:
    For attack classes (id > 0): fraction where binary_pred == 1 (correctly flagged as attack)
    For BENIGN (id == 0): fraction where binary_pred == 0 (correctly flagged as benign)
    """
    results = {}
    for idx, name in enumerate(class_names):
        mask = (y_true_multiclass == idx)
        total_samples = int(mask.sum())
        if total_samples == 0:
            results[idx] = {
                "name": name,
                "total": 0,
                "correct": 0,
                "recall": 0.0,
                "low_sample": True
            }
            continue

        target_expected = 0 if idx == 0 else 1
        correct_detects = int((binary_preds[mask] == target_expected).sum())
        recall = (correct_detects / total_samples) * 100.0
        low_sample = total_samples < 10

        results[idx] = {
            "name": name,
            "total": total_samples,
            "correct": correct_detects,
            "recall": recall,
            "low_sample": low_sample
        }
    return results

lr_per_class = compute_per_class_recall(y_test_mc, lr_preds, classes)

print(f"\n  {'ID':>2} | {'Class Name':<30} | {'Test Samples':>12} | {'Detected':>9} | {'Recall %':>9} | {'Note'}")
print(f"  {'-'*2}-+-{'-'*30}-+-{'-'*12}-+-{'-'*9}-+-{'-'*9}-+-{'-'*30}")
for idx in range(n_classes):
    r = lr_per_class[idx]
    note = "LOW SAMPLE (<10)" if r["low_sample"] and r["total"] > 0 else ("NO SAMPLES IN TEST SET" if r["total"] == 0 else "")
    print(f"  {idx:>2} | {r['name']:<30} | {r['total']:>12,} | {r['correct']:>9,} | {r['recall']:>8.2f}% | {note}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — BUILD & TRAIN LSTM (v3 Group Split)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Build & Train LSTM Sequence Model (v3 Split)")
print(DIVIDER)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"\n  Compute Device : {device}")
if device.type == "cuda":
    print(f"  GPU Name       : {torch.cuda.get_device_name(0)}")
    print(f"  VRAM Available : {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

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

model = LSTMDetector(F, LSTM_HIDDEN, LSTM_LAYERS, DROPOUT).to(device)
total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

print(f"\n  Architecture   : LSTM(in={F} → hidden={LSTM_HIDDEN}, layers={LSTM_LAYERS}) → Dropout({DROPOUT}) → Linear(1)")
print(f"  Trainable Param: {total_params:,}")

# Handle class imbalance via pos_weight in BCEWithLogitsLoss
neg_count = int((y_train == 0).sum())
pos_count = int((y_train == 1).sum())
pos_weight = torch.tensor([neg_count / pos_count], dtype=torch.float32).to(device)
print(f"  Loss Function  : BCEWithLogitsLoss (pos_weight={pos_weight.item():.2f})")

criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer = torch.optim.Adam(model.parameters(), lr=LR)

# DataLoaders
def make_loader(X, y, batch_size, shuffle=True):
    Xt = torch.tensor(X, dtype=torch.float32)
    yt = torch.tensor(y, dtype=torch.float32)
    ds = TensorDataset(Xt, yt)
    return DataLoader(
        ds,
        batch_size  = batch_size,
        shuffle     = shuffle,
        pin_memory  = (device.type == "cuda"),
        num_workers = 0
    )

train_loader = make_loader(X_train, y_train, BATCH_SIZE, shuffle=True)
test_loader  = make_loader(X_test,  y_test,  BATCH_SIZE, shuffle=False)

print(f"  Batch Size     : {BATCH_SIZE}")
print(f"  Train Batches  : {len(train_loader):,}")
print(f"  Test Batches   : {len(test_loader):,}")
print(f"  Epochs         : {EPOCHS}\n")

def evaluate_model(loader):
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for Xb, yb in loader:
            Xb = Xb.to(device)
            logits = model(Xb)
            preds  = (torch.sigmoid(logits) >= 0.5).long().cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(yb.long().numpy())
    yp = np.array(all_preds)
    yl = np.array(all_labels)
    return (
        accuracy_score(yl, yp),
        precision_score(yl, yp, zero_division=0),
        recall_score(yl, yp, zero_division=0),
        f1_score(yl, yp, zero_division=0),
        yp
    )

hdr = f"  {'Epoch':>5} | {'Train Loss':>11} | {'Val Acc':>8} | {'Val Prec':>9} | {'Val Rec':>8} | {'Val F1':>8} | {'Time':>6}"
print(hdr)
print("  " + "-" * (len(hdr) - 2))

epoch_history = []
t_start = time.time()
lstm_final_preds = None

for epoch in range(1, EPOCHS + 1):
    model.train()
    running_loss = 0.0
    t_ep = time.time()

    for Xb, yb in train_loader:
        Xb, yb = Xb.to(device), yb.to(device)
        optimizer.zero_grad()
        logits = model(Xb)
        loss   = criterion(logits, yb)
        loss.backward()
        optimizer.step()
        running_loss += loss.item() * len(yb)

    avg_loss = running_loss / N_train
    acc, prec, rec, f1, preds = evaluate_model(test_loader)
    lstm_final_preds = preds
    ep_duration = time.time() - t_ep

    epoch_history.append({
        "epoch": epoch, "loss": avg_loss,
        "acc": acc, "prec": prec, "rec": rec, "f1": f1
    })

    print(f"  {epoch:>5} | {avg_loss:>11.5f} | {acc*100:>7.2f}% | {prec:>9.4f} | {rec:>8.4f} | {f1:>8.4f} | {ep_duration:>5.1f}s")

lstm_train_time = time.time() - t_start
print(f"\n  LSTM Training completed in {lstm_train_time:.1f}s ({lstm_train_time/60:.1f} min)")

# LSTM Final metrics
lstm_acc  = epoch_history[-1]["acc"]
lstm_prec = epoch_history[-1]["prec"]
lstm_rec  = epoch_history[-1]["rec"]
lstm_f1   = epoch_history[-1]["f1"]
lstm_cm   = confusion_matrix(y_test, lstm_final_preds)

print(f"\n  Confusion Matrix (LSTM):")
print(f"                Pred BENIGN (0)    Pred ATTACK (1)")
print(f"  Actual BENIGN   {lstm_cm[0,0]:>12,}      {lstm_cm[0,1]:>12,}")
if lstm_cm.shape[0] > 1:
    print(f"  Actual ATTACK   {lstm_cm[1,0]:>12,}      {lstm_cm[1,1]:>12,}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — PER-CLASS EVALUATION & FINAL COMPARISON (v2 vs v3)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Per-Class Evaluation & Stricter v2 vs v3 Methodology Comparison")
print(DIVIDER)

lstm_per_class = compute_per_class_recall(y_test_mc, lstm_final_preds, classes)

# Baseline v2 metrics from training_summary_v2.txt for comparison
v2_overall_f1 = 0.9931
v2_recalls = {
    "SSH-Patator": "100.0%",
    "Web Attack ? Brute Force": "100.0%",
    "FTP-Patator": "99.4%",
    "Bot": "47.4%",
    "BENIGN": "99.7%",
}

# 1. Overall Binary Metrics Table (v3)
print(f"\n  ─── 1. v3 Binary Classification Performance (Strict Group Split) ───\n")
print(f"  {'Metric':<15} | {'Logistic Regression':>20} | {'LSTM (Per-IP)':>15} | {'Delta':>10}")
print(f"  {'-'*15}-+-{'-'*20}-+-{'-'*15}-+-{'-'*10}")
for name, lr_v, ls_v in [
    ("Accuracy",  lr_acc,  lstm_acc),
    ("Precision", lr_prec, lstm_prec),
    ("Recall",    lr_rec,  lstm_rec),
    ("F1 Score",  lr_f1,   lstm_f1),
]:
    diff = ls_v - lr_v
    sym  = "▲ +" if diff >= 0 else "▼ -"
    print(f"  {name:<15} | {lr_v*100:>19.2f}% | {ls_v*100:>14.2f}% | {sym}{abs(diff)*100:>5.2f}%")

# 2. Required Specific Comparison Table (v2 vs v3)
print(f"\n  ─── 2. Requested Side-by-Side Methodology Comparison (v2 vs v3) ───\n")
print(f"  {'Metric':<35} | {'v2 (Random Split / Leakage)':>30} | {'v3 (Group Split / Zero Leak)':>30}")
print(f"  {'-'*35}-+-{'-'*30}-+-{'-'*30}")
print(f"  {'Overall F1':<35} | {v2_overall_f1*100:>29.2f}% | {lstm_f1*100:>29.2f}%")

# Specific requested attack classes
target_classes = [
    "SSH-Patator",
    "Web Attack \x87 Brute Force" if "Web Attack \x87 Brute Force" in classes else ("Web Attack ? Brute Force" if "Web Attack ? Brute Force" in classes else "Web Attack - Brute Force"),
    "FTP-Patator",
]

for target in ["SSH-Patator", "Web Attack ? Brute Force", "FTP-Patator"]:
    matched_idx = None
    for idx, cname in enumerate(classes):
        if target.lower() in cname.lower() or cname.lower() in target.lower():
            matched_idx = idx
            break
    
    v2_val = v2_recalls.get(target, "N/A")
    if matched_idx is not None:
        c_info = lstm_per_class[matched_idx]
        if c_info["total"] > 0:
            v3_val = f"{c_info['recall']:.1f}% ({c_info['correct']}/{c_info['total']})"
        else:
            v3_val = "N/A (Grouped to Train Set)"
    else:
        v3_val = "N/A"
    
    label_display = target.replace("?", "-") + " Recall"
    print(f"  {label_display:<35} | {v2_val:>30} | {v3_val:>30}")

# Also show Bot class which has test samples in both
bot_idx = classes.index("Bot") if "Bot" in classes else 1
bot_info = lstm_per_class[bot_idx]
bot_v3_val = f"{bot_info['recall']:.1f}% ({bot_info['correct']}/{bot_info['total']})"
print(f"  {'Bot Attack Recall':<35} | {v2_recalls['Bot']:>30} | {bot_v3_val:>30}")
print(f"  {'BENIGN Specificity (Recall)':<35} | {v2_recalls['BENIGN']:>30} | {lstm_per_class[0]['recall']:>29.2f}%")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — SAVE MODEL CHECKPOINT & DETAILED SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Save Checkpoint & Full Summary Report")
print(DIVIDER)

model_path = os.path.join(DATA_DIR, "lstm_model_v3.pth")
torch.save({
    "state_dict"     : model.state_dict(),
    "input_size"     : F,
    "hidden_size"    : LSTM_HIDDEN,
    "num_layers"     : LSTM_LAYERS,
    "dropout"        : DROPOUT,
    "epochs"         : EPOCHS,
    "final_val_acc"  : lstm_acc,
    "final_val_f1"   : lstm_f1,
    "label_classes"  : classes,
    "feature_count"  : F,
    "split_version"  : "v3_group_source_ip_zero_leakage",
    "timestamp"      : time.strftime("%Y-%m-%d %H:%M:%S")
}, model_path)
print(f"  Saved model checkpoint → {model_path} ({os.path.getsize(model_path)/1024:.1f} KB)")

summary_path = os.path.join(DATA_DIR, "training_summary_v3.txt")
with open(summary_path, "w", encoding="utf-8") as f:
    f.write("AEGIS Model Evaluation & Benchmark Summary (v3 — Group-Based Zero-Leakage Split)\n")
    f.write("=" * 80 + "\n\n")
    f.write("1. DATASET & CONFIGURATION\n")
    f.write(f"  Train Sequences : {N_train:,}\n")
    f.write(f"  Test Sequences  : {N_test:,}\n")
    f.write(f"  Sequence Length : {T} timesteps\n")
    f.write(f"  Feature Count   : {F} numeric features\n")
    f.write(f"  Split Strategy  : GroupShuffleSplit (Source IP grouped, 0.00% overlap)\n")
    f.write(f"  Device Used     : {device}\n")
    f.write(f"  LSTM Architecture: LSTM(in={F}, hidden={LSTM_HIDDEN}, layers={LSTM_LAYERS}) -> Dropout({DROPOUT}) -> Linear(1)\n\n")

    f.write("2. OVERALL BINARY CLASSIFICATION COMPARISON (v3)\n")
    f.write(f"  {'Metric':<15} | {'Logistic Regression':>20} | {'LSTM (Per-IP)':>15} | {'Delta':>10}\n")
    f.write(f"  {'-'*15}-+-{'-'*20}-+-{'-'*15}-+-{'-'*10}\n")
    for name, lr_v, ls_v in [
        ("Accuracy",  lr_acc,  lstm_acc),
        ("Precision", lr_prec, lstm_prec),
        ("Recall",    lr_rec,  lstm_rec),
        ("F1 Score",  lr_f1,   lstm_f1),
    ]:
        diff = ls_v - lr_v
        sym  = "▲ +" if diff >= 0 else "▼ -"
        f.write(f"  {name:<15} | {lr_v*100:>19.2f}% | {ls_v*100:>14.2f}% | {sym}{abs(diff)*100:>5.2f}%\n")

    f.write("\n3. METHODOLOGY COMPARISON: v2 (RANDOM SPLIT) vs v3 (GROUP-BASED ZERO-LEAK SPLIT)\n")
    f.write(f"  {'Metric':<35} | {'v2 (Random / Potential Leak)':>30} | {'v3 (Group / Zero Leak)':>30}\n")
    f.write(f"  {'-'*35}-+-{'-'*30}-+-{'-'*30}\n")
    f.write(f"  {'Overall F1':<35} | {v2_overall_f1*100:>29.2f}% | {lstm_f1*100:>29.2f}%\n")
    for target in ["SSH-Patator", "Web Attack ? Brute Force", "FTP-Patator"]:
        matched_idx = None
        for idx, cname in enumerate(classes):
            if target.lower() in cname.lower() or cname.lower() in target.lower():
                matched_idx = idx
                break
        v2_val = v2_recalls.get(target, "N/A")
        if matched_idx is not None and lstm_per_class[matched_idx]["total"] > 0:
            c_info = lstm_per_class[matched_idx]
            v3_val = f"{c_info['recall']:.1f}% ({c_info['correct']}/{c_info['total']})"
        else:
            v3_val = "N/A (Grouped to Train)"
        label_display = target.replace("?", "-") + " Recall"
        f.write(f"  {label_display:<35} | {v2_val:>30} | {v3_val:>30}\n")
    f.write(f"  {'Bot Attack Recall':<35} | {v2_recalls['Bot']:>30} | {bot_v3_val:>30}\n")
    f.write(f"  {'BENIGN Specificity (Recall)':<35} | {v2_recalls['BENIGN']:>30} | {lstm_per_class[0]['recall']:>29.2f}%\n\n")

    f.write("4. PER-CLASS ATTACK DETECTION RECALL BREAKDOWN (v3 Test Set)\n")
    f.write(f"  {'ID':>2} | {'Attack Class Name':<28} | {'Test Samples':>12} | {'LR Recall':>10} | {'LSTM Recall':>12} | {'Delta':>10}\n")
    f.write(f"  {'-'*2}-+-{'-'*28}-+-{'-'*12}-+-{'-'*10}-+-{'-'*12}-+-{'-'*10}\n")
    for idx in range(n_classes):
        lr_r = lr_per_class[idx]
        ls_r = lstm_per_class[idx]
        delta = ls_r["recall"] - lr_r["recall"]
        if lr_r["total"] == 0:
            delta_str = "N/A"
            lr_str = "N/A"
            lstm_str = "N/A"
        else:
            sym = "▲ +" if delta > 0.05 else ("▼ -" if delta < -0.05 else "  =")
            delta_str = f"{sym}{abs(delta):>5.1f}%"
            lr_str   = f"{lr_r['recall']:>6.1f}%"
            lstm_str = f"{ls_r['recall']:>6.1f}%"
        f.write(f"  {idx:>2} | {lr_r['name']:<28} | {lr_r['total']:>12,} | {lr_str:>10} | {lstm_str:>12} | {delta_str:>10}\n")

    f.write("\n5. LSTM EPOCH TRAINING LOG (v3)\n")
    f.write(f"  {'Epoch':>5} | {'Loss':>10} | {'Val Acc':>8} | {'Val Prec':>9} | {'Val Rec':>8} | {'Val F1':>8}\n")
    for r in epoch_history:
        f.write(f"  {r['epoch']:>5} | {r['loss']:>10.5f} | {r['acc']*100:>7.2f}% | {r['prec']:>9.4f} | {r['rec']:>8.4f} | {r['f1']:>8.4f}\n")

print(f"  Saved full summary report → {summary_path}")

print(f"\n{DIVIDER}")
print("Done! Step 3 (v3) complete.")
print(f"Results and checkpoints stored in: {DATA_DIR}")
print(DIVIDER)
