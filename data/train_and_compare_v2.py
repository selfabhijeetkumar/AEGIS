"""
Step 3 (v2) — Train & Compare: Logistic Regression vs LSTM (Per-IP Sequences)
=============================================================================
Loads true time-ordered per-IP sequences (v2), trains baseline LR and LSTM,
evaluates overall binary metrics and per-attack-class detection recall,
and outputs a comprehensive side-by-side performance analysis.

Outputs saved to DATA_DIR:
  lstm_model_v2.pth        — LSTM state_dict + architecture metadata
  training_summary_v2.txt  — full benchmark & per-class evaluation report
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
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR    = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
BATCH_SIZE  = 512       # 512 provides fast throughput on CPU/GPU
EPOCHS      = 15
LR          = 0.001
LSTM_HIDDEN = 64
LSTM_LAYERS = 1
DROPOUT     = 0.3
DIVIDER     = "=" * 75


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD DATA & LABELS
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load Data & Class Mappings")
print(DIVIDER)

def load(name):
    path = os.path.join(DATA_DIR, name)
    arr  = np.load(path)
    size_mb = os.path.getsize(path) / (1024 ** 2)
    print(f"  Loaded {name:<35} shape={str(arr.shape):<22} ({size_mb:.1f} MB)")
    return arr

print()
X_train      = load("X_train_v2.npy")
X_test       = load("X_test_v2.npy")
y_train      = load("y_train_v2.npy")
y_test       = load("y_test_v2.npy")
y_train_mc   = load("y_train_multiclass_v2.npy")
y_test_mc    = load("y_test_multiclass_v2.npy")
X_bl_train   = load("X_baseline_train_v2.npy")
X_bl_test    = load("X_baseline_test_v2.npy")

encoder_path  = os.path.join(DATA_DIR, "label_encoder_v2.pkl")
label_encoder = joblib.load(encoder_path)
classes       = list(label_encoder.classes_)
n_classes     = len(classes)

N_train, T, F = X_train.shape
N_test        = X_test.shape[0]

print(f"\n  Sequence Dataset  : Train={N_train:,} | Test={N_test:,} | Timesteps={T} | Features={F}")
print(f"  Baseline Dataset  : Train=({N_train:,}, {F}) | Test=({N_test:,}, {F})")
print(f"  Binary Class Ratio: Train 0={int((y_train==0).sum()):,} ({((y_train==0).mean()*100):.1f}%) | 1={int((y_train==1).sum()):,} ({((y_train==1).mean()*100):.1f}%)")

print(f"\n  Label Encoder ({n_classes} classes):")
for idx, name in enumerate(classes):
    print(f"    [{idx:>2}] {name}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — BASELINE: LOGISTIC REGRESSION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Train Baseline: Logistic Regression")
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
print(f"\n  Confusion Matrix (Binary):")
print(f"                Pred BENIGN (0)    Pred ATTACK (1)")
print(f"  Actual BENIGN   {lr_cm[0,0]:>12,}      {lr_cm[0,1]:>12,}")
print(f"  Actual ATTACK   {lr_cm[1,0]:>12,}      {lr_cm[1,1]:>12,}")

print(f"\n  Overall Baseline Metrics:")
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
    note = "LOW SAMPLE (<10)" if r["low_sample"] and r["total"] > 0 else ("NO SAMPLES IN TEST" if r["total"] == 0 else "")
    print(f"  {idx:>2} | {r['name']:<30} | {r['total']:>12,} | {r['correct']:>9,} | {r['recall']:>8.2f}% | {note}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — BUILD & TRAIN LSTM
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Build & Train LSTM Sequence Model")
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
        # x shape: (batch_size, seq_len, input_size)
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
print(f"  Actual ATTACK   {lstm_cm[1,0]:>12,}      {lstm_cm[1,1]:>12,}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 & 6 — PER-CLASS EVALUATION & FINAL COMPARISON
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 & 6 — Overall & Per-Class Direct Comparison (LR vs LSTM)")
print(DIVIDER)

lstm_per_class = compute_per_class_recall(y_test_mc, lstm_final_preds, classes)

# 1. Overall Binary Metrics Table
print(f"\n  ─── 1. Overall Binary Classification Performance ───\n")
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

f1_diff = (lstm_f1 - lr_f1) * 100.0
sign = "+" if f1_diff >= 0 else "-"
print(f"\n  LSTM Overall Improvement: {sign}{abs(f1_diff):.2f}% F1 over single-flow baseline")

# 2. Per-Class Recall Comparison Table
print(f"\n  ─── 2. Per-Class Attack Detection Recall Breakdown ───\n")
print(f"  {'ID':>2} | {'Attack Class Name':<28} | {'Test Samples':>12} | {'LR Recall':>10} | {'LSTM Recall':>12} | {'Delta':>10} | {'Highlight / Evidence'}")
print(f"  {'-'*2}-+-{'-'*28}-+-{'-'*12}-+-{'-'*10}-+-{'-'*12}-+-{'-'*10}-+-{'-'*25}")

for idx in range(n_classes):
    lr_r = lr_per_class[idx]
    ls_r = lstm_per_class[idx]
    delta = ls_r["recall"] - lr_r["recall"]

    if lr_r["total"] == 0:
        highlight = "No test samples"
        delta_str = "N/A"
    else:
        sym = "▲ +" if delta > 0.05 else ("▼ -" if delta < -0.05 else "  =")
        delta_str = f"{sym}{abs(delta):>5.1f}%"

        if lr_r["low_sample"]:
            highlight = "Low sample (<10)"
        elif delta >= 5.0:
            highlight = "★ Significant sequence gain"
        elif delta <= -5.0:
            highlight = "Single-flow performed better"
        else:
            highlight = "Comparable performance"

    lr_str   = f"{lr_r['recall']:>6.1f}%" if lr_r["total"] > 0 else "N/A"
    lstm_str = f"{ls_r['recall']:>6.1f}%" if ls_r["total"] > 0 else "N/A"

    print(f"  {idx:>2} | {lr_r['name']:<28} | {lr_r['total']:>12,} | {lr_str:>10} | {lstm_str:>12} | {delta_str:>10} | {highlight}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — SAVE MODEL & FULL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 7 — Save Artifacts & Training Summary")
print(DIVIDER)

# Save LSTM PyTorch Checkpoint
model_path = os.path.join(DATA_DIR, "lstm_model_v2.pth")
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
    "timestamp"      : time.strftime("%Y-%m-%d %H:%M:%S")
}, model_path)
print(f"\n  Saved model checkpoint → {model_path} ({os.path.getsize(model_path)/1024:.1f} KB)")

# Save Full Summary Report
summary_path = os.path.join(DATA_DIR, "training_summary_v2.txt")
with open(summary_path, "w", encoding="utf-8") as f:
    f.write("AEGIS Model Evaluation & Benchmark Summary (v2 — True Per-IP Sequences)\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"1. DATASET & CONFIGURATION\n")
    f.write(f"  Train Sequences : {N_train:,}\n")
    f.write(f"  Test Sequences  : {N_test:,}\n")
    f.write(f"  Sequence Length : {T} timesteps\n")
    f.write(f"  Feature Count   : {F} numeric features\n")
    f.write(f"  Device Used     : {device}\n")
    f.write(f"  LSTM Architecture: LSTM(in={F}, hidden={LSTM_HIDDEN}, layers={LSTM_LAYERS}) -> Dropout({DROPOUT}) -> Linear(1)\n\n")

    f.write(f"2. OVERALL BINARY CLASSIFICATION COMPARISON\n")
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
    f.write(f"\n  F1 Improvement over single-flow baseline: {sign}{abs(f1_diff):.2f}%\n\n")

    f.write(f"3. PER-CLASS ATTACK DETECTION RECALL BREAKDOWN\n")
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

    f.write(f"\n4. LSTM EPOCH TRAINING LOG\n")
    f.write(f"  {'Epoch':>5} | {'Loss':>10} | {'Val Acc':>8} | {'Val Prec':>9} | {'Val Rec':>8} | {'Val F1':>8}\n")
    for r in epoch_history:
        f.write(f"  {r['epoch']:>5} | {r['loss']:>10.5f} | {r['acc']*100:>7.2f}% | {r['prec']:>9.4f} | {r['rec']:>8.4f} | {r['f1']:>8.4f}\n")

print(f"  Saved full summary report → {summary_path}")

print(f"\n{DIVIDER}")
print("Done! Step 3 (v2) complete.")
print(f"Results and checkpoints stored in: {DATA_DIR}")
print(DIVIDER)
