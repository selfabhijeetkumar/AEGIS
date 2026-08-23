"""
Step 3 — Train & Compare: Logistic Regression vs LSTM
======================================================
Loads prepared sequence arrays, trains a baseline LR model and an LSTM,
prints per-epoch metrics, side-by-side comparison table, and saves artefacts.

Outputs (saved to DATA_DIR):
  lstm_model.pth        — LSTM state_dict
  training_summary.txt  — full metric report
"""

import io
import os
import sys
import time
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix
)

# ── Force UTF-8 stdout on Windows ──────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR    = r"C:\Users\Abhijeet\Downloads\archive (2)"
BATCH_SIZE  = 256
EPOCHS      = 15
LR          = 0.001
LSTM_HIDDEN = 64
LSTM_LAYERS = 1
DROPOUT     = 0.3
DIVIDER     = "=" * 70

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD DATA
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load Data")
print(DIVIDER)

def load(name):
    path = os.path.join(DATA_DIR, name)
    arr  = np.load(path)
    print(f"  {name:<30} shape={arr.shape}  dtype={arr.dtype}")
    return arr

print()
X_train    = load("X_train.npy")          # (N_train, 10, F)
X_test     = load("X_test.npy")           # (N_test,  10, F)
y_train    = load("y_train.npy")          # (N_train,)
y_test     = load("y_test.npy")           # (N_test,)
X_bl_train = load("X_baseline_train.npy") # (N_train, F)
X_bl_test  = load("X_baseline_test.npy")  # (N_test,  F)

N_train, T, F = X_train.shape
N_test        = X_test.shape[0]

print(f"\n  Sequence shape    : ({N_train:,}, {T}, {F})  [train]")
print(f"  Baseline shape    : ({N_train:,}, {F})  [train]")
print(f"  Train class split : 0={int((y_train==0).sum()):,}  1={int((y_train==1).sum()):,}")
print(f"  Test  class split : 0={int((y_test==0).sum()):,}   1={int((y_test==1).sum()):,}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — BASELINE: LOGISTIC REGRESSION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Baseline: Logistic Regression")
print(DIVIDER)

print("\n  Training LogisticRegression (class_weight='balanced') ...")
t0 = time.time()
lr_model = LogisticRegression(
    class_weight="balanced",
    max_iter=500,
    solver="saga",          # fast for large datasets
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

print(f"\n  Training time : {lr_train_time:.1f}s")
print(f"\n  Confusion Matrix:")
print(f"              Pred 0   Pred 1")
print(f"    Actual 0  {lr_cm[0,0]:>7,}  {lr_cm[0,1]:>7,}")
print(f"    Actual 1  {lr_cm[1,0]:>7,}  {lr_cm[1,1]:>7,}")
print(f"\n  Accuracy  : {lr_acc:.4f}  ({lr_acc*100:.2f}%)")
print(f"  Precision : {lr_prec:.4f}")
print(f"  Recall    : {lr_rec:.4f}")
print(f"  F1 Score  : {lr_f1:.4f}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — BUILD LSTM MODEL
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Build LSTM Model")
print(DIVIDER)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"\n  Device        : {device}")
if device.type == "cuda":
    print(f"  GPU           : {torch.cuda.get_device_name(0)}")
    print(f"  VRAM          : {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

class LSTMClassifier(nn.Module):
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
        # No sigmoid here — we use BCEWithLogitsLoss (numerically stable)

    def forward(self, x):
        # x: (batch, seq_len, input_size)
        out, _ = self.lstm(x)         # out: (batch, seq_len, hidden)
        last    = out[:, -1, :]       # take last timestep: (batch, hidden)
        dropped = self.dropout(last)
        logits  = self.fc(dropped)    # (batch, 1)
        return logits.squeeze(1)      # (batch,)

model = LSTMClassifier(F, LSTM_HIDDEN, LSTM_LAYERS, DROPOUT).to(device)

total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"\n  Architecture  :")
print(f"    LSTM({F} → hidden={LSTM_HIDDEN}, layers={LSTM_LAYERS}) → Dropout({DROPOUT}) → Linear(1)")
print(f"  Trainable params: {total_params:,}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — TRAIN LSTM
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Train LSTM")
print(DIVIDER)

# Class imbalance: pos_weight = count(0) / count(1)
neg = int((y_train == 0).sum())
pos = int((y_train == 1).sum())
pos_weight = torch.tensor([neg / pos], dtype=torch.float32).to(device)
print(f"\n  pos_weight for BCEWithLogitsLoss: {pos_weight.item():.2f}  "
      f"(neg={neg:,} / pos={pos:,})")

criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer = torch.optim.Adam(model.parameters(), lr=LR)

# DataLoaders
def make_loader(X, y, shuffle=True):
    Xt = torch.tensor(X, dtype=torch.float32)
    yt = torch.tensor(y, dtype=torch.float32)
    ds = TensorDataset(Xt, yt)
    return DataLoader(ds, batch_size=BATCH_SIZE, shuffle=shuffle,
                      num_workers=0, pin_memory=(device.type == "cuda"))

train_loader = make_loader(X_train, y_train, shuffle=True)
test_loader  = make_loader(X_test,  y_test,  shuffle=False)

print(f"  Batch size    : {BATCH_SIZE}")
print(f"  Train batches : {len(train_loader):,}")
print(f"  Test  batches : {len(test_loader):,}")
print(f"  Epochs        : {EPOCHS}")
print()

# Header
hdr = (f"{'Epoch':>5} | {'Train Loss':>10} | {'Acc':>7} | {'Prec':>7} | "
       f"{'Rec':>7} | {'F1':>7} | {'Time':>6}")
print(hdr)
print("-" * len(hdr))

epoch_history = []

def evaluate(loader):
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
        f1_score(yl, yp, zero_division=0)
    )

t_total = time.time()

for epoch in range(1, EPOCHS + 1):
    model.train()
    epoch_loss = 0.0
    t_ep = time.time()

    for Xb, yb in train_loader:
        Xb, yb = Xb.to(device), yb.to(device)
        optimizer.zero_grad()
        logits = model(Xb)
        loss   = criterion(logits, yb)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item() * len(yb)

    avg_loss = epoch_loss / N_train
    acc, prec, rec, f1 = evaluate(test_loader)
    ep_time = time.time() - t_ep

    row = {
        "epoch": epoch, "loss": avg_loss,
        "acc": acc, "prec": prec, "rec": rec, "f1": f1
    }
    epoch_history.append(row)

    print(f"{epoch:>5} | {avg_loss:>10.5f} | {acc:>7.4f} | {prec:>7.4f} | "
          f"{rec:>7.4f} | {f1:>7.4f} | {ep_time:>5.1f}s")

total_time = time.time() - t_total
print(f"\n  Total training time: {total_time:.1f}s  ({total_time/60:.1f} min)")

# Final LSTM metrics (last epoch)
lstm_acc  = epoch_history[-1]["acc"]
lstm_prec = epoch_history[-1]["prec"]
lstm_rec  = epoch_history[-1]["rec"]
lstm_f1   = epoch_history[-1]["f1"]

# Full confusion matrix for LSTM
model.eval()
lstm_preds, lstm_true = [], []
with torch.no_grad():
    for Xb, yb in test_loader:
        logits = model(Xb.to(device))
        preds  = (torch.sigmoid(logits) >= 0.5).long().cpu().numpy()
        lstm_preds.extend(preds)
        lstm_true.extend(yb.long().numpy())
lstm_cm = confusion_matrix(lstm_true, lstm_preds)

print(f"\n  LSTM Final Confusion Matrix:")
print(f"              Pred 0   Pred 1")
print(f"    Actual 0  {lstm_cm[0,0]:>7,}  {lstm_cm[0,1]:>7,}")
print(f"    Actual 1  {lstm_cm[1,0]:>7,}  {lstm_cm[1,1]:>7,}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — FINAL COMPARISON TABLE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Final Comparison Table")
print(DIVIDER)

metrics = [
    ("Accuracy",  lr_acc,  lstm_acc),
    ("Precision", lr_prec, lstm_prec),
    ("Recall",    lr_rec,  lstm_rec),
    ("F1 Score",  lr_f1,   lstm_f1),
]

print()
print(f"  {'Metric':<12} | {'Logistic Regression':>20} | {'LSTM':>10}")
print(f"  {'-'*12}-+-{'-'*20}-+-{'-'*10}")
for name, lr_val, lstm_val in metrics:
    delta = lstm_val - lr_val
    arrow = "▲" if delta >= 0 else "▼"
    print(f"  {name:<12} | {lr_val:>20.4f} | {lstm_val:>10.4f}  {arrow}{abs(delta):.4f}")

f1_delta = lstm_f1 - lr_f1
sign     = "+" if f1_delta >= 0 else "-"
print(f"\n  LSTM improvement over baseline: {sign}{abs(f1_delta)*100:.2f}% F1")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — SAVE MODEL & SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Save Model & Summary")
print(DIVIDER)

# Save LSTM weights
model_path = os.path.join(DATA_DIR, "lstm_model.pth")
torch.save({
    "state_dict"  : model.state_dict(),
    "input_size"  : F,
    "hidden_size" : LSTM_HIDDEN,
    "num_layers"  : LSTM_LAYERS,
    "dropout"     : DROPOUT,
    "epochs"      : EPOCHS,
    "final_f1"    : lstm_f1,
}, model_path)
print(f"\n  Saved lstm_model.pth  ({os.path.getsize(model_path)/1024:.1f} KB)")

# Save training summary
summary_path = os.path.join(DATA_DIR, "training_summary.txt")
with open(summary_path, "w", encoding="utf-8") as f:
    f.write("AEGIS — Step 3 Training Summary\n")
    f.write("=" * 50 + "\n\n")
    f.write(f"Dataset\n")
    f.write(f"  Train samples : {N_train:,}\n")
    f.write(f"  Test  samples : {N_test:,}\n")
    f.write(f"  Timesteps (T) : {T}\n")
    f.write(f"  Features  (F) : {F}\n\n")
    f.write(f"Logistic Regression (baseline)\n")
    f.write(f"  Training time : {lr_train_time:.1f}s\n")
    f.write(f"  Accuracy  : {lr_acc:.4f}\n")
    f.write(f"  Precision : {lr_prec:.4f}\n")
    f.write(f"  Recall    : {lr_rec:.4f}\n")
    f.write(f"  F1 Score  : {lr_f1:.4f}\n")
    f.write(f"  Confusion Matrix:\n")
    f.write(f"    TN={lr_cm[0,0]:,}  FP={lr_cm[0,1]:,}\n")
    f.write(f"    FN={lr_cm[1,0]:,}  TP={lr_cm[1,1]:,}\n\n")
    f.write(f"LSTM\n")
    f.write(f"  Architecture : LSTM(in={F}, hidden={LSTM_HIDDEN}, layers={LSTM_LAYERS})"
            f" -> Dropout({DROPOUT}) -> Linear(1)\n")
    f.write(f"  Params       : {total_params:,}\n")
    f.write(f"  Epochs       : {EPOCHS}\n")
    f.write(f"  Batch size   : {BATCH_SIZE}\n")
    f.write(f"  Learning rate: {LR}\n")
    f.write(f"  Device       : {device}\n")
    f.write(f"  Training time: {total_time:.1f}s\n")
    f.write(f"  Accuracy  : {lstm_acc:.4f}\n")
    f.write(f"  Precision : {lstm_prec:.4f}\n")
    f.write(f"  Recall    : {lstm_rec:.4f}\n")
    f.write(f"  F1 Score  : {lstm_f1:.4f}\n")
    f.write(f"  Confusion Matrix:\n")
    f.write(f"    TN={lstm_cm[0,0]:,}  FP={lstm_cm[0,1]:,}\n")
    f.write(f"    FN={lstm_cm[1,0]:,}  TP={lstm_cm[1,1]:,}\n\n")
    f.write(f"Per-Epoch History\n")
    f.write(f"  {'Epoch':>5}  {'Loss':>10}  {'Acc':>7}  {'Prec':>7}  {'Rec':>7}  {'F1':>7}\n")
    for r in epoch_history:
        f.write(f"  {r['epoch']:>5}  {r['loss']:>10.5f}  {r['acc']:>7.4f}  "
                f"{r['prec']:>7.4f}  {r['rec']:>7.4f}  {r['f1']:>7.4f}\n")
    f.write(f"\nF1 improvement over baseline: {sign}{abs(f1_delta)*100:.2f}%\n")

print(f"  Saved training_summary.txt")

print(f"\n{DIVIDER}")
print("Done! Artefacts saved to:")
print(f"  {DATA_DIR}")
print(f"\n  lstm_model.pth        — model weights (reload with torch.load)")
print(f"  training_summary.txt  — full metric report")
print(DIVIDER)
