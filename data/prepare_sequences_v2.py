"""
Step 2 (v2) — Prepare True Per-IP Time-Ordered Sequences
=========================================================
Uses combined_cicids2017_v2.csv which retains Source IP, Destination IP,
Flow ID, and Timestamp — enabling genuine chronological per-IP sequences.

Outputs saved to DATA_DIR:
  X_train_v2.npy              — (N, 10, F)  sequence train set
  X_test_v2.npy               — (N, 10, F)  sequence test set
  y_train_v2.npy              — (N,)  binary targets  (0=BENIGN, 1=ATTACK)
  y_test_v2.npy               — (N,)  binary targets
  y_train_multiclass_v2.npy  — (N,)  integer multi-class targets
  y_test_multiclass_v2.npy   — (N,)  integer multi-class targets
  X_baseline_train_v2.npy    — (N, F)  last-timestep flat features
  X_baseline_test_v2.npy     — (N, F)  last-timestep flat features
  scaler_v2.pkl               — fitted StandardScaler
  label_encoder_v2.pkl        — LabelEncoder (index → class name mapping)
"""

import io
import os
import sys
import warnings
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# ── Force UTF-8 stdout on Windows ─────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR      = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
INPUT_FILE    = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")
WINDOW_SIZE   = 10
MIN_FLOWS     = WINDOW_SIZE + 1          # need >=11 flows per IP to get 1 sequence
MAX_SEQS      = 600_000                  # subsample cap (post-build, preserves rare classes)
RANDOM_STATE  = 42

DIVIDER = "=" * 70

# Columns to ALWAYS exclude from feature set (IDs, labels, metadata)
EXCLUDE_ALWAYS = {
    "Flow ID", "Source IP", "Destination IP",
    "Timestamp", "Label", "Label_Binary",
    "day_file",
    "Fwd Header Length.1",   # duplicate of Fwd Header Length
}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD & CLEAN
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load & Clean  (memory-optimised)")
print(DIVIDER)

# ── Pass 1: peek to identify numeric vs string columns ──────────────────────
print(f"\n  Peeking at column types ...")
_peek = pd.read_csv(INPUT_FILE, nrows=500, low_memory=False, encoding="utf-8")
_peek.columns = _peek.columns.str.strip()
_numeric_peek  = _peek.select_dtypes(include=[np.number]).columns.tolist()
_string_peek   = [c for c in _peek.columns if c not in _numeric_peek]
print(f"  Numeric columns: {len(_numeric_peek)}  |  String columns: {_string_peek}")
del _peek

# ── Pass 2: full read with float32 for numeric columns ──────────────────────
_dtypes = {col: np.float32 for col in _numeric_peek}
print(f"\n  Reading full CSV with float32 dtypes ...")
df = pd.read_csv(INPUT_FILE, dtype=_dtypes, low_memory=False, encoding="utf-8")
df.columns = df.columns.str.strip()
initial_rows = len(df)
print(f"  Loaded: {initial_rows:,} rows, {len(df.columns)} columns")

# ── Sanitise Label column (fix Latin-1 / en-dash corruption) ────────────────
if "Label" in df.columns:
    df["Label"] = (df["Label"]
                   .astype(str)
                   .str.encode("ascii", errors="replace")
                   .str.decode("ascii")
                   .str.strip())
    # 'nan' strings (from header-repeat rows) → actual NaN
    df["Label"] = df["Label"].replace("nan", np.nan)
    print(f"\n  Label column sanitised (ascii encode/decode, 'nan' → NaN)")
    label_nan_before = df["Label"].isna().sum()
    print(f"  Label NaN rows (header-repeat rows): {label_nan_before:,}")

# ── Drop rows where Label is NaN (header-repeat rows) ────────────────────────
label_nan_mask = df["Label"].isna()
df = df[~label_nan_mask].reset_index(drop=True)
after_label_drop = len(df)
print(f"  Rows dropped (NaN Label / header rows): {label_nan_before:,}")
print(f"  Rows remaining: {after_label_drop:,}")

# ── Replace Inf/-Inf with NaN ─────────────────────────────────────────────────
inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
print(f"\n  Inf values replaced with NaN: {inf_count:,}")

# ── Drop remaining NaN rows ───────────────────────────────────────────────────
nan_mask  = df.isnull().any(axis=1)
nan_count = nan_mask.sum()
df = df[~nan_mask].reset_index(drop=True)
after_nan = len(df)
print(f"  Rows dropped (remaining NaN): {nan_count:,}")
print(f"  Rows remaining: {after_nan:,}")

# ── Drop exact duplicate rows (excluding day_file) ────────────────────────────
cols_for_dup = [c for c in df.columns if c != "day_file"]
dup_mask     = df.duplicated(subset=cols_for_dup)
dup_count    = dup_mask.sum()
df = df[~dup_mask].reset_index(drop=True)
final_rows   = len(df)
print(f"\n  Rows dropped (duplicates):    {dup_count:,}")
print(f"  Rows remaining:               {final_rows:,}")
print(f"\n  Total removed from {initial_rows:,}: {initial_rows - final_rows:,}")
print(f"  ── Final clean row count: {final_rows:,} ──")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — LABEL PREPARATION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Label Preparation")
print(DIVIDER)

# Binary label
df["Label_Binary"] = (df["Label"] != "BENIGN").astype(np.int8)

# Multi-class integer encoding
label_encoder = LabelEncoder()
df["Label_Int"] = label_encoder.fit_transform(df["Label"]).astype(np.int16)

classes      = label_encoder.classes_
n_classes    = len(classes)
total        = len(df)

print(f"\n  Binary label distribution:")
for cls, name in [(0, "BENIGN"), (1, "ATTACK")]:
    cnt = (df["Label_Binary"] == cls).sum()
    print(f"    {cls} ({name:6s}) : {cnt:>9,}  ({cnt/total*100:.2f}%)")

print(f"\n  Multi-class label encoding ({n_classes} classes):")
print(f"  {'ID':>4}  {'Label':<45}  {'Count':>9}  {'%':>6}")
print(f"  {'-'*4}  {'-'*45}  {'-'*9}  {'-'*6}")
for i, cls in enumerate(classes):
    cnt = (df["Label"] == cls).sum()
    print(f"  {i:>4}  {cls:<45}  {cnt:>9,}  {cnt/total*100:>6.2f}%")

print(f"\n  Label encoder mapping saved as label_encoder_v2.pkl")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — PARSE TIMESTAMP & GROUP BY SOURCE IP
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Parse Timestamp & Analyse Source IP Groups")
print(DIVIDER)

# ── Parse Timestamp ───────────────────────────────────────────────────────────
print(f"\n  Parsing Timestamp column ...")
df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], format="mixed",
                                     dayfirst=True, errors="coerce")
ts_null = df["Timestamp_dt"].isna().sum()
if ts_null > 0:
    print(f"  ⚠ Unparseable timestamp rows: {ts_null:,}  (dropping them)")
    df = df[df["Timestamp_dt"].notna()].reset_index(drop=True)
    print(f"  Rows after timestamp drop: {len(df):,}")
else:
    print(f"  All {len(df):,} timestamps parsed successfully.")

ts_min = df["Timestamp_dt"].min()
ts_max = df["Timestamp_dt"].max()
print(f"  Time range: {ts_min}  →  {ts_max}")

# ── Source IP analysis ────────────────────────────────────────────────────────
print(f"\n  Analysing Source IP flow distribution ...")
ip_col      = "Source IP"
ip_counts   = df[ip_col].value_counts()
n_unique_ip = len(ip_counts)

print(f"\n  Unique Source IPs         : {n_unique_ip:,}")
print(f"  Flows per IP — min        : {ip_counts.min():,}")
print(f"  Flows per IP — max        : {ip_counts.max():,}")
print(f"  Flows per IP — median     : {ip_counts.median():.0f}")
print(f"  Flows per IP — mean       : {ip_counts.mean():.1f}")

eligible = (ip_counts >= MIN_FLOWS).sum()
skipped  = n_unique_ip - eligible
print(f"\n  IPs with >= {MIN_FLOWS} flows (eligible) : {eligible:,}")
print(f"  IPs with <  {MIN_FLOWS} flows (skipped)  : {skipped:,}")

print(f"\n  Top 15 IPs by flow count:")
print(f"  {'Source IP':<20}  {'Flows':>9}  {'Label':<15}")
print(f"  {'-'*20}  {'-'*9}  {'-'*15}")
for ip, cnt in ip_counts.head(15).items():
    # Show the most common label for this IP
    top_label = df[df[ip_col] == ip]["Label"].value_counts().index[0]
    print(f"  {ip:<20}  {cnt:>9,}  {top_label:<15}")

# ── Sort by Source IP then Timestamp ─────────────────────────────────────────
print(f"\n  Sorting by Source IP → Timestamp ...")
df.sort_values(by=[ip_col, "Timestamp_dt"], inplace=True, na_position="last")
df.reset_index(drop=True, inplace=True)
print(f"  Sorted. Rows: {len(df):,}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — BUILD TRUE PER-IP SLIDING-WINDOW SEQUENCES
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Build Per-IP Time-Ordered Sequences")
print(DIVIDER)

# ── Select feature columns ────────────────────────────────────────────────────
non_numeric = set(df.select_dtypes(exclude=[np.number]).columns.tolist())
exclude_all = EXCLUDE_ALWAYS | non_numeric | {"Label_Int", "Timestamp_dt"}

feature_cols = [c for c in df.columns if c not in exclude_all]

print(f"\n  Feature columns: {len(feature_cols)}")
print(f"  Excluded (IDs/labels/metadata): {sorted(EXCLUDE_ALWAYS & set(df.columns))}")
print(f"  Non-numeric excluded: {sorted(non_numeric - EXCLUDE_ALWAYS)}")
print(f"\n  Feature list:")
for i, c in enumerate(feature_cols, 1):
    print(f"    {i:>3}. {c}")

# Confirm Signal columns are included
for sig_col in ["Source Port", "Destination Port", "Protocol"]:
    if sig_col in feature_cols:
        print(f"\n  ✓ '{sig_col}' included as numeric feature (signal-bearing)")
    elif sig_col in df.columns:
        print(f"\n  ⚠ '{sig_col}' found but NOT in feature_cols — check exclusion logic")

# ── Build sequences ───────────────────────────────────────────────────────────
print(f"\n  Building sequences (window={WINDOW_SIZE}, min_flows={MIN_FLOWS}) ...")

feat_arr  = df[feature_cols].values.astype(np.float32)   # (N_rows, F)
binary_arr = df["Label_Binary"].values.astype(np.int8)    # (N_rows,)
int_arr    = df["Label_Int"].values.astype(np.int16)       # (N_rows,)
ip_arr     = df[ip_col].values                             # (N_rows,)

X_list, y_bin_list, y_int_list = [], [], []
eligible_ips = 0
skipped_ips  = 0

# Walk through groups using pre-sorted IP array (avoids groupby overhead)
# Since df is sorted by IP then time, find group boundaries
group_starts = np.where(np.concatenate(([True], ip_arr[1:] != ip_arr[:-1])))[0]
group_ends   = np.concatenate((group_starts[1:], [len(ip_arr)]))

for start, end in zip(group_starts, group_ends):
    n = end - start
    if n < MIN_FLOWS:
        skipped_ips += 1
        continue
    eligible_ips += 1
    grp_feats  = feat_arr[start:end]    # (n, F)
    grp_binary = binary_arr[start:end]  # (n,)
    grp_int    = int_arr[start:end]     # (n,)
    for i in range(n - WINDOW_SIZE):    # i+WINDOW_SIZE is the target row
        X_list.append(grp_feats[i : i + WINDOW_SIZE])
        y_bin_list.append(grp_binary[i + WINDOW_SIZE])
        y_int_list.append(grp_int[i + WINDOW_SIZE])

print(f"\n  Eligible IPs (>={MIN_FLOWS} flows) : {eligible_ips:,}")
print(f"  Skipped IPs (<{MIN_FLOWS} flows)   : {skipped_ips:,}")

X_all   = np.array(X_list,     dtype=np.float32)
y_bin   = np.array(y_bin_list, dtype=np.int8)
y_mc    = np.array(y_int_list, dtype=np.int16)
del X_list, y_bin_list, y_int_list

N, T, F = X_all.shape
print(f"\n  ─── Raw Sequence Stats ───")
print(f"  Total sequences : {N:,}")
print(f"  Shape           : {X_all.shape}  → (samples, timesteps, features)")
print(f"  Feature dim (F) : {F}")

print(f"\n  Binary class balance:")
for cls in [0, 1]:
    cnt = (y_bin == cls).sum()
    name = "BENIGN" if cls == 0 else "ATTACK"
    print(f"    {cls} ({name:6s}) : {cnt:>9,}  ({cnt/N*100:.2f}%)")

print(f"\n  Multi-class target distribution (per sequence):")
for i, cls_name in enumerate(classes):
    cnt = (y_mc == i).sum()
    if cnt > 0:
        print(f"    [{i:>2}] {cls_name:<45} {cnt:>9,}  ({cnt/N*100:.4f}%)")

# ── Subsample if needed (stratified by multi-class) ──────────────────────────
if N > MAX_SEQS:
    print(f"\n  Sequences ({N:,}) exceed MAX_SEQS={MAX_SEQS:,}.")
    print(f"  Stratified subsampling by multi-class label to {MAX_SEQS:,} ...")

    frac    = MAX_SEQS / N
    keep_idx = []
    rng = np.random.default_rng(RANDOM_STATE)

    for cls_id in np.unique(y_mc):
        cls_mask = np.where(y_mc == cls_id)[0]
        n_keep   = max(1, int(len(cls_mask) * frac))    # keep at least 1 per class
        chosen   = rng.choice(cls_mask, size=min(n_keep, len(cls_mask)), replace=False)
        keep_idx.extend(chosen.tolist())

    keep_idx = np.array(sorted(keep_idx))
    X_all    = X_all[keep_idx]
    y_bin    = y_bin[keep_idx]
    y_mc     = y_mc[keep_idx]
    N        = len(X_all)
    print(f"  Subsampled to: {N:,} sequences")

    print(f"\n  Post-subsample binary balance:")
    for cls in [0, 1]:
        cnt = (y_bin == cls).sum()
        print(f"    {cls}: {cnt:>9,}  ({cnt/N*100:.2f}%)")

    print(f"\n  Post-subsample multi-class distribution:")
    for i, cls_name in enumerate(classes):
        cnt = (y_mc == i).sum()
        if cnt > 0:
            print(f"    [{i:>2}] {cls_name:<45} {cnt:>9,}  ({cnt/N*100:.4f}%)")
else:
    print(f"\n  Sequence count ({N:,}) within MAX_SEQS — no subsampling needed.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — NORMALIZE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Normalisation (StandardScaler)")
print(DIVIDER)

# Fit on 2D view: (N*T, F)
X_2d = X_all.reshape(-1, F)

scaler      = StandardScaler()
X_2d_scaled = scaler.fit_transform(X_2d)
X_scaled    = X_2d_scaled.reshape(N, T, F).astype(np.float32)

SAMPLE_FEATURES = feature_cols[:5]
sample_idx = [feature_cols.index(c) for c in SAMPLE_FEATURES]

print("\n  Sample feature stats BEFORE scaling (mean | std):")
for idx, col in zip(sample_idx, SAMPLE_FEATURES):
    vals = X_2d[:, idx]
    print(f"    {col:<40}  mean={vals.mean():>14.4f}  std={vals.std():>14.4f}")

print("\n  Sample feature stats AFTER  scaling (mean | std):")
for idx, col in zip(sample_idx, SAMPLE_FEATURES):
    vals = X_2d_scaled[:, idx]
    print(f"    {col:<40}  mean={vals.mean():>14.6f}  std={vals.std():>14.6f}")

del X_2d, X_2d_scaled  # free memory


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — TRAIN/TEST SPLIT AND SAVE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Train/Test Split & Save")
print(DIVIDER)

indices = np.arange(N)
idx_train, idx_test = train_test_split(
    indices,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y_bin              # stratify by binary for balanced splits
)

X_train      = X_scaled[idx_train]
X_test       = X_scaled[idx_test]
y_train      = y_bin[idx_train]
y_test       = y_bin[idx_test]
y_train_mc   = y_mc[idx_train]
y_test_mc    = y_mc[idx_test]
X_bl_train   = X_scaled[idx_train, -1, :]   # last timestep: (N_train, F)
X_bl_test    = X_scaled[idx_test,  -1, :]

# ── Save numpy arrays ─────────────────────────────────────────────────────────
arrays = {
    "X_train_v2.npy"              : X_train,
    "X_test_v2.npy"               : X_test,
    "y_train_v2.npy"              : y_train,
    "y_test_v2.npy"               : y_test,
    "y_train_multiclass_v2.npy"   : y_train_mc,
    "y_test_multiclass_v2.npy"    : y_test_mc,
    "X_baseline_train_v2.npy"     : X_bl_train,
    "X_baseline_test_v2.npy"      : X_bl_test,
}

print()
for fname, arr in arrays.items():
    path    = os.path.join(DATA_DIR, fname)
    np.save(path, arr)
    size_mb = os.path.getsize(path) / (1024 ** 2)
    print(f"  Saved {fname:<35}  shape={str(arr.shape):<25}  ({size_mb:.1f} MB)")

# ── Save scaler and label encoder ─────────────────────────────────────────────
scaler_path  = os.path.join(DATA_DIR, "scaler_v2.pkl")
encoder_path = os.path.join(DATA_DIR, "label_encoder_v2.pkl")
joblib.dump(scaler,        scaler_path)
joblib.dump(label_encoder, encoder_path)
print(f"\n  Saved scaler_v2.pkl")
print(f"  Saved label_encoder_v2.pkl  (classes: {list(classes)})")

# ── Final shape summary ───────────────────────────────────────────────────────
print(f"\n  ─── Final Array Shapes ───")
print(f"  X_train         : {X_train.shape}   ← (train_samples, timesteps, features)")
print(f"  X_test          : {X_test.shape}")
print(f"  y_train         : {y_train.shape}")
print(f"  y_test          : {y_test.shape}")
print(f"  y_train_mc      : {y_train_mc.shape}")
print(f"  y_test_mc       : {y_test_mc.shape}")
print(f"  X_baseline_train: {X_bl_train.shape}")
print(f"  X_baseline_test : {X_bl_test.shape}")

# ── Multi-class distribution in train and test splits ────────────────────────
print(f"\n  ─── Multi-class distribution in TRAIN split ───")
print(f"  {'ID':>4}  {'Label':<45}  {'Count':>9}  {'%':>7}")
any_missing_train = []
for i, cls_name in enumerate(classes):
    cnt = (y_train_mc == i).sum()
    print(f"  {i:>4}  {cls_name:<45}  {cnt:>9,}  {cnt/len(y_train)*100:>7.4f}%")
    if cnt == 0:
        any_missing_train.append(cls_name)

print(f"\n  ─── Multi-class distribution in TEST split ───")
any_missing_test = []
for i, cls_name in enumerate(classes):
    cnt = (y_test_mc == i).sum()
    print(f"  {i:>4}  {cls_name:<45}  {cnt:>9,}  {cnt/len(y_test)*100:>7.4f}%")
    if cnt == 0:
        any_missing_test.append(cls_name)

if any_missing_train:
    print(f"\n  ⚠ Classes with 0 samples in TRAIN: {any_missing_train}")
if any_missing_test:
    print(f"  ⚠ Classes with 0 samples in TEST:  {any_missing_test}")
if not any_missing_train and not any_missing_test:
    print(f"\n  ✓ All {n_classes} classes represented in both train and test splits.")

print(f"\n{DIVIDER}")
print("Done! All v2 arrays and scalers saved to:")
print(f"  {DATA_DIR}")
print("Ready for train_and_compare_v2.py — true per-IP sequence LSTM.")
print(DIVIDER)
