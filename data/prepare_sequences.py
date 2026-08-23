"""
Step 2 — Prepare Sequences for AEGIS (LSTM/Transformer)
=========================================================
Reads combined_cicids2017.csv, cleans it, builds sliding-window sequences
of length 10, normalises, splits 80/20, and saves numpy arrays + scaler.

Outputs (saved to DATA_DIR):
  X_train.npy, X_test.npy          — (N, 10, F) sequence arrays
  y_train.npy, y_test.npy          — (N,)  binary target arrays
  X_baseline_train.npy, X_baseline_test.npy  — (N, F) last-step feature arrays
  scaler.pkl                        — fitted StandardScaler
"""

import io
import os
import sys
import warnings
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# Force UTF-8 stdout so Windows cp1252 doesn't choke on mangled label chars
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR      = r"C:\Users\Abhijeet\Downloads\archive (2)"
INPUT_FILE    = os.path.join(DATA_DIR, "combined_cicids2017.csv")
WINDOW_SIZE   = 10      # number of flows per sequence
MIN_FLOWS     = WINDOW_SIZE + 1
MAX_ROWS      = 500_000  # subsample cap after cleaning (keeps RAM < ~4 GB)
RANDOM_STATE  = 42

DIVIDER = "=" * 70

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD & CLEAN
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load & Clean  (memory-optimised)")
print(DIVIDER)

# ── Pass 1: peek at column names and identify numeric vs string columns ──────
print(f"\n  Peeking at column types ({INPUT_FILE}) ...")
_peek = pd.read_csv(INPUT_FILE, nrows=500, low_memory=False)
_numeric_cols = _peek.select_dtypes(include=[np.number]).columns.tolist()
_str_cols     = [c for c in _peek.columns if c not in _numeric_cols]
print(f"  Numeric columns : {len(_numeric_cols)}   String columns: {_str_cols}")

# ── Pass 2: full read with float32 for all numeric columns (~50% less RAM) ───
_dtypes = {col: np.float32 for col in _numeric_cols}
print(f"  Reading full CSV with float32 dtypes to reduce RAM usage ...")
df = pd.read_csv(INPUT_FILE, dtype=_dtypes, low_memory=False)
del _peek
initial_rows = len(df)
print(f"  Loaded: {initial_rows:,} rows, {len(df.columns)} columns")

# ── Replace Inf/-Inf with NaN ─────────────────────────────────────────────────
inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
print(f"\n  Inf values replaced with NaN: {inf_count:,}")

# ── Drop rows with any NaN ────────────────────────────────────────────────────
nan_mask  = df.isnull().any(axis=1)
nan_count = nan_mask.sum()
df = df[~nan_mask].reset_index(drop=True)
print(f"  Rows dropped (NaN):           {nan_count:,}")
after_nan = len(df)
print(f"  Rows remaining:               {after_nan:,}")

# ── Drop exact duplicate rows (ignoring day_file column) ─────────────────────
cols_for_dup = [c for c in df.columns if c != "day_file"]
dup_mask  = df.duplicated(subset=cols_for_dup)
dup_count = dup_mask.sum()
df = df[~dup_mask].reset_index(drop=True)
after_dup = len(df)
print(f"\n  Rows dropped (duplicates):    {dup_count:,}")
print(f"  Rows remaining:               {after_dup:,}")
print(f"\n  Total rows removed:           {initial_rows - after_dup:,}")
print(f"  Final clean row count:        {after_dup:,}")

# ── Stratified subsample if dataset exceeds MAX_ROWS ─────────────────────────
# Label not yet created; use raw 'Label' string column for stratification.
if after_dup > MAX_ROWS:
    print(f"\n  Dataset ({after_dup:,} rows) exceeds MAX_ROWS={MAX_ROWS:,}.")
    print(f"  Stratified subsampling to {MAX_ROWS:,} rows (preserving class ratio) ...")
    df = df.groupby("Label", group_keys=False).apply(
        lambda g: g.sample(
            frac=MAX_ROWS / after_dup, random_state=RANDOM_STATE
        )
    ).reset_index(drop=True)
    print(f"  Subsampled row count: {len(df):,}")
else:
    print(f"  Dataset fits within MAX_ROWS limit — no subsampling needed.")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — LABEL SIMPLIFICATION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Label Simplification")
print(DIVIDER)

df["Label_Binary"] = (df["Label"] != "BENIGN").astype(int)

counts = df["Label_Binary"].value_counts().sort_index()
total  = len(df)
print("\n  Label_Binary distribution:")
print(f"    0 (BENIGN) : {counts.get(0, 0):>9,}  ({counts.get(0, 0)/total*100:.2f}%)")
print(f"    1 (ATTACK) : {counts.get(1, 0):>9,}  ({counts.get(1, 0)/total*100:.2f}%)")

# Sanitise label strings — the CSV has \ufffd chars from encoding corruption
df["Label"] = df["Label"].str.encode("ascii", errors="replace").str.decode("ascii").str.strip()

print("\n  Original multi-class label counts:")
for lbl, cnt in df["Label"].value_counts().items():
    print(f"    {lbl:<45} {cnt:>9,}  ({cnt/total*100:.2f}%)")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — IDENTIFY SOURCE IP AND TIMESTAMP COLUMNS
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Source IP & Timestamp Detection")
print(DIVIDER)

# Column candidates (case-insensitive, strip-safe)
all_cols_lower = {c.lower().strip(): c for c in df.columns}

IP_CANDIDATES  = ["source ip", "src ip", "src_ip", "sourceip"]
TS_CANDIDATES  = ["timestamp", "ts", "time", "flow start"]

src_ip_col  = None
ts_col      = None

for cand in IP_CANDIDATES:
    if cand in all_cols_lower:
        src_ip_col = all_cols_lower[cand]
        break

for cand in TS_CANDIDATES:
    if cand in all_cols_lower:
        ts_col = all_cols_lower[cand]
        break

print(f"\n  All columns in dataset: {list(df.columns)}\n")

USE_IP_GROUPING = False

try:
    if src_ip_col is None:
        raise KeyError(
            "No Source IP column found. Tried: " + str(IP_CANDIDATES) +
            "\nAvailable columns: " + str(list(df.columns))
        )
    print(f"  ✓ Source IP column found : '{src_ip_col}'")
    print(f"    Unique IPs: {df[src_ip_col].nunique():,}")

    if ts_col is None:
        print(f"  ⚠ No Timestamp column found (tried: {TS_CANDIDATES}).")
        print(f"    Sequences will be built in existing row order per IP.")
    else:
        print(f"  ✓ Timestamp column found : '{ts_col}'")
        print(f"    Converting to datetime and sorting by IP → Timestamp ...")
        df[ts_col] = pd.to_datetime(df[ts_col], infer_datetime_format=True, errors="coerce")
        ts_null = df[ts_col].isnull().sum()
        if ts_null > 0:
            print(f"    ⚠ {ts_null:,} rows with unparseable timestamps — they'll sort last.")
        df.sort_values(by=[src_ip_col, ts_col], inplace=True, na_position="last")
        df.reset_index(drop=True, inplace=True)
        print(f"    Sorted. Row count: {len(df):,}")

    USE_IP_GROUPING = True

except KeyError as e:
    print(f"\n  ⚠ WARNING: {e}")
    print(f"\n  → Falling back: sequences will be built in existing row order")
    print(f"    (no per-IP grouping — all rows treated as one global time series)")
    src_ip_col = None
    ts_col     = None

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — BUILD SEQUENCES
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Build Sliding-Window Sequences")
print(DIVIDER)

# Columns to EXCLUDE from feature set (non-numeric / ID / label columns)
EXCLUDE_COLS = {
    "Label", "Label_Binary", "day_file",
    "Flow ID", "flow id",
    "Source IP", "source ip", "src ip",
    "Destination IP", "destination ip", "dst ip",
    "Timestamp", "timestamp",
    "Fwd Header Length.1",  # duplicate of Fwd Header Length
}
# Also exclude any non-numeric dtype columns
non_numeric = set(df.select_dtypes(exclude=[np.number]).columns.tolist())
exclude_final = (EXCLUDE_COLS | non_numeric) - {"Label_Binary"}  # keep for labelling

feature_cols = [c for c in df.columns if c not in exclude_final]
print(f"\n  Feature columns selected: {len(feature_cols)}")
print(f"  Excluded: {sorted(EXCLUDE_COLS & set(df.columns))}")
print(f"  Non-numeric cols excluded: {sorted(non_numeric)}")
print(f"  Features: {feature_cols}")

def build_sequences_from_group(group_df, feature_cols, window=10):
    """
    Given a dataframe (already sorted), creates sliding windows of `window`
    rows. Target = Label_Binary of the row immediately AFTER the window.
    Returns (X_list, y_list) as lists of numpy arrays.
    """
    X_list, y_list = [], []
    feats = group_df[feature_cols].values
    labels = group_df["Label_Binary"].values

    for i in range(len(feats) - window):          # i+window is the target row
        window_feats = feats[i : i + window]       # shape: (window, F)
        target_label = labels[i + window]          # scalar: 0 or 1
        X_list.append(window_feats)
        y_list.append(target_label)

    return X_list, y_list

all_X, all_y = [], []

if USE_IP_GROUPING:
    print(f"\n  Building sequences per Source IP (window={WINDOW_SIZE}) ...")
    groups = df.groupby(src_ip_col)
    total_ips   = df[src_ip_col].nunique()
    skipped_ips = 0
    eligible_ips = 0

    for ip, grp in groups:
        if len(grp) < MIN_FLOWS:
            skipped_ips += 1
            continue
        eligible_ips += 1
        X_g, y_g = build_sequences_from_group(grp, feature_cols, WINDOW_SIZE)
        all_X.extend(X_g)
        all_y.extend(y_g)

    print(f"  Total unique IPs     : {total_ips:,}")
    print(f"  IPs with ≥{MIN_FLOWS} flows  : {eligible_ips:,}")
    print(f"  IPs skipped (<{MIN_FLOWS})   : {skipped_ips:,}")

else:
    # Fallback: treat entire dataframe as one sequence
    print(f"\n  Building sequences from full dataframe in row order (window={WINDOW_SIZE}) ...")
    all_X, all_y = build_sequences_from_group(df, feature_cols, WINDOW_SIZE)

X_all = np.array(all_X, dtype=np.float32)   # (N, 10, F)
y_all = np.array(all_y, dtype=np.int32)     # (N,)

print(f"\n  ─── Sequence Summary ───")
print(f"  Total sequences created  : {len(X_all):,}")
print(f"  Sequence shape           : {X_all.shape}  → (samples, timesteps, features)")
print(f"  Feature dimension (F)    : {X_all.shape[2]}")
print(f"  Target class balance:")
unique, cnts = np.unique(y_all, return_counts=True)
for cls, cnt in zip(unique, cnts):
    name = "BENIGN" if cls == 0 else "ATTACK"
    print(f"    {cls} ({name:6s}) : {cnt:>9,}  ({cnt/len(y_all)*100:.2f}%)")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — NORMALISE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Normalisation (StandardScaler)")
print(DIVIDER)

# Fit scaler on 2-D view of all sequence data, then reshape back
N, T, F = X_all.shape
X_2d = X_all.reshape(-1, F)   # (N*T, F)

scaler = StandardScaler()
X_2d_scaled = scaler.fit_transform(X_2d)
X_all_scaled = X_2d_scaled.reshape(N, T, F).astype(np.float32)

SAMPLE_FEATURES = feature_cols[:5]   # show first 5 features
sample_idx = [feature_cols.index(c) for c in SAMPLE_FEATURES]

print("\n  Sample feature stats BEFORE scaling (mean | std):")
for i, col in zip(sample_idx, SAMPLE_FEATURES):
    vals = X_2d[:, i]
    print(f"    {col:<40}  mean={vals.mean():>12.4f}  std={vals.std():>12.4f}")

print("\n  Sample feature stats AFTER  scaling (mean | std):")
for i, col in zip(sample_idx, SAMPLE_FEATURES):
    vals = X_2d_scaled[:, i]
    print(f"    {col:<40}  mean={vals.mean():>12.4f}  std={vals.std():>12.4f}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — TRAIN/TEST SPLIT AND SAVE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Train/Test Split & Save")
print(DIVIDER)

# Baseline: last timestep features only (shape: N, F)
X_baseline = X_all_scaled[:, -1, :]   # take last flow in each window

indices = np.arange(N)
(idx_train, idx_test) = train_test_split(
    indices,
    test_size=0.20,
    random_state=42,
    stratify=y_all
)

X_train       = X_all_scaled[idx_train]
X_test        = X_all_scaled[idx_test]
y_train       = y_all[idx_train]
y_test        = y_all[idx_test]
X_bl_train    = X_baseline[idx_train]
X_bl_test     = X_baseline[idx_test]

# Save numpy arrays
arrays = {
    "X_train.npy"           : X_train,
    "X_test.npy"            : X_test,
    "y_train.npy"           : y_train,
    "y_test.npy"            : y_test,
    "X_baseline_train.npy"  : X_bl_train,
    "X_baseline_test.npy"   : X_bl_test,
}

print()
for fname, arr in arrays.items():
    path = os.path.join(DATA_DIR, fname)
    np.save(path, arr)
    size_mb = os.path.getsize(path) / (1024 ** 2)
    print(f"  Saved {fname:<30}  shape={str(arr.shape):<25}  ({size_mb:.1f} MB)")

# Save scaler
scaler_path = os.path.join(DATA_DIR, "scaler.pkl")
joblib.dump(scaler, scaler_path)
print(f"  Saved scaler.pkl")

print(f"\n  ─── Final Array Shapes ───")
print(f"  X_train         : {X_train.shape}   ← (train_samples, timesteps, features)")
print(f"  X_test          : {X_test.shape}    ← (test_samples,  timesteps, features)")
print(f"  y_train         : {y_train.shape}")
print(f"  y_test          : {y_test.shape}")
print(f"  X_baseline_train: {X_bl_train.shape}")
print(f"  X_baseline_test : {X_bl_test.shape}")

print(f"\n  Train label balance:")
for cls in [0, 1]:
    cnt = (y_train == cls).sum()
    print(f"    {cls}: {cnt:,}  ({cnt/len(y_train)*100:.2f}%)")

print(f"\n  Test label balance:")
for cls in [0, 1]:
    cnt = (y_test == cls).sum()
    print(f"    {cls}: {cnt:,}  ({cnt/len(y_test)*100:.2f}%)")

print(f"\n{DIVIDER}")
print("Done! Sequences, baseline arrays, and scaler saved to:")
print(f"  {DATA_DIR}")
print("Ready for Step 3 — Model Training.")
print(DIVIDER)
