"""
verify_and_fix_split_v2.py
==========================
Data-leakage audit and group-based train/test split fix for the AEGIS pipeline.

STEP 1  — Audit existing split (v2): measure Source IP overlap between train/test.
STEP 2  — Rebuild split using GroupShuffleSplit keyed on Source IP (zero leakage).
STEP 3  — Save rebuilt arrays as _v3 files (fully compatible with downstream pipeline).
STEP 4  — Print side-by-side comparison: old vs new split.

Run from the project root or directly:
    python data/verify_and_fix_split_v2.py
"""

import io
import os
import sys
import warnings
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, GroupShuffleSplit

# ── Force UTF-8 stdout on Windows ─────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  (identical to prepare_sequences_v2.py)
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR     = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
INPUT_FILE   = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")
WINDOW_SIZE  = 10
MIN_FLOWS    = WINDOW_SIZE + 1          # >= 11 flows per IP required
MAX_SEQS     = 600_000                  # subsample cap
RANDOM_STATE = 42

EXCLUDE_ALWAYS = {
    "Flow ID", "Source IP", "Destination IP",
    "Timestamp", "Label", "Label_Binary",
    "day_file",
    "Fwd Header Length.1",
}

DIVIDER = "=" * 70


# ─────────────────────────────────────────────────────────────────────────────
# SHARED HELPER — rebuild full sequence dataset with Source IP tracking
# ─────────────────────────────────────────────────────────────────────────────
def build_all_sequences():
    """
    Replicate Steps 1-5 of prepare_sequences_v2.py exactly.
    Additionally tracks which Source IP each sequence came from.
    Returns:
        X_scaled     : (N, T, F) float32
        y_bin        : (N,) int8
        y_mc         : (N,) int16
        ip_seq       : (N,) object  — Source IP per sequence
        feature_cols : list[str]
        label_encoder: LabelEncoder
        scaler       : fitted StandardScaler
        classes      : ndarray[str]
    """
    # STEP 1: Load & Clean
    _peek = pd.read_csv(INPUT_FILE, nrows=500, low_memory=False, encoding="utf-8")
    _peek.columns = _peek.columns.str.strip()
    _numeric_peek = _peek.select_dtypes(include=[np.number]).columns.tolist()
    del _peek

    _dtypes = {col: np.float32 for col in _numeric_peek}
    df = pd.read_csv(INPUT_FILE, dtype=_dtypes, low_memory=False, encoding="utf-8")
    df.columns = df.columns.str.strip()

    if "Label" in df.columns:
        df["Label"] = (df["Label"]
                       .astype(str)
                       .str.encode("ascii", errors="replace")
                       .str.decode("ascii")
                       .str.strip())
        df["Label"] = df["Label"].replace("nan", np.nan)

    df = df[~df["Label"].isna()].reset_index(drop=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df = df[~df.isnull().any(axis=1)].reset_index(drop=True)

    cols_for_dup = [c for c in df.columns if c != "day_file"]
    df = df[~df.duplicated(subset=cols_for_dup)].reset_index(drop=True)

    # STEP 2: Labels
    df["Label_Binary"] = (df["Label"] != "BENIGN").astype(np.int8)
    label_encoder = LabelEncoder()
    df["Label_Int"] = label_encoder.fit_transform(df["Label"]).astype(np.int16)
    classes = label_encoder.classes_

    # STEP 3: Timestamps & sort
    df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], format="mixed",
                                        dayfirst=True, errors="coerce")
    df = df[df["Timestamp_dt"].notna()].reset_index(drop=True)
    ip_col = "Source IP"
    df.sort_values(by=[ip_col, "Timestamp_dt"], inplace=True, na_position="last")
    df.reset_index(drop=True, inplace=True)

    # STEP 4: Feature selection & sequence building
    non_numeric = set(df.select_dtypes(exclude=[np.number]).columns.tolist())
    exclude_all = EXCLUDE_ALWAYS | non_numeric | {"Label_Int", "Timestamp_dt"}
    feature_cols = [c for c in df.columns if c not in exclude_all]

    feat_arr   = df[feature_cols].values.astype(np.float32)
    binary_arr = df["Label_Binary"].values.astype(np.int8)
    int_arr    = df["Label_Int"].values.astype(np.int16)
    ip_arr     = df[ip_col].values

    X_list, y_bin_list, y_int_list, ip_seq_list = [], [], [], []

    group_starts = np.where(np.concatenate(([True], ip_arr[1:] != ip_arr[:-1])))[0]
    group_ends   = np.concatenate((group_starts[1:], [len(ip_arr)]))

    for start, end in zip(group_starts, group_ends):
        n = end - start
        if n < MIN_FLOWS:
            continue
        grp_ip = ip_arr[start]
        for i in range(n - WINDOW_SIZE):
            X_list.append(feat_arr[start + i : start + i + WINDOW_SIZE])
            y_bin_list.append(binary_arr[start + i + WINDOW_SIZE])
            y_int_list.append(int_arr[start + i + WINDOW_SIZE])
            ip_seq_list.append(grp_ip)

    X_all  = np.array(X_list,     dtype=np.float32)
    y_bin  = np.array(y_bin_list, dtype=np.int8)
    y_mc   = np.array(y_int_list, dtype=np.int16)
    ip_seq = np.array(ip_seq_list, dtype=object)
    del X_list, y_bin_list, y_int_list, ip_seq_list

    N, T, F = X_all.shape

    # Subsample (same logic as v2)
    if N > MAX_SEQS:
        frac = MAX_SEQS / N
        keep_idx = []
        rng = np.random.default_rng(RANDOM_STATE)
        for cls_id in np.unique(y_mc):
            cls_mask = np.where(y_mc == cls_id)[0]
            n_keep   = max(1, int(len(cls_mask) * frac))
            chosen   = rng.choice(cls_mask, size=min(n_keep, len(cls_mask)), replace=False)
            keep_idx.extend(chosen.tolist())
        keep_idx = np.array(sorted(keep_idx))
        X_all  = X_all[keep_idx]
        y_bin  = y_bin[keep_idx]
        y_mc   = y_mc[keep_idx]
        ip_seq = ip_seq[keep_idx]
        N      = len(X_all)

    # STEP 5: Normalise
    F = X_all.shape[2]
    X_2d = X_all.reshape(-1, F)
    scaler = StandardScaler()
    X_2d_scaled = scaler.fit_transform(X_2d)
    X_scaled = X_2d_scaled.reshape(N, T, F).astype(np.float32)
    del X_2d, X_2d_scaled

    return X_scaled, y_bin, y_mc, ip_seq, feature_cols, label_encoder, scaler, classes


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — AUDIT CURRENT (v2) SPLIT
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Audit Existing v2 Split for Source IP Leakage")
print(DIVIDER)

v2_Xtr_path = os.path.join(DATA_DIR, "X_train_v2.npy")
v2_Xte_path = os.path.join(DATA_DIR, "X_test_v2.npy")
if os.path.exists(v2_Xtr_path) and os.path.exists(v2_Xte_path):
    print(f"\n  Found existing v2 arrays:")
    print(f"  X_train_v2 : {len(np.load(v2_Xtr_path, mmap_mode='r')):,} sequences")
    print(f"  X_test_v2  : {len(np.load(v2_Xte_path, mmap_mode='r')):,} sequences")
else:
    print("\n  v2 arrays not found — auditing by reproducing old split.")

print("\n  Rebuilding sequence dataset with Source IP tracking ...")
print("  (Mirrors Steps 1-5 of prepare_sequences_v2.py exactly.)\n")

X_scaled, y_bin, y_mc, ip_seq, feature_cols, label_encoder, scaler, classes = \
    build_all_sequences()

N         = len(X_scaled)
n_classes = len(classes)
print(f"  Total sequences : {N:,}   shape: {X_scaled.shape}")
print(f"  Unique Source IPs in full dataset: {len(np.unique(ip_seq)):,}")

# Reproduce old random split (same RANDOM_STATE => deterministic)
indices = np.arange(N)
idx_train_old, idx_test_old = train_test_split(
    indices, test_size=0.20, random_state=RANDOM_STATE, stratify=y_bin)

ip_train_old    = set(ip_seq[idx_train_old])
ip_test_old     = set(ip_seq[idx_test_old])
overlap_old     = ip_train_old & ip_test_old
n_overlap_old   = len(overlap_old)
n_unique_total  = len(set(ip_seq))
pct_overlap_old = n_overlap_old / n_unique_total * 100

print(f"\n  --- OLD SPLIT (v2 random stratified) ---")
print(f"  Train sequences    : {len(idx_train_old):,}")
print(f"  Test  sequences    : {len(idx_test_old):,}")
print(f"  Unique IPs (train) : {len(ip_train_old):,}")
print(f"  Unique IPs (test)  : {len(ip_test_old):,}")
print(f"  Total unique IPs   : {n_unique_total:,}")
print(f"  Source IPs in BOTH : {n_overlap_old:,} ({pct_overlap_old:.1f}% of all IPs)")

if n_overlap_old > 0:
    print(f"\n  DATA LEAKAGE CONFIRMED: {n_overlap_old} IP(s) span both splits.")
    for ip in sorted(overlap_old)[:20]:
        print(f"    {ip}")
    if n_overlap_old > 20:
        print(f"    ... and {n_overlap_old - 20} more")
else:
    print("\n  No leakage found in existing split.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — REBUILD WITH GroupShuffleSplit
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Rebuild Train/Test Split with GroupShuffleSplit (Source IP groups)")
print(DIVIDER)

gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_STATE)
idx_train_new, idx_test_new = next(gss.split(X_scaled, y_bin, groups=ip_seq))

ip_train_new = set(ip_seq[idx_train_new])
ip_test_new  = set(ip_seq[idx_test_new])
overlap_new  = ip_train_new & ip_test_new

print(f"\n  --- NEW SPLIT (v3 GroupShuffleSplit) ---")
print(f"  Train sequences    : {len(idx_train_new):,}  ({len(idx_train_new)/N*100:.1f}%)")
print(f"  Test  sequences    : {len(idx_test_new):,}  ({len(idx_test_new)/N*100:.1f}%)")
print(f"  Unique IPs (train) : {len(ip_train_new):,}")
print(f"  Unique IPs (test)  : {len(ip_test_new):,}")
print(f"  Source IP overlap  : {len(overlap_new):,}")

if len(overlap_new) == 0:
    print("\n  ZERO Source IP overlap confirmed — no data leakage.")
else:
    print(f"\n  UNEXPECTED OVERLAP: {overlap_new}")
    sys.exit(1)

y_tr_new    = y_bin[idx_train_new]
y_te_new    = y_bin[idx_test_new]
y_tr_mc_new = y_mc[idx_train_new]
y_te_mc_new = y_mc[idx_test_new]

print(f"\n  Binary class balance — TRAIN:")
for cls, name in [(0,"BENIGN"),(1,"ATTACK")]:
    cnt = (y_tr_new == cls).sum()
    print(f"    {name} : {cnt:>9,}  ({cnt/len(y_tr_new)*100:.2f}%)")

print(f"\n  Binary class balance — TEST:")
for cls, name in [(0,"BENIGN"),(1,"ATTACK")]:
    cnt = (y_te_new == cls).sum()
    print(f"    {name} : {cnt:>9,}  ({cnt/len(y_te_new)*100:.2f}%)")

print(f"\n  Multi-class distribution — TRAIN:")
missing_train_new = []
for i, cls_name in enumerate(classes):
    cnt  = (y_tr_mc_new == i).sum()
    flag = "  <<< MISSING" if cnt == 0 else ""
    print(f"  [{i:>2}] {cls_name:<45} {cnt:>9,}  ({cnt/len(y_tr_mc_new)*100:.4f}%){flag}")
    if cnt == 0:
        missing_train_new.append(cls_name)

print(f"\n  Multi-class distribution — TEST:")
missing_test_new = []
for i, cls_name in enumerate(classes):
    cnt  = (y_te_mc_new == i).sum()
    flag = "  <<< MISSING" if cnt == 0 else ""
    print(f"  [{i:>2}] {cls_name:<45} {cnt:>9,}  ({cnt/len(y_te_mc_new)*100:.4f}%){flag}")
    if cnt == 0:
        missing_test_new.append(cls_name)

if missing_train_new:
    print(f"\n  WARNING — Classes absent from TRAIN: {missing_train_new}")
    print("  (Rare class whose sequences all belong to IPs assigned to test.)")
if missing_test_new:
    print(f"\n  WARNING — Classes absent from TEST: {missing_test_new}")
if not missing_train_new and not missing_test_new:
    print(f"\n  All {n_classes} classes present in both new splits.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — SAVE v3 ARRAYS
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Save v3 Arrays")
print(DIVIDER)

X_train_v3    = X_scaled[idx_train_new]
X_test_v3     = X_scaled[idx_test_new]
X_bl_train_v3 = X_scaled[idx_train_new, -1, :]
X_bl_test_v3  = X_scaled[idx_test_new,  -1, :]

arrays_v3 = {
    "X_train_v3.npy"            : X_train_v3,
    "X_test_v3.npy"             : X_test_v3,
    "y_train_v3.npy"            : y_tr_new,
    "y_test_v3.npy"             : y_te_new,
    "y_train_multiclass_v3.npy" : y_tr_mc_new,
    "y_test_multiclass_v3.npy"  : y_te_mc_new,
    "X_baseline_train_v3.npy"   : X_bl_train_v3,
    "X_baseline_test_v3.npy"    : X_bl_test_v3,
}

print()
for fname, arr in arrays_v3.items():
    path    = os.path.join(DATA_DIR, fname)
    np.save(path, arr)
    size_mb = os.path.getsize(path) / (1024 ** 2)
    print(f"  Saved {fname:<35}  shape={str(arr.shape):<25}  ({size_mb:.1f} MB)")

print(f"\n  --- File Verification ---")
all_ok = True
for fname, arr in arrays_v3.items():
    path   = os.path.join(DATA_DIR, fname)
    loaded = np.load(path, mmap_mode="r")
    ok     = loaded.shape == arr.shape
    print(f"  [{'OK' if ok else 'FAIL'}] {fname:<35}  disk={loaded.shape}  expected={arr.shape}")
    all_ok = all_ok and ok

if all_ok:
    print("\n  All 8 v3 arrays saved and verified.")
else:
    print("\n  Verification failed for one or more arrays — see above.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — COMPARISON TABLE
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Old (v2) vs New (v3) Split Comparison")
print(DIVIDER)

w = 22
print(f"\n  {'Metric':<32}  {'Old v2 (random)':>{w}}  {'New v3 (group IP)':>{w}}")
print(f"  {'-'*32}  {'-'*w}  {'-'*w}")
rows = [
    ("Train sequences",        f"{len(idx_train_old):,}",           f"{len(idx_train_new):,}"),
    ("Test sequences",         f"{len(idx_test_old):,}",            f"{len(idx_test_new):,}"),
    ("Unique IPs (train)",     f"{len(ip_train_old):,}",            f"{len(ip_train_new):,}"),
    ("Unique IPs (test)",      f"{len(ip_test_old):,}",             f"{len(ip_test_new):,}"),
    ("IP overlap count",       f"{n_overlap_old:,}",                f"{len(overlap_new):,}"),
    ("IP overlap %",           f"{pct_overlap_old:.1f}%",           f"{len(overlap_new)/n_unique_total*100:.1f}%"),
    ("Data leakage",           "YES" if n_overlap_old > 0 else "NO", "YES" if overlap_new else "NO"),
]
for label, old_val, new_val in rows:
    print(f"  {label:<32}  {old_val:>{w}}  {new_val:>{w}}")

print(f"\n  Binary balance (train):")
print(f"  {'Class':<8}  {'Old %':>10}  {'New %':>10}  {'Delta':>8}")
for cls, name in [(0,"BENIGN"),(1,"ATTACK")]:
    old_p = (y_bin[idx_train_old] == cls).sum() / len(idx_train_old) * 100
    new_p = (y_tr_new == cls).sum() / len(y_tr_new) * 100
    print(f"  {name:<8}  {old_p:>9.2f}%  {new_p:>9.2f}%  {new_p-old_p:>+7.2f}pp")

print(f"\n  Binary balance (test):")
print(f"  {'Class':<8}  {'Old %':>10}  {'New %':>10}  {'Delta':>8}")
for cls, name in [(0,"BENIGN"),(1,"ATTACK")]:
    old_p = (y_bin[idx_test_old] == cls).sum() / len(idx_test_old) * 100
    new_p = (y_te_new == cls).sum() / len(y_te_new) * 100
    print(f"  {name:<8}  {old_p:>9.2f}%  {new_p:>9.2f}%  {new_p-old_p:>+7.2f}pp")

print(f"\n  --- Final Verdict ---")
if n_overlap_old > 0 and len(overlap_new) == 0:
    print(f"  DATA LEAKAGE FIXED: IP overlap {n_overlap_old:,} -> 0.")
    print(f"  Every Source IP appears in exactly one of train / test.")
elif n_overlap_old == 0:
    print(f"  Existing split already clean. v3 maintains zero overlap.")
else:
    print(f"  Overlap persists in new split — investigate.")

if missing_train_new or missing_test_new:
    print(f"\n  Class-coverage warning (non-zero overlap classes only):")
    if missing_train_new:
        print(f"  Missing from TRAIN: {missing_train_new}")
    if missing_test_new:
        print(f"  Missing from TEST : {missing_test_new}")
    print("  Recommendation: these are very rare classes whose flows all share")
    print("  a single Source IP. For presentation purposes, document this and")
    print("  note that GroupShuffleSplit correctly prioritises leakage prevention.")
else:
    print(f"  Full class coverage: all {n_classes} attack classes in both splits.")

print(f"\n{DIVIDER}")
print("Complete. v3 arrays are in:")
print(f"  {DATA_DIR}")
print(DIVIDER)
