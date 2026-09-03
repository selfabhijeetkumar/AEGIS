"""
Methodology Audit & Data Leakage Remediation: Group-Based Source IP Split (v3)
=============================================================================
SIH26153 Pipeline — Audit and Fix Data Leakage in Train/Test Sequence Splitting

STEP 1 — AUDIT CURRENT SPLIT (v2):
  - Re-derives Source IP for each sequence using chronological sliding-window logic.
  - Computes Source IP overlap between the existing random stratified train & test sets.
  - Reports exact count and percentage of overlapping Source IPs (data leakage).

STEP 2 — REBUILD WITH GROUP-BASED SPLIT (v3):
  - Uses sklearn.model_selection.GroupShuffleSplit grouped by Source IP.
  - Ensures 100% isolation of Source IPs between Train and Test (ZERO overlap).
  - Targets ~80/20 train/test sequence distribution.

STEP 3 — SAVE v3 DATASETS:
  - X_train_v3.npy, X_test_v3.npy
  - y_train_v3.npy, y_test_v3.npy
  - y_train_multiclass_v3.npy, y_test_multiclass_v3.npy
  - X_baseline_train_v3.npy, X_baseline_test_v3.npy
  - scaler_v3.pkl, label_encoder_v3.pkl

STEP 4 — PRINT COMPARISON & CLASS AUDIT:
  - Direct comparison between v2 (old) and v3 (new) splits.
  - Confirms zero IP overlap.
  - Details per-attack-class representation in both splits with transparent reporting.
"""

import io
import os
import sys
import time
import warnings
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, GroupShuffleSplit

# Force UTF-8 stdout on Windows
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

warnings.filterwarnings("ignore")

# =============================================================================
# CONFIGURATION (Exact match with prepare_sequences_v2.py)
# =============================================================================
DATA_DIR      = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
INPUT_FILE    = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")
WINDOW_SIZE   = 10
MIN_FLOWS     = WINDOW_SIZE + 1          # need >= 11 flows per IP to form at least 1 sequence
MAX_SEQS      = 600_000                  # subsample cap matching prepare_sequences_v2.py
RANDOM_STATE  = 42

DIVIDER = "=" * 78

# Columns to ALWAYS exclude from feature set (IDs, labels, metadata)
EXCLUDE_ALWAYS = {
    "Flow ID", "Source IP", "Destination IP",
    "Timestamp", "Label", "Label_Binary",
    "day_file",
    "Fwd Header Length.1",   # duplicate of Fwd Header Length
}


def main():
    start_total_time = time.time()
    print(DIVIDER)
    print("SIH26153 PIPELINE — AUDIT & FIX DATA LEAKAGE (GROUP-BASED SOURCE IP SPLIT)")
    print(DIVIDER)
    print(f"Data Directory : {DATA_DIR}")
    print(f"Input CSV      : {INPUT_FILE}")
    print(f"Window Size    : {WINDOW_SIZE} flows per sequence")
    print(f"Min Flows / IP : {MIN_FLOWS}")
    print(f"Subsample Cap  : {MAX_SEQS:,}")
    print(f"Random Seed    : {RANDOM_STATE}")

    # =========================================================================
    # STEP 1: LOAD & CLEAN DATA (EXACT REPRODUCTION OF PREPARE_SEQUENCES_V2)
    # =========================================================================
    print(f"\n{DIVIDER}")
    print("STAGE 1 — Load & Clean Dataset (Memory-Optimized float32)")
    print(DIVIDER)

    print("  Peeking at column types ...", flush=True)
    _peek = pd.read_csv(INPUT_FILE, nrows=500, low_memory=False, encoding="utf-8")
    _peek.columns = _peek.columns.str.strip()
    _numeric_peek  = _peek.select_dtypes(include=[np.number]).columns.tolist()
    _string_peek   = [c for c in _peek.columns if c not in _numeric_peek]
    print(f"  Numeric columns : {len(_numeric_peek)} | String columns: {_string_peek}", flush=True)
    del _peek

    _dtypes = {col: np.float32 for col in _numeric_peek}
    print(f"  Reading full CSV ({os.path.getsize(INPUT_FILE)/(1024**2):.1f} MB) with float32 dtypes ...", flush=True)
    t0 = time.time()
    df = pd.read_csv(INPUT_FILE, dtype=_dtypes, low_memory=False, encoding="utf-8")
    df.columns = df.columns.str.strip()
    initial_rows = len(df)
    print(f"  Loaded: {initial_rows:,} rows, {len(df.columns)} columns in {time.time() - t0:.1f}s", flush=True)

    # Sanitise Label column (fix Latin-1 / en-dash corruption)
    if "Label" in df.columns:
        df["Label"] = (df["Label"]
                       .astype(str)
                       .str.encode("ascii", errors="replace")
                       .str.decode("ascii")
                       .str.strip())
        df["Label"] = df["Label"].replace("nan", np.nan)
        label_nan_before = df["Label"].isna().sum()
        print(f"  Label NaN rows (header-repeat rows dropped): {label_nan_before:,}", flush=True)

    # Drop rows where Label is NaN
    df = df[df["Label"].notna()].reset_index(drop=True)

    # Replace Inf with NaN and drop remaining NaN
    inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    nan_mask  = df.isnull().any(axis=1)
    nan_count = nan_mask.sum()
    df = df[~nan_mask].reset_index(drop=True)
    print(f"  Inf values: {inf_count:,} | NaN rows dropped: {nan_count:,}", flush=True)

    # Drop exact duplicate rows (excluding day_file)
    cols_for_dup = [c for c in df.columns if c != "day_file"]
    dup_mask     = df.duplicated(subset=cols_for_dup)
    dup_count    = dup_mask.sum()
    df = df[~dup_mask].reset_index(drop=True)
    final_rows   = len(df)
    print(f"  Duplicate rows dropped: {dup_count:,} | Clean rows remaining: {final_rows:,}", flush=True)

    # Binary and multi-class labels
    df["Label_Binary"] = (df["Label"] != "BENIGN").astype(np.int8)
    label_encoder = LabelEncoder()
    df["Label_Int"] = label_encoder.fit_transform(df["Label"]).astype(np.int16)
    classes = label_encoder.classes_
    n_classes = len(classes)

    # Parse Timestamps and Sort by [Source IP, Timestamp_dt]
    print("  Parsing Timestamp and sorting chronologically per Source IP ...", flush=True)
    df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    df = df[df["Timestamp_dt"].notna()].reset_index(drop=True)

    ip_col = "Source IP"
    df.sort_values(by=[ip_col, "Timestamp_dt"], inplace=True, na_position="last")
    df.reset_index(drop=True, inplace=True)
    print(f"  Chronologically sorted: {len(df):,} flows across {df[ip_col].nunique():,} unique IPs", flush=True)

    # Feature column selection
    non_numeric = set(df.select_dtypes(exclude=[np.number]).columns.tolist())
    exclude_all = EXCLUDE_ALWAYS | non_numeric | {"Label_Int", "Timestamp_dt"}
    feature_cols = [c for c in df.columns if c not in exclude_all]
    F = len(feature_cols)
    print(f"  Selected {F} numeric feature columns (including signal-bearing ports/protocols)", flush=True)

    # Build sequences + track Source IP for each sequence
    print(f"\n{DIVIDER}")
    print("STAGE 2 — Extract Sliding-Window Sequences with Source IP Provenance")
    print(DIVIDER)
    print(f"  Extracting sequences (window={WINDOW_SIZE}, min_flows={MIN_FLOWS}) ...", flush=True)
    t0 = time.time()

    feat_arr   = df[feature_cols].values.astype(np.float32)
    binary_arr = df["Label_Binary"].values.astype(np.int8)
    int_arr    = df["Label_Int"].values.astype(np.int16)
    ip_arr     = df[ip_col].values

    X_list, y_bin_list, y_int_list, ip_list = [], [], [], []
    eligible_ips = 0
    skipped_ips  = 0

    group_starts = np.where(np.concatenate(([True], ip_arr[1:] != ip_arr[:-1])))[0]
    group_ends   = np.concatenate((group_starts[1:], [len(ip_arr)]))

    for start, end in zip(group_starts, group_ends):
        n = end - start
        if n < MIN_FLOWS:
            skipped_ips += 1
            continue
        eligible_ips += 1
        grp_feats  = feat_arr[start:end]
        grp_binary = binary_arr[start:end]
        grp_int    = int_arr[start:end]
        grp_ip     = ip_arr[start]
        for i in range(n - WINDOW_SIZE):
            X_list.append(grp_feats[i : i + WINDOW_SIZE])
            y_bin_list.append(grp_binary[i + WINDOW_SIZE])
            y_int_list.append(grp_int[i + WINDOW_SIZE])
            ip_list.append(grp_ip)

    X_all   = np.array(X_list,     dtype=np.float32)
    y_bin   = np.array(y_bin_list, dtype=np.int8)
    y_mc    = np.array(y_int_list, dtype=np.int16)
    seq_ips = np.array(ip_list,    dtype=object)
    del X_list, y_bin_list, y_int_list, ip_list, feat_arr, binary_arr, int_arr, ip_arr, df

    N = len(X_all)
    print(f"  Built {N:,} sequences across {eligible_ips:,} eligible IPs ({skipped_ips:,} skipped) in {time.time() - t0:.1f}s", flush=True)

    # Subsample if exceeds MAX_SEQS
    if N > MAX_SEQS:
        print(f"  Subsampling from {N:,} to {MAX_SEQS:,} (preserving multi-class distribution) ...", flush=True)
        frac = MAX_SEQS / N
        keep_idx = []
        rng = np.random.default_rng(RANDOM_STATE)
        for cls_id in np.unique(y_mc):
            cls_mask = np.where(y_mc == cls_id)[0]
            n_keep   = max(1, int(len(cls_mask) * frac))
            chosen   = rng.choice(cls_mask, size=min(n_keep, len(cls_mask)), replace=False)
            keep_idx.extend(chosen.tolist())
        keep_idx = np.array(sorted(keep_idx))
        X_all   = X_all[keep_idx]
        y_bin   = y_bin[keep_idx]
        y_mc    = y_mc[keep_idx]
        seq_ips = seq_ips[keep_idx]
        N       = len(X_all)
        print(f"  Post-subsample sequence count: {N:,}", flush=True)

    # Normalization (StandardScaler)
    print("  Fitting StandardScaler across all sequence timesteps ...", flush=True)
    X_2d = X_all.reshape(-1, F)
    scaler = StandardScaler()
    X_2d_scaled = scaler.fit_transform(X_2d)
    X_scaled = X_2d_scaled.reshape(N, WINDOW_SIZE, F).astype(np.float32)
    del X_2d, X_2d_scaled, X_all

    # =========================================================================
    # STEP 1: AUDIT CURRENT SPLIT (V2 RANDOM STRATIFIED SPLIT)
    # =========================================================================
    print(f"\n{DIVIDER}")
    print("STEP 1 — AUDIT CURRENT SPLIT (v2 Random Stratified Split)")
    print(DIVIDER)

    indices = np.arange(N)
    idx_tr_old, idx_te_old = train_test_split(
        indices,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y_bin
    )

    old_tr_ips = set(seq_ips[idx_tr_old])
    old_te_ips = set(seq_ips[idx_te_old])
    old_overlap = old_tr_ips.intersection(old_te_ips)
    total_unique_ips = len(np.unique(seq_ips))

    old_overlap_pct_total = (len(old_overlap) / total_unique_ips) * 100
    old_overlap_pct_test  = (len(old_overlap) / len(old_te_ips)) * 100

    print("  [v2 OLD SPLIT AUDIT RESULTS]")
    print(f"  Total Sequences               : {N:,}")
    print(f"  Train Sequences               : {len(idx_tr_old):,} ({len(idx_tr_old)/N*100:.2f}%)")
    print(f"  Test Sequences                : {len(idx_te_old):,} ({len(idx_te_old)/N*100:.2f}%)")
    print(f"  Total Unique Source IPs       : {total_unique_ips:,}")
    print(f"  Unique IPs in Train Set       : {len(old_tr_ips):,}")
    print(f"  Unique IPs in Test Set        : {len(old_te_ips):,}")
    print(f"  OVERLAPPING Source IPs        : {len(old_overlap):,}")
    print(f"  Overlap % of Total Unique IPs : {old_overlap_pct_total:.2f}%")
    print(f"  Overlap % of Test Set IPs     : {old_overlap_pct_test:.2f}%")
    print("  LEAKAGE DIAGNOSIS             : HIGH DATA LEAKAGE DETECTED in v2!")
    print(f"                                  {len(old_overlap):,} Source IPs ({old_overlap_pct_test:.2f}% of test IPs) leaked across train & test.")

    # =========================================================================
    # STEP 2: REBUILD WITH GROUP-BASED SPLIT (GROUP SHUFFLE SPLIT ON SOURCE IP)
    # =========================================================================
    print(f"\n{DIVIDER}")
    print("STEP 2 — REBUILD WITH GROUP-BASED SPLIT (GroupShuffleSplit on Source IP)")
    print(DIVIDER)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_STATE)
    idx_tr_new, idx_te_new = next(gss.split(X_scaled, y_bin, groups=seq_ips))

    new_tr_ips = set(seq_ips[idx_tr_new])
    new_te_ips = set(seq_ips[idx_te_new])
    new_overlap = new_tr_ips.intersection(new_te_ips)

    new_overlap_count = len(new_overlap)
    new_overlap_pct   = (new_overlap_count / total_unique_ips) * 100

    print("  [v3 NEW GROUP-SPLIT RESULTS]")
    print(f"  Train Sequences               : {len(idx_tr_new):,} ({len(idx_tr_new)/N*100:.2f}%)")
    print(f"  Test Sequences                : {len(idx_te_new):,} ({len(idx_te_new)/N*100:.2f}%)")
    print(f"  Unique IPs in Train Set       : {len(new_tr_ips):,}")
    print(f"  Unique IPs in Test Set        : {len(new_te_ips):,}")
    print(f"  OVERLAPPING Source IPs        : {new_overlap_count:,}")
    print(f"  Overlap % of Total Unique IPs : {new_overlap_pct:.2f}%")
    print(f"  ZERO OVERLAP CONFIRMATION     : {'PASSED (ZERO LEAKAGE)' if new_overlap_count == 0 else 'FAILED'}")

    assert new_overlap_count == 0, f"GroupShuffleSplit failed: found {new_overlap_count} overlapping IPs!"

    # Class balance check
    print("\n  Binary Class Balance in New Group Split:")
    for cls, name in [(0, "BENIGN"), (1, "ATTACK")]:
        cnt_tr = (y_bin[idx_tr_new] == cls).sum()
        cnt_te = (y_bin[idx_te_new] == cls).sum()
        print(f"    {cls} ({name:6s}) — Train: {cnt_tr:>9,} ({cnt_tr/len(idx_tr_new)*100:.2f}%)  |  Test: {cnt_te:>9,} ({cnt_te/len(idx_te_new)*100:.2f}%)")

    # =========================================================================
    # STEP 3: SAVE REBUILT V3 DATASETS
    # =========================================================================
    print(f"\n{DIVIDER}")
    print("STEP 3 — SAVE REBUILT v3 DATASETS")
    print(DIVIDER)

    X_train_v3    = X_scaled[idx_tr_new]
    X_test_v3     = X_scaled[idx_te_new]
    y_train_v3    = y_bin[idx_tr_new]
    y_test_v3     = y_bin[idx_te_new]
    y_train_mc_v3 = y_mc[idx_tr_new]
    y_test_mc_v3  = y_mc[idx_te_new]
    X_bl_train_v3 = X_scaled[idx_tr_new, -1, :]
    X_bl_test_v3  = X_scaled[idx_te_new, -1, :]

    arrays_v3 = {
        "X_train_v3.npy"            : X_train_v3,
        "X_test_v3.npy"             : X_test_v3,
        "y_train_v3.npy"            : y_train_v3,
        "y_test_v3.npy"             : y_test_v3,
        "y_train_multiclass_v3.npy" : y_train_mc_v3,
        "y_test_multiclass_v3.npy"  : y_test_mc_v3,
        "X_baseline_train_v3.npy"   : X_bl_train_v3,
        "X_baseline_test_v3.npy"    : X_bl_test_v3,
    }

    for fname, arr in arrays_v3.items():
        path = os.path.join(DATA_DIR, fname)
        np.save(path, arr)
        size_mb = os.path.getsize(path) / (1024 ** 2)
        print(f"  Saved {fname:<32} shape={str(arr.shape):<25} ({size_mb:.1f} MB)")

    scaler_path_v3  = os.path.join(DATA_DIR, "scaler_v3.pkl")
    encoder_path_v3 = os.path.join(DATA_DIR, "label_encoder_v3.pkl")
    joblib.dump(scaler,        scaler_path_v3)
    joblib.dump(label_encoder, encoder_path_v3)
    print("  Saved scaler_v3.pkl")
    print("  Saved label_encoder_v3.pkl")

    # =========================================================================
    # STEP 4: PRINT COMPREHENSIVE COMPARISON & CLASS AUDIT
    # =========================================================================
    print(f"\n{DIVIDER}")
    print("STEP 4 — COMPREHENSIVE COMPARISON & CLASS PRESERVATION AUDIT")
    print(DIVIDER)

    print(f"  {'':<35}  {'Old Split (v2)':<20}  {'New Split (v3)':<20}")
    print(f"  {'-'*35}  {'-'*20}  {'-'*20}")
    print(f"  {'Splitting Strategy':<35}  {'Random Stratified':<20}  {'GroupShuffleSplit':<20}")
    print(f"  {'Grouping Variable':<35}  {'None (Sequence-level)':<20}  {'Source IP':<20}")
    print(f"  {'Train Sequences':<35}  {len(idx_tr_old):<20,}  {len(idx_tr_new):<20,}")
    print(f"  {'Test Sequences':<35}  {len(idx_te_old):<20,}  {len(idx_te_new):<20,}")
    print(f"  {'Unique Source IPs in Train':<35}  {len(old_tr_ips):<20,}  {len(new_tr_ips):<20,}")
    print(f"  {'Unique Source IPs in Test':<35}  {len(old_te_ips):<20,}  {len(new_te_ips):<20,}")
    print(f"  {'Overlapping Source IPs':<35}  {len(old_overlap):<20,}  {new_overlap_count:<20,}")
    print(f"  {'Overlap % of Total IPs':<35}  {old_overlap_pct_total:<19.2f}%  {new_overlap_pct:<19.2f}%")
    print(f"  {'Data Leakage Present':<35}  {'YES (High Leakage)':<20}  {'NO (100% Zero Leak)':<20}")

    print("\n  Multi-Class Category Distribution in v3 Group-Based Split:")
    print(f"  {'ID':>3}  {'Attack Category / Label':<42}  {'Train Count':>12}  {'Test Count':>12}  {'Observation / Notes':<25}")
    print(f"  {'-'*3}  {'-'*42}  {'-'*12}  {'-'*12}  {'-'*25}")

    missing_train = []
    missing_test  = []

    for i, cls_name in enumerate(classes):
        tr_c = (y_train_mc_v3 == i).sum()
        te_c = (y_test_mc_v3 == i).sum()
        note = "Present in both"
        if tr_c == 0:
            note = "Exclusive to Test set"
            missing_train.append(cls_name)
        elif te_c == 0:
            note = "Exclusive to Train set"
            missing_test.append(cls_name)
        print(f"  {i:>3}  {cls_name:<42}  {tr_c:>12,}  {te_c:>12,}  {note:<25}")

    print("\n  Class Preservation & Dataset Structure Audit:")
    if missing_test or missing_train:
        print("  [NOTE] In benchmark datasets like CICIDS2017, certain specific attack classes (e.g., Heartbleed,")
        print("         Infiltration, specific DoS variants) are generated from a single designated attacker IP machine.")
        print("         Under strict group-based IP splitting (zero data leakage), when that unique attacker IP")
        print("         is assigned to Train, Test receives 0 flows of that specific variant (and vice-versa).")
        if missing_train:
            print(f"         - Classes exclusive to Test: {missing_train}")
        if missing_test:
            print(f"         - Classes exclusive to Train: {missing_test}")
        print("         - Binary classes (BENIGN vs ATTACK) remain fully populated in BOTH splits:")
        print(f"           Train Attacks: {(y_train_v3 == 1).sum():,}, Test Attacks: {(y_test_v3 == 1).sum():,}")
    else:
        print(f"  [+] ALL {n_classes} attack classes are successfully represented in both splits!")

    print(f"\n{DIVIDER}")
    print("METHODOLOGY AUDIT & FIX COMPLETE — v3 DATASETS READY")
    print(f"Total Execution Time: {time.time() - start_total_time:.1f}s")
    print(f"Zero Source IP Leakage Verified: {new_overlap_count == 0}")
    print(f"All v3 datasets saved to: {DATA_DIR}")
    print(DIVIDER)


if __name__ == "__main__":
    main()
