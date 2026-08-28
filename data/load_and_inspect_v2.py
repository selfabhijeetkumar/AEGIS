"""
Step 1 (v2) — Load & Inspect CIC-IDS2017 GeneratedLabelledFlows
================================================================
Uses the GeneratedLabelledFlows version which retains Source IP,
Destination IP, Flow ID, and Timestamp columns needed for per-IP
sequence building in subsequent pipeline steps.

Outputs:
  combined_cicids2017_v2.csv  — combined, cleaned dataset
"""

import io
import os
import sys
import numpy as np
import pandas as pd

# ── Force UTF-8 stdout on Windows ────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR    = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
OUTPUT_FILE = os.path.join(DATA_DIR, "combined_cicids2017_v2.csv")

CSV_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

# Columns we know/hope to find — exact casing may vary
KEY_COLS = ["Flow ID", "Source IP", "Source Port",
            "Destination IP", "Destination Port", "Protocol", "Timestamp"]

DIVIDER = "=" * 70


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — LOAD ALL CSVs ONE AT A TIME (memory-efficient)
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Load CSVs (one at a time, float32 for numeric columns)")
print(DIVIDER)

frames = []

for filename in CSV_FILES:
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        print(f"  [WARNING] Not found, skipping: {filepath}")
        continue

    # ── Pass 1: peek at first 200 rows to learn column dtypes ────────────────
    peek = pd.read_csv(filepath, nrows=200, low_memory=False, encoding="latin-1")
    peek.columns = peek.columns.str.strip()   # strip whitespace immediately

    numeric_cols = peek.select_dtypes(include=[np.number]).columns.tolist()
    str_cols     = [c for c in peek.columns if c not in numeric_cols]

    # ── Pass 2: full read with float32 for all numeric columns ───────────────
    dtypes = {col: np.float32 for col in numeric_cols}
    df = pd.read_csv(filepath, dtype=dtypes, low_memory=False, encoding="latin-1")
    df.columns = df.columns.str.strip()

    # Sanitise Label immediately to avoid encoding issues downstream
    if "Label" in df.columns:
        df["Label"] = (df["Label"]
                       .astype(str)
                       .str.encode("ascii", errors="replace")
                       .str.decode("ascii")
                       .str.strip())

    df["day_file"] = filename
    frames.append(df)
    print(f"  Loaded  {filename}")
    print(f"          → {len(df):,} rows | numeric cols: {len(numeric_cols)} | "
          f"string cols: {str_cols}")

    del peek  # free peek memory

combined = pd.concat(frames, ignore_index=True)
del frames  # free individual frames

print(f"\n  ── Combined: {len(combined):,} rows, {len(combined.columns)} columns ──")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — CONFIRM COLUMN NAMES (whitespace already stripped per-file above)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Column Inventory")
print(DIVIDER)

print(f"\n  Total rows   : {len(combined):,}")
print(f"  Total columns: {len(combined.columns)}")

print("\n  All column names:")
for i, col in enumerate(combined.columns, 1):
    print(f"    {i:>3}. {col}")

# Explicitly check for key columns (case-insensitive search)
print(f"\n  ── Key Column Detection ──")
cols_lower_map = {c.lower(): c for c in combined.columns}
for key in KEY_COLS:
    exact_match = key in combined.columns
    lower_match = key.lower() in cols_lower_map
    if exact_match:
        print(f"  ✓ FOUND    '{key}'")
    elif lower_match:
        actual = cols_lower_map[key.lower()]
        print(f"  ~ FOUND*   '{key}' as '{actual}'  (different casing)")
    else:
        print(f"  ✗ MISSING  '{key}'  — not present in this dataset version")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — TIMESTAMP SAMPLE VALUES
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Timestamp Sample Values")
print(DIVIDER)

ts_col = None
for cand in ["Timestamp", "timestamp", "TIMESTAMP"]:
    if cand in combined.columns:
        ts_col = cand
        break
if ts_col is None:
    # Try case-insensitive
    ts_col = cols_lower_map.get("timestamp")

if ts_col:
    print(f"\n  Timestamp column: '{ts_col}'")
    sample_vals = combined[ts_col].dropna().head(3).tolist()
    for i, v in enumerate(sample_vals, 1):
        print(f"    Sample {i}: {v!r}")
    # Attempt datetime parse to show format
    try:
        parsed = pd.to_datetime(sample_vals, infer_datetime_format=True,
                                errors="coerce")
        print(f"\n  Parsed as datetime:")
        for i, v in enumerate(parsed, 1):
            print(f"    Sample {i}: {v}")
    except Exception as e:
        print(f"  [WARNING] Could not parse timestamps: {e}")
else:
    print("\n  [WARNING] No Timestamp column found — cannot sort by time.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — LABEL DISTRIBUTION
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Label Distribution")
print(DIVIDER)

if "Label" in combined.columns:
    total = len(combined)
    label_counts = combined["Label"].value_counts()
    print(f"\n  Unique labels: {len(label_counts)}")
    print()
    for lbl, cnt in label_counts.items():
        bar = "█" * int(cnt / total * 40)
        print(f"  {lbl:<45} {cnt:>9,}  ({cnt/total*100:5.2f}%)  {bar}")
else:
    print("  [WARNING] 'Label' column not found!")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — INF / NaN / DUPLICATE CHECK
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Data Quality Checks")
print(DIVIDER)

# NaN check
nan_per_col   = combined.isnull().sum()
nan_cols      = nan_per_col[nan_per_col > 0]
total_nan_rows = combined.isnull().any(axis=1).sum()

print(f"\n  Rows with at least one NaN : {total_nan_rows:,}")
if not nan_cols.empty:
    print("  Columns with NaN values:")
    for col, count in nan_cols.items():
        print(f"    {col:<45} {count:>9,} NaNs")
else:
    print("  No NaN values found.")

# Inf check (numeric columns only)
numeric_df = combined.select_dtypes(include=[np.number])
inf_mask    = np.isinf(numeric_df).any(axis=1)
inf_per_col = np.isinf(numeric_df).sum()
inf_cols    = inf_per_col[inf_per_col > 0]

print(f"\n  Rows with at least one Inf  : {inf_mask.sum():,}")
if not inf_cols.empty:
    print("  Columns with Inf values:")
    for col, count in inf_cols.items():
        print(f"    {col:<45} {count:>9,} Infs")
else:
    print("  No Inf values found.")

affected = combined.isnull().any(axis=1) | inf_mask
print(f"\n  Total rows affected (NaN OR Inf): {affected.sum():,}")

# Duplicate check (excluding day_file)
cols_for_dup = [c for c in combined.columns if c != "day_file"]
n_dups = combined.duplicated(subset=cols_for_dup).sum()
print(f"\n  Duplicate rows (ignoring day_file): {n_dups:,}")
if n_dups > 0:
    print(f"  That's {n_dups/len(combined)*100:.2f}% of total rows.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — SAVE COMBINED CSV
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Save Combined CSV")
print(DIVIDER)

combined.to_csv(OUTPUT_FILE, index=False, encoding="utf-8", errors="replace")
size_mb = os.path.getsize(OUTPUT_FILE) / (1024 ** 2)
print(f"\n  Saved → {OUTPUT_FILE}")
print(f"  File size : {size_mb:.1f} MB")
print(f"  Rows      : {len(combined):,}  |  Columns: {len(combined.columns)}")

print(f"\n{DIVIDER}")
print("Done! combined_cicids2017_v2.csv is ready for prepare_sequences.py")
print(DIVIDER)
