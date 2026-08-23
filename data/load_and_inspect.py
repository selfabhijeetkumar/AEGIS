"""
Step 1 — Load & Inspect CIC-IDS2017
====================================
Loads all 8 CSV files, cleans column names, inspects data quality,
and saves a single combined CSV for downstream pipeline steps.
"""

import os
import pandas as pd
import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — update this path to your actual folder
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR = r"C:\Users\Abhijeet\Downloads\archive (2)"
OUTPUT_FILE = os.path.join(DATA_DIR, "combined_cicids2017.csv")

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

DIVIDER = "=" * 70


# ─────────────────────────────────────────────────────────────────────────────
# 1. LOAD ALL CSVs INTO ONE DATAFRAME
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Loading CSVs")
print(DIVIDER)

frames = []
for filename in CSV_FILES:
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        print(f"  [WARNING] File not found, skipping: {filepath}")
        continue

    df = pd.read_csv(filepath, low_memory=False)
    df["day_file"] = filename          # track source file
    frames.append(df)
    print(f"  Loaded  {filename}  →  {len(df):,} rows")

combined = pd.concat(frames, ignore_index=True)
print(f"\n  Combined total: {len(combined):,} rows from {len(frames)} files")


# ─────────────────────────────────────────────────────────────────────────────
# 2. STRIP WHITESPACE FROM COLUMN NAMES
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Stripping whitespace from column names")
print(DIVIDER)

before = list(combined.columns)
combined.columns = combined.columns.str.strip()
after = list(combined.columns)

changed = [(b, a) for b, a in zip(before, after) if b != a]
if changed:
    print(f"  Fixed {len(changed)} column name(s):")
    for old, new in changed:
        print(f"    '{old}'  →  '{new}'")
else:
    print("  No column names needed fixing.")


# ─────────────────────────────────────────────────────────────────────────────
# 3. BASIC STATS — row count, columns, label distribution
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Basic statistics")
print(DIVIDER)

print(f"\n  Total rows   : {len(combined):,}")
print(f"  Total columns: {len(combined.columns)}")

print("\n  All column names:")
for i, col in enumerate(combined.columns, 1):
    print(f"    {i:>3}. {col}")

print("\n  Label distribution (column: 'Label'):")
if "Label" in combined.columns:
    label_counts = combined["Label"].value_counts()
    for label, count in label_counts.items():
        pct = count / len(combined) * 100
        print(f"    {label:<45} {count:>9,}  ({pct:.2f}%)")
else:
    print("  [WARNING] 'Label' column not found!")


# ─────────────────────────────────────────────────────────────────────────────
# 4. MISSING / NaN / INFINITE VALUES
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 4 — Missing & infinite value check")
print(DIVIDER)

# NaN check
nan_per_col = combined.isnull().sum()
nan_cols = nan_per_col[nan_per_col > 0]
total_nan_rows = combined.isnull().any(axis=1).sum()

print(f"\n  Rows with at least one NaN : {total_nan_rows:,}")
if not nan_cols.empty:
    print("  Columns with NaN values:")
    for col, count in nan_cols.items():
        print(f"    {col:<45} {count:>9,} NaNs")
else:
    print("  No NaN values found.")

# Infinite value check (only on numeric columns)
numeric_cols = combined.select_dtypes(include=[np.number]).columns
inf_mask = np.isinf(combined[numeric_cols]).any(axis=1)
total_inf_rows = inf_mask.sum()

inf_per_col = np.isinf(combined[numeric_cols]).sum()
inf_cols = inf_per_col[inf_per_col > 0]

print(f"\n  Rows with at least one Inf  : {total_inf_rows:,}")
if not inf_cols.empty:
    print("  Columns with Inf values:")
    for col, count in inf_cols.items():
        print(f"    {col:<45} {count:>9,} Infs")
else:
    print("  No infinite values found.")

# Combined affected rows
affected_rows = combined.isnull().any(axis=1) | inf_mask
print(f"\n  Total rows affected (NaN OR Inf): {affected_rows.sum():,}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. DUPLICATE ROW CHECK
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 5 — Duplicate row check")
print(DIVIDER)

# Check duplicates excluding the 'day_file' tracking column
cols_for_dup = [c for c in combined.columns if c != "day_file"]
n_duplicates = combined.duplicated(subset=cols_for_dup).sum()
print(f"\n  Duplicate rows (ignoring day_file): {n_duplicates:,}")
if n_duplicates > 0:
    pct = n_duplicates / len(combined) * 100
    print(f"  That's {pct:.2f}% of total rows.")
    print("  Note: duplicates are reported but NOT dropped here — handle in Step 2.")


# ─────────────────────────────────────────────────────────────────────────────
# 6. SAVE COMBINED DATAFRAME
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 6 — Saving combined CSV")
print(DIVIDER)

combined.to_csv(OUTPUT_FILE, index=False)
file_size_mb = os.path.getsize(OUTPUT_FILE) / (1024 ** 2)
print(f"\n  Saved → {OUTPUT_FILE}")
print(f"  File size: {file_size_mb:.1f} MB")
print(f"  Rows: {len(combined):,}  |  Columns: {len(combined.columns)}")

print(f"\n{DIVIDER}")
print("Done! combined_cicids2017.csv is ready for Step 2 of the pipeline.")
print(DIVIDER)
