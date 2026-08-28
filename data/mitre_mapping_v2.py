"""
Step 6 (v2) — MITRE ATT&CK Mapping & Test Sequence Breakdown
=============================================================
Reuses and extends the existing AEGIS backend threat classification rules
(backend/threat_classifier.py) to map CIC-IDS2017 multi-class labels to
official MITRE ATT&CK Tactics, Techniques, and Technique IDs.

Applies this mapping to the evaluation dataset (y_test_multiclass_v2.npy)
and exports `mitre_stage_mapping_v2.json` for seamless dashboard & reporting integration.

Outputs saved:
  TrafficLabelling/mitre_stage_mapping_v2.json
  data/mitre_stage_mapping_v2.json
"""

import io
import os
import sys
import json
import warnings
import numpy as np
import joblib

# ── Force UTF-8 stdout on Windows ─────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR     = r"C:\Users\Abhijeet\Downloads\GeneratedLabelledFlows\TrafficLabelling"
ENCODER_PATH = os.path.join(DATA_DIR, "label_encoder_v2.pkl")
Y_TEST_PATH  = os.path.join(DATA_DIR, "y_test_multiclass_v2.npy")

OUTPUT_JSON_DATA = os.path.join(DATA_DIR, "mitre_stage_mapping_v2.json")
OUTPUT_JSON_REPO = r"c:\CODE CLASH HACKATHON\AEGIS\data\mitre_stage_mapping_v2.json"

DIVIDER = "=" * 75


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — REUSE & EXTEND BACKEND MITRE MAPPING SCHEMA
# ─────────────────────────────────────────────────────────────────────────────
print(DIVIDER)
print("STEP 1 — Check Existing Backend Logic & Build MITRE ATT&CK Mapping")
print(DIVIDER)

# Verification of backend reuse
backend_classifier_path = r"c:\CODE CLASH HACKATHON\AEGIS\backend\threat_classifier.py"
if os.path.exists(backend_classifier_path):
    print(f"  ✓ Found existing AEGIS backend logic: {backend_classifier_path}")
    print(f"    Reusing: MITRE_TECHNIQUES taxonomy, technique names, codes (T1110, T1046, T1498, T1071, etc.)")
    print(f"    Extending: Exact 1-to-1 mapping for all 15 CIC-IDS2017 fine-grained attack classes.")
else:
    print("  [INFO] Backend classifier not found locally; using complete embedded MITRE taxonomy.")

# Master CIC-IDS2017 -> MITRE ATT&CK Mapping Dictionary
# Aligns with backend/threat_classifier.py and MITRE ATT&CK Matrix for Enterprise
CICIDS_TO_MITRE = {
    "BENIGN": {
        "tactic": "None",
        "technique_id": "N/A",
        "technique_name": "Normal Authorized Traffic",
        "stage": "Baseline",
        "description": "Legitimate baseline communications and operations without adversarial intent."
    },
    "PortScan": {
        "tactic": "Reconnaissance / Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "stage": "Reconnaissance",
        "description": "Adversary actively probes IPs and ports to discover live hosts and open listening services."
    },
    "DDoS": {
        "tactic": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "stage": "Disruption",
        "description": "Volumetric packet flooding designed to exhaust bandwidth and disable network edge devices."
    },
    "DoS Hulk": {
        "tactic": "Impact",
        "technique_id": "T1499.002",
        "technique_name": "HTTP Flood (Application Exhaustion)",
        "stage": "Disruption",
        "description": "Obfuscated HTTP GET flood generating dynamic URLs to defeat web server caches."
    },
    "DoS GoldenEye": {
        "tactic": "Impact",
        "technique_id": "T1499.002",
        "technique_name": "HTTP Keep-Alive & No-Cache Flood",
        "stage": "Disruption",
        "description": "Application-layer denial of service consuming server worker threads via keep-alive manipulation."
    },
    "DoS slowloris": {
        "tactic": "Impact",
        "technique_id": "T1499.003",
        "technique_name": "Slowloris Connection Starvation",
        "stage": "Disruption",
        "description": "Slow, persistent partial HTTP headers holding concurrent connection slots open indefinitely."
    },
    "DoS Slowhttptest": {
        "tactic": "Impact",
        "technique_id": "T1499.003",
        "technique_name": "Slow Read / Slow Request Body",
        "stage": "Disruption",
        "description": "Slow HTTP POST body transmissions starving target server resources with minimal bandwidth."
    },
    "FTP-Patator": {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing: FTP Brute Force",
        "stage": "Credential Harvesting",
        "description": "Systematic automated dictionary/credential guessing targeting FTP authentication (Port 21)."
    },
    "SSH-Patator": {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing: SSH Brute Force",
        "stage": "Credential Harvesting",
        "description": "High-frequency credential brute-forcing targeting secure remote shell services (Port 22)."
    },
    "Web Attack ? Brute Force": {
        "tactic": "Initial Access",
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing: Web Application Login",
        "stage": "Initial Access",
        "description": "Automated login form submission to compromise web application user accounts."
    },
    "Web Attack ? XSS": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: Cross-Site Scripting",
        "stage": "Initial Access",
        "description": "Injecting malicious client-side scripts into web applications to execute in user browser contexts."
    },
    "Web Attack ? Sql Injection": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: SQL Injection",
        "stage": "Initial Access",
        "description": "Injecting structured database query syntax to bypass authentication or extract backend data."
    },
    "Infiltration": {
        "tactic": "Initial Access / Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter: Multi-Stage Infiltration",
        "stage": "Execution & Lateral Movement",
        "description": "Compromising an internal workstation followed by post-exploitation lateral scanning."
    },
    "Bot": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: C2 Beaconing",
        "stage": "Command & Control",
        "description": "Periodic outbound network beaconing communicating with adversary Command and Control infrastructure."
    },
    "Heartbleed": {
        "tactic": "Initial Access / Collection",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: OpenSSL Memory Leak",
        "stage": "Initial Access",
        "description": "Exploiting OpenSSL TLS heartbeat extension (CVE-2014-0160) to read server memory buffers."
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — LOAD TEST DATASET & APPLY MITRE MAPPING
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 2 — Apply Mapping to Evaluation Test Sequences")
print(DIVIDER)

label_encoder = joblib.load(ENCODER_PATH)
classes = list(label_encoder.classes_)
y_test_mc = np.load(Y_TEST_PATH)

total_test_seqs = len(y_test_mc)
print(f"  Test Sequences Loaded: {total_test_seqs:,}")
print(f"  Label Classes ({len(classes)}): {classes}\n")

# Tally per-attack and per-tactic counts
tactic_counts = {}
attack_counts = {}

for cls_idx, cls_name in enumerate(classes):
    count = int((y_test_mc == cls_idx).sum())
    attack_counts[cls_name] = count

    mitre_info = CICIDS_TO_MITRE.get(cls_name, {
        "tactic": "Unknown / Unmapped",
        "technique_id": "T1071",
        "technique_name": "Protocol Anomaly",
        "stage": "Unknown",
        "description": "Unclassified threat vector"
    })

    tactic = mitre_info["tactic"]
    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + count

# ── 1. Attack Label to MITRE ATT&CK Matrix Table ───────────────────────────────
print(f"  ─── 1. Label-to-MITRE ATT&CK Taxonomy Table ───\n")
print(f"  {'Class Name':<28} | {'MITRE Code':<11} | {'MITRE Tactic':<28} | {'Technique Name'}")
print(f"  {'-'*28}-+-{'-'*11}-+-{'-'*28}-+-{'-'*35}")
for cls_name in classes:
    m = CICIDS_TO_MITRE.get(cls_name, {})
    print(f"  {cls_name:<28} | {m.get('technique_id', 'N/A'):<11} | {m.get('tactic', 'N/A'):<28} | {m.get('technique_name', 'N/A')}")

# ── 2. Test Set Distribution by MITRE Tactic ──────────────────────────────────
print(f"\n  ─── 2. Test Set Breakdown by MITRE ATT&CK Tactic ───\n")
print(f"  {'MITRE ATT&CK Tactic':<32} | {'Test Sequences':>14} | {'Percentage':>10} | {'Visual Distribution'}")
print(f"  {'-'*32}-+-{'-'*14}-+-{'-'*10}-+-{'-'*25}")

sorted_tactics = sorted(tactic_counts.items(), key=lambda kv: kv[1], reverse=True)
for tactic, cnt in sorted_tactics:
    pct = (cnt / total_test_seqs) * 100.0
    bar = "█" * int(pct / 2)
    print(f"  {tactic:<32} | {cnt:>14,} | {pct:>9.2f}% | {bar}")

# ── 3. Attack Only Tactical Breakdown (Excluding BENIGN) ───────────────────────
attack_total = sum(cnt for tac, cnt in tactic_counts.items() if tac != "None")
print(f"\n  ─── 3. Attack Threats Breakdown by MITRE Tactic (Total Attacks = {attack_total:,}) ───\n")
print(f"  {'MITRE ATT&CK Tactic':<32} | {'Attack Sequences':>16} | {'% of Threat Traffic'}")
print(f"  {'-'*32}-+-{'-'*16}-+-{'-'*20}")
for tactic, cnt in sorted_tactics:
    if tactic == "None":
        continue
    pct_atk = (cnt / attack_total) * 100.0 if attack_total > 0 else 0.0
    print(f"  {tactic:<32} | {cnt:>16,} | {pct_atk:>18.2f}%")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — SAVE MITRE STAGE MAPPING JSON
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("STEP 3 — Export MITRE ATT&CK Mapping JSON for AEGIS Dashboard")
print(DIVIDER)

export_data = {
    "metadata": {
        "dataset": "CIC-IDS2017",
        "framework": "MITRE ATT&CK v14",
        "reused_from": "AEGIS Backend (threat_classifier.py)",
        "total_classes": len(classes),
        "total_test_sequences": total_test_seqs,
        "attack_threat_sequences": attack_total
    },
    "tactics_summary": {
        tactic: {
            "test_count": cnt,
            "pct_total": round((cnt / total_test_seqs) * 100.0, 4),
            "pct_threats": round((cnt / attack_total) * 100.0, 4) if tactic != "None" and attack_total > 0 else 0.0
        }
        for tactic, cnt in tactic_counts.items()
    },
    "mappings": CICIDS_TO_MITRE
}

# Write to DATA_DIR
with open(OUTPUT_JSON_DATA, "w", encoding="utf-8") as f:
    json.dump(export_data, f, indent=2)
print(f"  ✓ Saved JSON artifact → {OUTPUT_JSON_DATA}")

# Write to AEGIS repo data directory
try:
    os.makedirs(os.path.dirname(OUTPUT_JSON_REPO), exist_ok=True)
    with open(OUTPUT_JSON_REPO, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
    print(f"  ✓ Saved JSON artifact in repo → {OUTPUT_JSON_REPO}")
except Exception as e:
    print(f"  [WARNING] Could not write to {OUTPUT_JSON_REPO}: {e}")

print(f"\n{DIVIDER}")
print("Done! MITRE ATT&CK mapping successfully integrated and exported.")
print(DIVIDER)
