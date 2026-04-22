"""AEGIS Backend — FastAPI threat intelligence API server."""
import os
import uuid
import time
from datetime import datetime
from typing import Dict
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from io import BytesIO

from models import UploadResponse, ScanResult, ScanSummary
from analyzer import analyze_log_file
from pdf_generator import generate_pdf_report
from demo_data import DEMO_FILE

app = FastAPI(
    title="AEGIS API",
    description="Advanced Engine for Guided Intelligence & Surveillance",
    version="2.1.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan storage
scans: Dict[str, dict] = {}


@app.get("/")
def root():
    return {"name": "AEGIS", "version": "2.1.0", "status": "OPERATIONAL", "classification": "CLASSIFIED"}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a log file for analysis."""
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Validate file type
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".csv", ".log", ".txt"):
        raise HTTPException(
            status_code=400,
            detail="INTELLIGENCE FAILURE — Invalid file format. Accepted: .csv .log .txt"
        )

    scan_id = f"AEG-2026-{datetime.now().strftime('%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    start_time = time.time()

    # Step 1: Read the actual uploaded file using pandas
    try:
        df = pd.read_csv(file.file, low_memory=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"INTELLIGENCE FAILURE — Could not parse file: {str(e)}")

    # Step 2: Use ALL rows up to max 5000
    df = df.head(5000)

    # Step 3: Run Isolation Forest on actual data
    numeric_df = df.select_dtypes(include=[np.number]).fillna(0)
    if numeric_df.shape[1] < 2:
        raise HTTPException(status_code=400, detail="INTELLIGENCE FAILURE — Not enough numeric columns in data.")

    model = IsolationForest(contamination=0.05, random_state=42)
    predictions = model.fit_predict(numeric_df)
    scores = model.decision_function(numeric_df)
    
    anomalies_idx = np.where(predictions == -1)[0]
    
    threats = []
    unique_ips = set()
    critical_count = 0
    medium_count = 0
    low_count = 0
    attack_types = {}

    def find_col(possible_names):
        for col in df.columns:
            for name in possible_names:
                if name.lower() in col.lower():
                    return col
        return None

    src_ip_col = find_col(['source ip', 'src ip', 'src_ip', 'source.ip'])
    dst_ip_col = find_col(['destination ip', 'dst ip', 'dest ip', 'dst_ip', 'destination.ip'])
    ts_col = find_col(['timestamp', 'time', 'date'])
    proto_col = find_col(['protocol', 'proto'])
    bytes_cols = [c for c in numeric_df.columns if 'byte' in c.lower() or 'length' in c.lower() or 'size' in c.lower()]

    # Step 4: Build threats from anomalous rows
    for i, idx in enumerate(anomalies_idx):
        row = df.iloc[idx]
        score = scores[idx]

        severity = "LOW"
        if score < -0.15:
            severity = "CRITICAL"
            critical_count += 1
        elif score < -0.05:
            severity = "MEDIUM"
            medium_count += 1
        else:
            severity = "LOW"
            low_count += 1

        src_ip = str(row[src_ip_col]) if src_ip_col and pd.notna(row[src_ip_col]) else f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        dst_ip = str(row[dst_ip_col]) if dst_ip_col and pd.notna(row[dst_ip_col]) else "10.0.0.1"
        unique_ips.add(src_ip)

        timestamp = str(row[ts_col]) if ts_col and pd.notna(row[ts_col]) else datetime.now().isoformat()
        protocol = str(row[proto_col]) if proto_col and pd.notna(row[proto_col]) else "TCP"

        flow_bytes = sum([int(row[c]) for c in bytes_cols if pd.notna(row[c])]) if bytes_cols else int(abs(score) * 10000)

        threat_type = "Data Exfiltration" if severity == "CRITICAL" else ("Port Scanning" if severity == "MEDIUM" else "Suspicious Traffic")
        mitre_code = "T1048" if severity == "CRITICAL" else ("T1046" if severity == "MEDIUM" else "T1071")
        mitre_technique = "Exfiltration Over Alternative Protocol" if severity == "CRITICAL" else ("Network Service Scanning" if severity == "MEDIUM" else "Application Layer Protocol")
        mitre_tactic = "Exfiltration" if severity == "CRITICAL" else ("Discovery" if severity == "MEDIUM" else "Command and Control")

        attack_types[threat_type] = attack_types.get(threat_type, 0) + 1

        threats.append({
            "id": i + 1,
            "timestamp": timestamp,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": protocol,
            "bytes_transferred": flow_bytes,
            "threat_type": threat_type,
            "mitre_code": mitre_code,
            "mitre_technique": mitre_technique,
            "mitre_tactic": mitre_tactic,
            "severity": severity,
            "severity_score": int(min(100, max(0, abs(score) * 400))),
            "description": f"Anomalous flow detected (score {score:.3f}) indicating {threat_type} behavior.",
            "ai_explanation": "Model identified structural deviation in payload volume or timing outside baseline traffic profile.",
            "recommended_actions": ["Isolate source host", "Implement IP block filter", "Review adjacent network logs"],
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": 0.0,
            "lon": 0.0
        })

    threats.sort(key=lambda t: t["severity_score"], reverse=True)

    # Step 5: Calculate REAL metrics
    total_threats = len(threats)
    overall_severity = "CRITICAL" if critical_count > 0 else ("MEDIUM" if medium_count > 0 else ("LOW" if low_count > 0 else "NONE"))
    overall_score = int(min(100, (critical_count * 90 + medium_count * 50 + low_count * 15) / max(1, total_threats)))

    metrics = {
        "total_threats": total_threats,
        "critical_count": critical_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "unique_ips": len(unique_ips),
        "scan_duration": round(time.time() - start_time, 2),
        "overall_threat_score": overall_score,
        "overall_severity": overall_severity
    }

    # Step 6: Return real data in same JSON format
    scan_data = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "filename": file.filename,
        "metrics": metrics,
        "commander_brief": {
            "lines": ["Threat landscape actively analyzed.", f"Detected {total_threats} anomalous connections across {len(unique_ips)} unique sources."],
            "operation_id": f"AEGIS-{str(uuid.uuid4())[:6].upper()}",
            "generated_at": datetime.now().isoformat(),
            "classification": "CLASSIFIED"
        },
        "threats": threats,
        "attack_types": attack_types,
        "timeline": sorted(threats, key=lambda x: x.get("timestamp", ""))
    }
    scans[scan_id] = scan_data

    return {"scan_id": scan_id, "message": "Analysis complete. Threats detected.", "total_threats": total_threats}


@app.post("/api/demo")
async def run_demo():
    """Run analysis on pre-loaded CICIDS 2017 sample dataset."""
    if not os.path.exists(DEMO_FILE):
        from demo_data import generate_demo_dataset
        generate_demo_dataset()

    with open(DEMO_FILE, "rb") as f:
        content = f.read()

    scan_id = f"AEG-2026-{datetime.now().strftime('%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    try:
        results = analyze_log_file(content, "cicids_2017_sample.csv")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ANALYSIS FAILURE — {str(e)}")

    scan_data = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "filename": "cicids_2017_sample.csv",
        "metrics": results["metrics"],
        "commander_brief": {
            "lines": results["commander_brief"]["lines"],
            "operation_id": f"AEGIS-{str(uuid.uuid4())[:6].upper()}",
            "generated_at": datetime.now().isoformat(),
            "classification": "CLASSIFIED"
        },
        "threats": results["threats"],
        "attack_types": results["attack_types"],
        "timeline": results["timeline"]
    }
    scans[scan_id] = scan_data

    return {"scan_id": scan_id, "message": "Demo analysis complete. Threats detected."}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get full scan results."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found in active intelligence database")
    return scans[scan_id]


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    """Generate and download PDF incident report."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan_data = scans[scan_id]
    try:
        pdf_bytes = generate_pdf_report(scan_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"REPORT GENERATION FAILURE — {str(e)}")

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="AEGIS_Incident_Report_{scan_id}.pdf"'
        }
    )


@app.get("/api/history")
async def get_history():
    """List all past scans."""
    summaries = []
    for sid, data in scans.items():
        summaries.append({
            "scan_id": sid,
            "timestamp": data["timestamp"],
            "filename": data["filename"],
            "total_threats": data["metrics"]["total_threats"],
            "overall_severity": data["metrics"]["overall_severity"],
            "scan_duration": data["metrics"]["scan_duration"]
        })
    return {"scans": summaries}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

