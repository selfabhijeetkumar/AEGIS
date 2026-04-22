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
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Validate file type
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".csv", ".log", ".txt"):
        raise HTTPException(
            status_code=400,
            detail="INTELLIGENCE FAILURE — Invalid file format. Accepted: .csv .log .txt"
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="INTELLIGENCE FAILURE — Empty file received")

    scan_id = f"AEG-2026-{datetime.now().strftime('%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    # Run analysis
    try:
        results = analyze_log_file(content, file.filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ANALYSIS FAILURE — {str(e)}")

    # Store results
    scan_data = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "filename": file.filename,
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

    return {"scan_id": scan_id, "message": "Analysis complete. Threats detected."}


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

