<div align="center">

# 🛡️ AEGIS
### Advanced Engine for Guided Intelligence & Surveillance

**Detect. Decode. Defend.**

[![Live Demo](https://img.shields.io/badge/LIVE%20DEMO-aegis--tau--two.vercel.app-blue?style=for-the-badge&logo=vercel)](https://aegis-tau-two.vercel.app/)
[![Backend](https://img.shields.io/badge/BACKEND-Render-46E3B7?style=for-the-badge&logo=render)](https://render.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)](https://react.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Hackathon](https://img.shields.io/badge/CODE%20CLASH-2026-red?style=for-the-badge)](/)

> *"Upload a log file. Let AI decode every threat. Receive a military-grade incident report in seconds — not hours."*

</div>

---

## 📌 What is AEGIS?

AEGIS is an **AI-powered military-grade network threat detection platform** built for the **CODE CLASH 2026** hackathon under **Challenge 02 — Interference Detection and Alert System**.

Defence networks generate millions of log entries every day. Hidden inside: brute force attacks, data exfiltration, port scans, lateral movement. Manual analysis takes **8+ hours**. By then, the damage is done.

**AEGIS detects hostile interference patterns in defence network traffic, classifies severity using machine learning, maps attacker origins globally, and delivers an instant classified incident report — in under 3 seconds.**

---

## 🚀 Live Demo

🌐 **[aegis-tau-two.vercel.app](https://aegis-tau-two.vercel.app/)**

- Click **"TRY CICIDS 2017 SAMPLE DATASET"** on the upload page for an instant demo
- Or upload any `.csv` / `.log` / `.txt` network log file
- Watch AEGIS detect, classify, and brief — in real time

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **ML Anomaly Detection** | Scikit-learn Isolation Forest trained on CICIDS 2017 dataset |
| 🗺️ **IP Geolocation Map** | Real-time attacker origin mapping with severity-colored dots |
| 🧠 **Gemini AI Analysis** | Plain-English military-tone threat explanations per incident |
| 📋 **Commander's Brief** | AI-generated 3-line classified intelligence summary |
| 🎯 **MITRE ATT&CK Mapping** | Threat classification across T1110, T1041, T1046, T1071, T1078, T1021 |
| 📄 **PDF Incident Report** | Branded CONFIDENTIAL report with full threat inventory |
| 🛡️ **3D Holographic Shield** | Three.js animated AEGIS shield on landing page |
| ⚡ **12-Second Analysis** | End-to-end from upload to full intelligence dashboard |
| 🔍 **Threat Detail Panel** | Per-threat deep-dive with raw log, MITRE details, and recommended actions |
| 📊 **Visual Dashboard** | Bento-grid with gauge, doughnut, timeline, bar chart, threat table |

---

## 🏗️ Tech Stack

### Frontend
- **React 18** + **Vite** + **TypeScript**
- **Tailwind CSS** — Utility-first styling
- **Framer Motion** — Cinematic animations and transitions
- **Three.js** + **@react-three/fiber** — 3D holographic shield
- **Recharts** — Dashboard data visualizations
- **react-simple-maps** — IP Geolocation world map
- **tsParticles** — Animated particle field
- **Lucide React** — Icon system

### Backend
- **Python FastAPI** — REST API
- **Pandas** — Log file parsing and feature extraction
- **Scikit-learn** — Isolation Forest anomaly detection (contamination=0.05)
- **Google Gemini API** — AI threat explanations + Commander's Brief
- **ReportLab** — PDF incident report generation
- **ip-api.com** — Real-time IP geolocation

### Deployment
- **Vercel** — Frontend hosting with auto-deploy on push
- **Render** — Backend (FastAPI) Python web service

### Dataset
- **CICIDS 2017** — Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset

---

## 🧠 How It Works

```
User uploads log file (.csv / .log / .txt)
            ↓
FastAPI receives file → Pandas parses it
            ↓
Feature extraction per flow:
  - Connection counts per IP
  - Failed login count
  - Port distribution
  - Bytes transferred
  - Protocol analysis
  - Off-hours activity flags
            ↓
Isolation Forest scores each flow (anomaly score 0–100)
            ↓
Rule-based MITRE ATT&CK classification:
  - Many failed logins → T1110 Brute Force
  - Huge byte transfer → T1041 Data Exfiltration
  - Many destination ports → T1046 Port Scanning
  - Unusual protocol → T1071 Protocol Anomaly
  - Privilege patterns → T1078 Valid Accounts
  - Lateral spread → T1021 Lateral Movement
            ↓
Severity classification: LOW (0–30) | MEDIUM (31–65) | CRITICAL (66–100)
            ↓
ip-api.com geolocation for each attacker IP
            ↓
Gemini API → AI explanation per threat + Commander's Brief
            ↓
ReportLab → CONFIDENTIAL PDF incident report
            ↓
Full dashboard rendered in frontend
```

---

## 📁 Project Structure

```
AEGIS/
├── frontend/                  # React + Vite app
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Landing.tsx    # Hero + 3D Shield + landing sections
│   │   │   ├── Upload.tsx     # Log file upload interface
│   │   │   ├── Dashboard.tsx  # Command Intelligence Center
│   │   │   └── Report.tsx     # PDF report + scan history
│   │   ├── components/        # Reusable UI components
│   │   └── main.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── vercel.json
│
└── backend/                   # FastAPI Python backend
    ├── main.py                # API routes + ML pipeline
    ├── pdf_generator.py       # ReportLab PDF generation
    └── requirements.txt
```

---

## ⚙️ Local Setup

### Prerequisites
- Node.js 18+
- Python 3.10+
- Google Gemini API Key

### Frontend

```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

### Backend

```bash
cd backend
pip install -r requirements.txt

# Create .env file
echo "GEMINI_API_KEY=your_key_here" > .env

uvicorn main:app --reload --port 8000
# Runs on http://localhost:8000
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Backend health check |
| `POST` | `/api/upload` | Upload and analyze log file |
| `POST` | `/api/demo` | Run CICIDS 2017 demo dataset |
| `GET` | `/api/scan/{id}` | Get scan results by ID |
| `GET` | `/api/scan/{id}/report` | Download PDF report |
| `GET` | `/api/history` | Get all past scan history |

---

## 🎯 Challenge Alignment — CODE CLASH 2026

**Challenge 02: Interference Detection and Alert System**

> *"Create a solution that detects interference in RF signals, classifies its severity, and notifies users with actionable insights."*

AEGIS addresses this challenge at the **network layer**:

- ✅ **Detects interference** — hostile anomalies in defence network traffic
- ✅ **Classifies severity** — CRITICAL / MEDIUM / LOW with threat score 0–100
- ✅ **Notifies with actionable insights** — Gemini AI explanations + mitigation scripts + PDF report
- ✅ **Signal Integrity** — monitors network traffic signal patterns
- ✅ **Alert Engine** — real-time dashboard alerts + Commander's Brief

---

## 👨‍💻 Built By

**Abhijeet Kumar** — B.Tech CSE, Dayananda Sagar University, Bengaluru

- GitHub: [@selfabhijeetkumar](https://github.com/selfabhijeetkumar)

---

## 📜 License

MIT License — built for CODE CLASH 2026 Hackathon.

---

<div align="center">

**🛡️ AEGIS — Classified. Precise. Lethal.**

*Detect. Decode. Defend.*

</div>
