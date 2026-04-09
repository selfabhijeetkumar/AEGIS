"""AEGIS Data Models — Pydantic schemas for the threat intelligence API."""
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class ThreatEvent(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: str
    bytes_transferred: int
    threat_type: str
    mitre_code: str
    mitre_technique: str
    mitre_tactic: str
    severity: str  # CRITICAL, MEDIUM, LOW
    severity_score: int  # 0-100
    description: str
    ai_explanation: str
    recommended_actions: List[str]
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0


class ScanMetrics(BaseModel):
    total_threats: int
    critical_count: int
    medium_count: int
    low_count: int
    unique_ips: int
    scan_duration: float
    overall_threat_score: int
    overall_severity: str


class CommanderBrief(BaseModel):
    lines: List[str]
    operation_id: str
    generated_at: str
    classification: str = "CLASSIFIED"


class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    filename: str
    metrics: ScanMetrics
    commander_brief: CommanderBrief
    threats: List[ThreatEvent]
    attack_types: dict  # type -> count
    timeline: List[ThreatEvent]


class ScanSummary(BaseModel):
    scan_id: str
    timestamp: str
    filename: str
    total_threats: int
    overall_severity: str
    scan_duration: float


class UploadResponse(BaseModel):
    scan_id: str
    message: str
