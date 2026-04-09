import axios from 'axios';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 120000, // 2 min for large file analysis
});

export interface ThreatEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  protocol: string;
  bytes_transferred: number;
  threat_type: string;
  mitre_code: string;
  mitre_technique: string;
  mitre_tactic: string;
  severity: 'CRITICAL' | 'MEDIUM' | 'LOW';
  severity_score: number;
  description: string;
  ai_explanation: string;
  recommended_actions: string[];
  country: string;
  city: string;
  isp: string;
  lat: number;
  lon: number;
}

export interface ScanMetrics {
  total_threats: number;
  critical_count: number;
  medium_count: number;
  low_count: number;
  unique_ips: number;
  scan_duration: number;
  overall_threat_score: number;
  overall_severity: 'CRITICAL' | 'MEDIUM' | 'LOW';
}

export interface CommanderBrief {
  lines: string[];
  operation_id: string;
  generated_at: string;
  classification: string;
}

export interface ScanResult {
  scan_id: string;
  timestamp: string;
  filename: string;
  metrics: ScanMetrics;
  commander_brief: CommanderBrief;
  threats: ThreatEvent[];
  attack_types: Record<string, number>;
  timeline: ThreatEvent[];
}

export interface ScanSummary {
  scan_id: string;
  timestamp: string;
  filename: string;
  total_threats: number;
  overall_severity: string;
  scan_duration: number;
}

export const uploadFile = async (file: File): Promise<{ scan_id: string; message: string }> => {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

export const runDemo = async (): Promise<{ scan_id: string; message: string }> => {
  const { data } = await api.post('/demo');
  return data;
};

export const getScanResults = async (scanId: string): Promise<ScanResult> => {
  const { data } = await api.get(`/scan/${scanId}`);
  return data;
};

export const downloadReport = async (scanId: string): Promise<Blob> => {
  const { data } = await api.get(`/scan/${scanId}/report`, {
    responseType: 'blob',
  });
  return data;
};

export const getHistory = async (): Promise<{ scans: ScanSummary[] }> => {
  const { data } = await api.get('/history');
  return data;
};

export default api;
