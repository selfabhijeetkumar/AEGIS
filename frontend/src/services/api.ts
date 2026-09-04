import axios from 'axios';

const API_BASE = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE)
  ? import.meta.env.VITE_API_BASE
  : (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'))
    ? 'http://localhost:8000'
    : 'https://aegis-backend-748p.onrender.com';

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
  pre_attack_escalation?: boolean;
}

export interface SequenceWindow {
  window_id: number;
  flow_index: number;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  attack_probability: number;
  attack_prob_pct: number;
  decision: 'ATTACK' | 'BENIGN';
  pre_attack_escalation: boolean;
  true_label: string;
  mitre_tactic: string;
  mitre_code: string;
  mitre_technique: string;
  mitre_stage: string;
  description: string;
}

export interface SequenceAnalysisResponse {
  source_ip: string;
  total_flows: number;
  total_windows: number;
  threat_windows: number;
  escalation_windows: number;
  threat_rate_pct: number;
  threshold: number;
  dominant_tactic: string;
  mitre_tactical_breakdown: Record<string, number>;
  sequences: SequenceWindow[];
}

export interface SystemStatusResponse {
  status: string;
  mode: string;
  engine: string;
  cuda_available: boolean;
  device: string;
  device_name: string;
  input_features: number;
  hidden_size: number;
  window_size: number;
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
  sequences_evaluated?: number;
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
  sequence_data?: SequenceAnalysisResponse;
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
  const { data } = await api.post('/api/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

export const runDemo = async (): Promise<{ scan_id: string; message: string }> => {
  const { data } = await api.post('/api/demo');
  return data;
};

export const getScanResults = async (scanId: string): Promise<ScanResult> => {
  const { data } = await api.get(`/api/scan/${scanId}`);
  return data;
};

export const analyzeSequence = async (params?: {
  source_ip?: string;
  threshold?: number;
  flows?: Record<string, unknown>[];
}): Promise<SequenceAnalysisResponse> => {
  const { data } = await api.post('/api/analyze-sequence', params || { threshold: 0.5 });
  return data;
};

export const getSystemStatus = async (): Promise<SystemStatusResponse> => {
  const { data } = await api.get('/api/system-status');
  return data;
};

export const downloadReport = async (scanId: string): Promise<Blob> => {
  const { data } = await api.get(`/api/scan/${scanId}/report`, {
    responseType: 'blob',
  });
  return data;
};

export const getHistory = async (): Promise<{ scans: ScanSummary[] }> => {
  const { data } = await api.get('/api/history');
  return data;
};

export default api;
