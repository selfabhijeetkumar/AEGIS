import { useEffect, useState, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, Activity, Globe, Clock, X, Target, Filter, Brain,
  Copy, AlertTriangle, Map, Maximize2, Shield
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { MapContainer, TileLayer, Marker as LeafletMarker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { getScanResults, type ScanResult, type ThreatEvent } from '../services/api';

const EASE = [0.16, 1, 0.3, 1] as const;
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

/* ===== ANIMATED NUMBER ===== */
function AnimatedNumber({ value, duration = 1500, suffix = '' }: { value: number; duration?: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const countRef = useRef(0);
  const [display, setDisplay] = useState(0);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true;
        const startTime = performance.now();
        const animate = (now: number) => {
          const elapsed = now - startTime;
          const progress = Math.min(elapsed / duration, 1);
          // easeOutCubic
          const eased = 1 - Math.pow(1 - progress, 3);
          countRef.current = Math.floor(eased * value);
          if (progress < 1) {
            requestAnimationFrame(animate);
          } else {
            countRef.current = value;
          }
          setDisplay(countRef.current);
        };
        requestAnimationFrame(animate);
      }
    }, { threshold: 0.3 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [value, duration]);

  return <span ref={ref}>{display}{suffix}</span>;
}

/* ===== THREAT SCORE GAUGE ===== */
function ThreatGauge({ score, size = 220 }: { score: number; size?: number }) {
  const severity = score >= 66 ? 'CRITICAL' : score >= 31 ? 'MEDIUM' : 'LOW';
  const color = SEVERITY_COLORS[severity];
  const radius = size / 2 - 20;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference * (1 - score / 100);

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        {/* Background track */}
        <circle cx={size/2} cy={size/2} r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={8} />
        {/* Progress arc */}
        <motion.circle
          cx={size/2} cy={size/2} r={radius}
          fill="none" stroke={color} strokeWidth={8} strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
          style={{
            filter: score >= 66 ? `drop-shadow(0 0 16px ${color})` : `drop-shadow(0 0 10px ${color})`,
          }}
        />
        {/* Tick marks */}
        {Array.from({ length: 20 }, (_, i) => {
          const angle = (i / 20) * 360 - 90;
          const rad = (angle * Math.PI) / 180;
          const x1 = size/2 + (radius + 8) * Math.cos(rad);
          const y1 = size/2 + (radius + 8) * Math.sin(rad);
          const x2 = size/2 + (radius + 3) * Math.cos(rad);
          const y2 = size/2 + (radius + 3) * Math.sin(rad);
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(255,255,255,0.12)" strokeWidth={1} />;
        })}
      </svg>
      <div className="absolute text-center">
        <div className="font-display text-5xl" style={{ color, textShadow: `0 0 20px ${color}40` }}><AnimatedNumber value={score} /></div>
        <div className="font-mono text-xs mt-1 tracking-[0.15em] uppercase" style={{ color }}>{severity}</div>
      </div>
    </div>
  );
}

/* ===== COMMANDER'S BRIEF ===== */
function CommanderBrief({ brief, severity, scanId }: {
  brief: { lines: string[]; operation_id: string; generated_at: string };
  severity: string;
  scanId: string;
}) {
  const isCritical = severity === 'CRITICAL';
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.8, ease: EASE }}
      className="aegis-card mb-8 relative" style={{ padding: 32, paddingTop: 40, overflow: 'visible', minHeight: 'auto' }}
    >
      {/* Left edge glow bar — pulses on critical */}
      <div className={`absolute left-0 top-0 bottom-0 w-1 rounded-l-2xl ${isCritical ? 'commander-edge-critical' : 'commander-edge'}`}
        style={{ background: isCritical
          ? 'linear-gradient(to bottom, #ef4444, #f97316, rgba(239,68,68,0.2))'
          : 'linear-gradient(to bottom, #06b6d4, #3b82f6, rgba(59,130,246,0.2))'
        }} />

      {/* CLASSIFIED badge top-right */}
      <div className="absolute top-4 right-4">
        <span className="border border-red-500/30 text-red-400 text-[10px] font-mono tracking-[0.2em] uppercase px-2 py-0.5 rounded">
          CLASSIFIED
        </span>
      </div>

      {/* Header — must be the first visible element */}
      <p className="font-mono text-[10px] tracking-[0.25em] text-cyan-400 uppercase mb-4 opacity-70 ml-4">
        COMMANDER'S BRIEF — OPERATION AEGIS-{scanId?.slice(-6)}
      </p>

      {/* Content - typewriter lines */}
      <div className="space-y-2 ml-4" style={{ overflow: 'visible', paddingTop: 32 }}>
        {brief.lines.map((line, i) => (
          <TypewriterLine key={i} text={`▸ ${line}`} delay={300 + i * 800} />
        ))}
      </div>

      {/* Footer */}
      <div className="flex items-center gap-1.5 mt-4 ml-4">
        <Clock size={12} className="text-slate-600" />
        <span className="text-[10px] font-mono text-slate-600">
          Generated by AEGIS AI Engine — {new Date(brief.generated_at).toISOString()}
        </span>
      </div>
    </motion.div>
  );
}

/* Typewriter line component */
function TypewriterLine({ text, delay = 0 }: { text: string; delay?: number }) {
  const [displayed, setDisplayed] = useState('');
  const [started, setStarted] = useState(false);

  useEffect(() => {
    const timeout = setTimeout(() => setStarted(true), delay);
    return () => clearTimeout(timeout);
  }, [delay]);

  useEffect(() => {
    if (!started) return;
    let i = 0;
    const timer = setInterval(() => {
      if (i <= text.length) {
        setDisplayed(text.slice(0, i));
        i++;
      } else {
        clearInterval(timer);
      }
    }, 30);
    return () => clearInterval(timer);
  }, [started, text]);

  return (
    <p className="text-sm leading-relaxed" style={{ color: '#94a3b8' }}>
      {displayed}
      {displayed.length < text.length && started && <span className="typewriter-cursor" />}
    </p>
  );
}

/* ===== THREAT DETAIL SIDE PANEL ===== */
function ThreatDetailPanel({ threat, onClose }: { threat: ThreatEvent; onClose: () => void }) {
  const color = SEVERITY_COLORS[threat.severity];
  const panelRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  // Escape key closes panel
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  // Focus trap
  useEffect(() => {
    if (panelRef.current) panelRef.current.focus();
  }, []);

  const iptablesCmd = `# AEGIS AUTO-GENERATED DEFENCE RULE
iptables -A INPUT -s ${threat.source_ip} -j DROP
iptables -A INPUT -s ${threat.source_ip} -p tcp --dport 22 -j LOG --log-prefix "AEGIS-BLOCKED: "
iptables -A FORWARD -s ${threat.source_ip} -j DROP`;

  const handleCopy = () => {
    navigator.clipboard.writeText(iptablesCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      ref={panelRef}
      role="dialog"
      aria-label={`Threat detail panel for ${threat.threat_type}`}
      tabIndex={-1}
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
      className="side-panel"
    >
      <div className="p-6">
        <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors mb-6" aria-label="Close panel">
          <X size={24} />
        </button>

        {/* MITRE badge prominent at top */}
        <div className="aegis-card p-3 mb-4 text-center" style={{ borderColor: 'rgba(59,130,246,0.25)' }}>
          <Target size={20} className="text-blue-400 mx-auto mb-1" />
          <div className="font-mono text-lg text-blue-400 font-bold">{threat.mitre_code}</div>
          <div className="font-mono text-xs text-slate-400">{threat.mitre_technique}</div>
        </div>

        {/* Severity + MITRE badge */}
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <span className={`badge-${threat.severity.toLowerCase()}`}>{threat.severity}</span>
          <span className="badge-mitre">{threat.mitre_code}</span>
          <span className="font-mono text-xs text-slate-500">SCORE: {threat.severity_score}/100</span>
        </div>

        {/* Threat type heading */}
        <h2 className="text-xl font-bold mb-4" style={{ color, textShadow: `0 0 12px ${color}40` }}>{threat.threat_type}</h2>

        {/* MITRE ATT&CK Card */}
        <div className="aegis-card p-4 mb-4">
          <div className="flex items-center gap-2 mb-2">
            <Target size={16} className="text-cyan-400" />
            <span className="font-mono text-xs tracking-wider text-cyan-400">MITRE ATT&CK</span>
          </div>
          <div className="font-mono text-sm text-blue-400 mb-1">{threat.mitre_code} · {threat.mitre_technique}</div>
          <div className="font-mono text-[10px] text-slate-500 mb-2">TACTIC: {threat.mitre_tactic}</div>
          <p className="text-xs text-slate-400">{threat.description}</p>
        </div>

        {/* AI Intelligence Analysis Card — Gemini */}
        <div className="aegis-card p-4 mb-4" style={{ borderColor: 'rgba(6,182,212,0.2)' }}>
          <div className="flex items-center gap-2 mb-2">
            <Brain size={16} className="text-cyan-400" />
            <span className="font-mono text-xs tracking-wider text-cyan-400">GEMINI AI ANALYSIS</span>
          </div>
          <p className="text-sm leading-relaxed text-slate-400">{threat.ai_explanation}</p>
        </div>

        {/* Source Intelligence Grid */}
        <div className="aegis-card p-4 mb-4">
          <h4 className="font-mono text-xs tracking-wider text-slate-500 mb-3">SOURCE INTELLIGENCE</h4>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[10px] font-mono text-slate-600 mb-0.5">SOURCE IP</div>
              <div className="font-mono text-cyan-400 text-sm">{threat.source_ip}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-slate-600 mb-0.5">DESTINATION</div>
              <div className="font-mono text-slate-400 text-sm">{threat.dest_ip}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-slate-600 mb-0.5">COUNTRY</div>
              <div className="text-sm">{threat.country}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-slate-600 mb-0.5">ISP</div>
              <div className="text-sm text-slate-400">{threat.isp}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-slate-600 mb-0.5">TIMESTAMP</div>
              <div className="font-mono text-slate-400 text-xs">{String(threat.timestamp).slice(0, 19)}</div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-slate-600 mb-0.5">BYTES TRANSFERRED</div>
              <div className="font-mono text-sm text-slate-400">{threat.bytes_transferred?.toLocaleString()}</div>
            </div>
          </div>
        </div>

        {/* Raw Log Block */}
        <div className="mb-4">
          <h4 className="font-mono text-xs tracking-wider text-slate-500 mb-2">RAW LOG</h4>
          <div className="rounded-lg p-3 font-mono text-xs text-green-400/80 leading-5 overflow-x-auto" style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(16,185,129,0.1)' }}>
            <div>{threat.timestamp} {threat.protocol} {threat.source_ip} → {threat.dest_ip}</div>
            <div>bytes={threat.bytes_transferred} type={threat.threat_type}</div>
            <div>mitre={threat.mitre_code} score={threat.severity_score} severity={threat.severity}</div>
            <div>tactic={threat.mitre_tactic} technique={threat.mitre_technique}</div>
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="mb-6">
          <h4 className="font-mono text-xs tracking-wider text-slate-500 mb-3">RECOMMENDED ACTIONS</h4>
          <ul className="space-y-2">
            {threat.recommended_actions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-400">
                <span className="mt-1.5 w-1.5 h-1.5 rounded-full flex-shrink-0" style={{
                  background: i === 0 ? '#ef4444' : i === 1 ? '#f59e0b' : '#3b82f6'
                }} />
                {a}
              </li>
            ))}
          </ul>
        </div>

        {/* Engage Defences Button */}
        <button
          onClick={handleCopy}
          className="w-full py-3 rounded-lg font-mono text-sm tracking-wider flex items-center justify-center gap-2 transition-all duration-300"
          style={{
            background: copied ? 'rgba(16,185,129,0.2)' : 'linear-gradient(135deg, rgba(59,130,246,0.2), rgba(6,182,212,0.2))',
            border: `1px solid ${copied ? 'rgba(16,185,129,0.3)' : 'rgba(59,130,246,0.3)'}`,
            color: copied ? '#10b981' : '#3b82f6',
          }}
          aria-label="Copy iptables block command to clipboard"
        >
          <Copy size={16} />
          {copied ? 'COPIED TO CLIPBOARD' : 'ENGAGE DEFENCES'}
        </button>
      </div>
    </motion.div>
  );
}

/* ===== ATTACK TIMELINE — REDESIGNED ===== */
function AttackTimeline({ timeline, onSelectThreat }: { timeline: ThreatEvent[]; onSelectThreat: (t: ThreatEvent) => void }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.7 }}
      className="aegis-card mb-8" style={{ padding: 24 }}
    >
      <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-6 flex items-center gap-2 text-slate-500">
        <Clock size={16} /> ATTACK TIMELINE
      </h3>
      <div className="relative pl-12">
        {/* Vertical gradient line — bold neon glow */}
        <div
          className="absolute top-2 bottom-2 rounded-full"
          style={{
            left: 15,
            width: 3,
            background: 'linear-gradient(to bottom, #06b6d4, #3b82f6, rgba(59,130,246,0.2))',
            boxShadow: '0 0 8px rgba(6,182,212,0.6), 0 0 16px rgba(6,182,212,0.3)',
          }}
        />

        {timeline.slice(0, 15).map((t, i) => {
          const color = SEVERITY_COLORS[t.severity];
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.06, duration: 0.5, ease: EASE }}
              className="relative mb-6 cursor-pointer group"
              onClick={() => onSelectThreat(t)}
            >
              {/* Large bold severity dot with white ring */}
              <div className="absolute rounded-full"
                style={{
                  left: -30,
                  top: 10,
                  width: 18,
                  height: 18,
                  background: color,
                  border: '2px solid rgba(255,255,255,0.3)',
                  boxShadow: `0 0 12px ${color}, 0 0 24px ${color}60`,
                }}
              />

              {/* Timeline card with severity-colored left border */}
              <div className="ml-6 aegis-card group-hover:border-blue-500/30 transition-all duration-300"
                style={{
                  minHeight: 80,
                  borderLeft: `3px solid ${color}`,
                  ...(t.severity === 'CRITICAL' ? { boxShadow: '0 0 12px rgba(239,68,68,0.1)' } : {}),
                }}>
                <div className="flex items-center gap-3 mb-2 flex-wrap">
                  <span className="font-mono font-bold text-white text-sm">{String(t.timestamp).slice(0, 19)}</span>
                  <span className="badge-mitre">{t.mitre_code} · {t.mitre_technique}</span>
                  <span className={`badge-${t.severity.toLowerCase()}`}>{t.severity}</span>
                </div>
                <p className="text-sm text-slate-400">
                  {t.threat_type} from <span className="ip-highlight">{t.source_ip}</span> ({t.country})
                </p>
              </div>
            </motion.div>
          );
        })}
      </div>
    </motion.div>
  );
}

/* ===== MAIN DASHBOARD ===== */
export default function Dashboard() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);
  const [sortField, setSortField] = useState<string>('severity_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    if (!scanId) return;
    getScanResults(scanId).then(d => { setData(d); setLoading(false); }).catch(() => setLoading(false));
  }, [scanId]);

  const handleSelectThreat = useCallback((t: ThreatEvent) => {
    setSelectedThreat(t);
  }, []);

  const [alertsOpen, setAlertsOpen] = useState(false);
  const alertsRef = useRef<HTMLDivElement>(null);
  const [mapModalOpen, setMapModalOpen] = useState(false);
  const [barsMounted, setBarsMounted] = useState(false);

  // Close alerts dropdown on outside click
  useEffect(() => {
    if (!alertsOpen) return;
    const handler = (e: MouseEvent) => {
      if (alertsRef.current && !alertsRef.current.contains(e.target as Node)) {
        setAlertsOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [alertsOpen]);

  // Trigger severity bars animation on mount
  useEffect(() => {
    const timer = setTimeout(() => setBarsMounted(true), 150);
    return () => clearTimeout(timer);
  }, []);

  // Escape key closes map modal
  useEffect(() => {
    if (!mapModalOpen) return;
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') setMapModalOpen(false); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [mapModalOpen]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center z-10 relative">
        <div className="text-center">
          <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: 'linear' }}>
            <ShieldAlert size={32} className="text-blue-400 mx-auto" />
          </motion.div>
          <p className="font-mono text-sm mt-4 text-slate-500">LOADING INTELLIGENCE...</p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="min-h-screen flex items-center justify-center z-10 relative">
        <div className="text-center">
          <AlertTriangle size={24} className="text-red-400 mx-auto mb-4" />
          <p className="font-mono text-sm mb-4 text-red-400">INTELLIGENCE FAILURE — Scan data not found</p>
          <button onClick={() => navigate('/upload')} className="cta-button">NEW SCAN</button>
        </div>
      </div>
    );
  }

  const { metrics, commander_brief, threats, attack_types, timeline } = data;
  const severityData = [
    { name: 'CRITICAL', value: metrics.critical_count, color: '#ef4444', glow: '0 0 12px rgba(239,68,68,0.4)' },
    { name: 'MEDIUM', value: metrics.medium_count, color: '#f59e0b', glow: '0 0 12px rgba(245,158,11,0.4)' },
    { name: 'LOW', value: metrics.low_count, color: '#10b981', glow: '0 0 12px rgba(16,185,129,0.4)' },
  ];
  const severityTotal = Math.max(metrics.total_threats, 1);

  const barData = Object.entries(attack_types)
    .map(([name, value]) => ({ name, value: value as number }))
    .sort((a, b) => b.value - a.value);

  const sortedThreats = [...threats].sort((a, b) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const aVal = (a as any)[sortField];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bVal = (b as any)[sortField];
    if (typeof aVal === 'number') return sortDir === 'desc' ? bVal - aVal : aVal - bVal;
    return sortDir === 'desc' ? String(bVal).localeCompare(String(aVal)) : String(aVal).localeCompare(String(bVal));
  });

  const attackerMarkers = threats
    .filter(t => t.lat !== 0 && t.lon !== 0 && t.country !== 'Internal')
    .reduce((acc, t) => {
      const key = `${t.lat}-${t.lon}`;
      if (!acc.find(m => `${m.lat}-${m.lon}` === key)) {
        acc.push({ ...t, count: threats.filter(x => x.source_ip === t.source_ip).length });
      }
      return acc;
    }, [] as (ThreatEvent & { count: number })[]);

  const handleSort = (field: string) => {
    if (sortField === field) setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const metricCards = [
    { label: 'TOTAL THREATS', value: metrics.total_threats, icon: <Activity size={18} />, color: '#3b82f6', accent: 'metric-accent-blue' },
    { label: 'CRITICAL ALERTS', value: metrics.critical_count, icon: <ShieldAlert size={18} />, color: '#ef4444', accent: 'metric-accent-red' },
    { label: 'UNIQUE IPS', value: metrics.unique_ips, icon: <Globe size={18} />, color: '#f59e0b', accent: 'metric-accent-amber' },
    { label: 'SCAN TIME', value: metrics.scan_duration, icon: <Clock size={18} />, color: '#10b981', suffix: 's', accent: 'metric-accent-green' },
  ];

  const criticalThreats = threats.filter(t => t.severity === 'CRITICAL').slice(0, 8);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="relative z-10 min-h-screen"
    >
      {/* ===== NAV BAR ===== */}
      <motion.header
        initial={{ y: -64 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.5, ease: EASE }}
        className="fixed top-0 left-0 right-0 h-16 z-30 flex items-center justify-between"
        style={{
          background: 'rgba(3,7,18,0.85)',
          backdropFilter: 'blur(20px) saturate(180%)',
          borderBottom: '1px solid rgba(255,255,255,0.08)',
          paddingLeft: 'var(--page-padding-x)',
          paddingRight: 'var(--page-padding-x)',
        }}
      >
        <div className="flex items-center gap-3">
          <ShieldAlert size={20} className="text-blue-400" />
          <span className="font-bold tracking-wider text-sm">AEGIS</span>
        </div>

        <nav className="hidden md:flex items-center">
          <div className="flex items-center gap-4 rounded-xl p-1.5" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <span className="rounded-lg px-6 py-2 font-mono text-sm tracking-wider cursor-pointer font-medium transition-colors" style={{ background: 'rgba(59,130,246,0.15)', color: '#60a5fa' }}>Dashboard</span>
            <span onClick={() => navigate(`/report/${scanId}`)} className="rounded-lg px-6 py-2 font-mono text-sm tracking-wider cursor-pointer text-slate-500 hover:text-white hover:bg-white/[0.05] transition-all font-medium">Report</span>
          </div>
        </nav>

        <div className="flex items-center gap-4">
          {/* Mini threat score */}
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLORS[metrics.overall_severity], boxShadow: `0 0 8px ${SEVERITY_COLORS[metrics.overall_severity]}` }} />
            <span className="font-mono text-xs font-bold" style={{ color: SEVERITY_COLORS[metrics.overall_severity] }}>
              {metrics.overall_threat_score}
            </span>
          </div>
          {/* Critical count badge — clickable dropdown */}
          <div className="relative" ref={alertsRef}>
            <button
              onClick={() => setAlertsOpen(prev => !prev)}
              className="relative cursor-pointer"
              aria-label="Toggle critical alerts panel"
            >
              <AlertTriangle size={18} className="text-slate-400" />
              {metrics.critical_count > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-[9px] font-bold flex items-center justify-center" style={{ boxShadow: '0 0 8px rgba(239,68,68,0.5)' }}>
                  {metrics.critical_count}
                </span>
              )}
            </button>

            {/* Critical alerts dropdown */}
            <AnimatePresence>
              {alertsOpen && (
                <motion.div
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.2 }}
                  className="absolute top-full right-0 mt-2 w-80 rounded-xl overflow-hidden"
                  style={{
                    background: 'rgba(12, 18, 32, 0.95)',
                    backdropFilter: 'blur(24px)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    boxShadow: '0 16px 48px rgba(0,0,0,0.5)',
                    zIndex: 9999,
                  }}
                >
                  <div className="p-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                    <span className="font-mono text-xs tracking-[0.15em] text-slate-500 uppercase">Critical Alerts</span>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {criticalThreats.length === 0 ? (
                      <div className="p-6 text-center">
                        <p className="font-mono text-sm text-slate-500">No critical alerts</p>
                      </div>
                    ) : (
                      criticalThreats.map((t, i) => (
                        <div
                          key={i}
                          className="px-4 py-3 cursor-pointer transition-colors hover:bg-white/[0.03]"
                          style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                          onClick={() => { handleSelectThreat(t); setAlertsOpen(false); }}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-xs text-blue-400">{t.source_ip}</span>
                            <span className="badge-critical">{t.severity}</span>
                          </div>
                          <div className="font-mono text-xs text-slate-500">{t.threat_type} · {t.mitre_code}</div>
                        </div>
                      ))
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          <button
            onClick={() => navigate('/upload')}
            className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-mono tracking-[0.1em] rounded-lg px-4 py-1.5 transition-colors"
          >
            NEW SCAN
          </button>
        </div>
      </motion.header>

      {/* ===== MAIN CONTENT ===== */}
      <main className="pt-20 pb-24 max-w-[1440px] mx-auto perspective-container" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>

        {/* COMMANDER'S BRIEF */}
        <CommanderBrief brief={commander_brief} severity={metrics.overall_severity} scanId={scanId || ''} />

        {/* KEY METRICS */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-5 mb-8">
          {metricCards.map((m, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * i, ease: EASE }}
              className="aegis-card relative overflow-hidden" style={{ minHeight: 120 }}
            >
              {/* Top accent gradient line */}
              <div className={`absolute top-0 left-0 right-0 h-px ${m.accent}`} />
              <div className="flex items-center justify-between mb-3">
                <span style={{ color: m.color }}>{m.icon}</span>
                <span className="font-mono text-[10px] tracking-[0.2em] uppercase text-slate-500">{m.label}</span>
              </div>
              <div className="font-display text-3xl" style={{ color: m.color, textShadow: `0 0 12px ${m.color}30` }}>
                <AnimatedNumber value={m.value} suffix={m.suffix || ''} />
              </div>
            </motion.div>
          ))}
        </div>

        {/* ROW 1: Gauge + Donut */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="md:col-span-2 aegis-card flex flex-col items-center justify-center relative" style={{ minHeight: 320 }}
          >

            <div className="text-center relative z-10">
              <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-4 text-slate-500">OVERALL THREAT SCORE</h3>
              <ThreatGauge score={metrics.overall_threat_score} />
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="aegis-card"
          >
            <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-6 text-slate-500">SEVERITY DISTRIBUTION</h3>
            <div className="space-y-5">
              {severityData.map((d) => {
                const pct = Math.round((d.value / severityTotal) * 100);
                return (
                  <div key={d.name}>
                    <div className="flex items-center gap-3 mb-2">
                      {/* Severity icon circle */}
                      <div className="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0"
                        style={{ background: `${d.color}20`, border: `1.5px solid ${d.color}40` }}>
                        {d.name === 'CRITICAL' ? <Shield size={16} style={{ color: d.color }} /> :
                         <div className="w-3 h-3 rounded-full" style={{ background: d.color }} />}
                      </div>
                      {/* Label */}
                      <span className="font-mono text-xs tracking-wider text-slate-300 w-20">{d.name}</span>
                      {/* Bar track */}
                      <div className="flex-1 h-9 rounded-full relative" style={{ background: 'rgba(255,255,255,0.06)' }}>
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: barsMounted ? `${pct}%` : '0%',
                            background: d.color,
                            boxShadow: d.glow,
                            transition: 'width 1.2s cubic-bezier(0.16,1,0.3,1)',
                            minWidth: pct > 0 ? 8 : 0,
                          }}
                        />
                      </div>
                      {/* Percentage */}
                      <span className="font-mono text-sm font-bold w-12 text-right" style={{ color: d.color }}>{pct}%</span>
                    </div>
                    <div className="font-mono text-xs text-slate-500 ml-12 pl-1">{d.value} threats detected</div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </div>

        {/* ROW 2: World Map + Bar Chart */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }} className="aegis-card relative overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-mono text-xs tracking-[0.15em] uppercase flex items-center gap-2 text-slate-500">
                <Map size={16} /> IP GEOLOCATION — ATTACKER ORIGINS
              </h3>
              <button
                onClick={() => setMapModalOpen(true)}
                className="p-1.5 rounded-lg transition-all hover:bg-white/[0.08] text-slate-500 hover:text-white"
                aria-label="Open fullscreen map"
              >
                <Maximize2 size={16} />
              </button>
            </div>
            <div className="relative" style={{ height: 350 }}>
              <ComposableMap
                projectionConfig={{ scale: 130, center: [20, 10] }}
                style={{ width: '100%', height: '100%' }}
              >
                <Geographies geography={GEO_URL}>
                  {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                  {({ geographies }: { geographies: any[] }) =>
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    geographies.map((geo: any) => {
                      const isAttackerCountry = attackerMarkers.some(m => m.country === geo.properties?.name);
                      return (
                        <Geography
                          key={geo.rsmKey}
                          geography={geo}
                          fill={isAttackerCountry ? '#1e3a5f' : '#162033'}
                          stroke="#0c1525"
                          strokeWidth={0.5}
                          style={{
                            default: { outline: 'none' },
                            hover: { fill: isAttackerCountry ? '#2563eb' : '#1e293b', outline: 'none' },
                            pressed: { outline: 'none' }
                          }}
                        />
                      );
                    })
                  }
                </Geographies>
                {attackerMarkers.map((m, i) => {
                  const markerColor = m.severity === 'CRITICAL' ? '#ef4444' : SEVERITY_COLORS[m.severity] || '#ef4444';
                  return (
                    <Marker key={i} coordinates={[m.lon, m.lat]}>
                      <circle r={4} fill={markerColor} opacity={0.95} style={{ filter: `drop-shadow(0 0 6px ${markerColor})` }} />
                      <circle r={6} fill="none" stroke={markerColor} strokeWidth={1.5} opacity={0.6}>
                        <animate attributeName="r" values="4;14;4" dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.7;0;0.7" dur="2s" repeatCount="indefinite" />
                      </circle>
                      <circle r={8} fill="none" stroke={markerColor} strokeWidth={1} opacity={0.3}>
                        <animate attributeName="r" values="6;20;6" dur="2s" begin="0.4s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.5;0;0.5" dur="2s" begin="0.4s" repeatCount="indefinite" />
                      </circle>
                    </Marker>
                  );
                })}
              </ComposableMap>
            </div>
            <div className="flex gap-4 mt-2">
              {Object.entries(SEVERITY_COLORS).map(([k, v]) => (
                <div key={k} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full" style={{ background: v, boxShadow: `0 0 6px ${v}` }} />
                  <span className="font-mono text-[10px] text-slate-500">{k}</span>
                </div>
              ))}
            </div>
          </motion.div>

          {/* ===== FULLSCREEN MAP MODAL ===== */}
          <AnimatePresence>
            {mapModalOpen && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-50 flex flex-col"
                style={{ background: 'rgba(5,10,24,0.95)', backdropFilter: 'blur(24px)' }}
              >
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <div className="flex items-center gap-3">
                    <Globe size={18} className="text-blue-400" />
                    <span className="font-mono text-xs tracking-[0.15em] uppercase text-slate-400">IP GEOLOCATION — THREAT ORIGIN MAPPING</span>
                    <span className="badge-critical ml-2">{attackerMarkers.length} ORIGINS</span>
                  </div>
                  <button
                    onClick={() => setMapModalOpen(false)}
                    className="p-2 rounded-lg hover:bg-white/[0.08] text-slate-400 hover:text-white transition-colors"
                    aria-label="Close fullscreen map"
                  >
                    <X size={20} />
                  </button>
                </div>
                {/* Leaflet Map */}
                <div className="flex-1">
                  <MapContainer
                    center={[20, 0]}
                    zoom={2}
                    scrollWheelZoom={true}
                    zoomControl={true}
                    dragging={true}
                    style={{ width: '100%', height: '100%' }}
                  >
                    <TileLayer
                      attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
                      url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                    />
                    {attackerMarkers.map((m, i) => {
                      const markerColor = SEVERITY_COLORS[m.severity] || '#ef4444';
                      const icon = L.divIcon({
                        className: '',
                        html: `<div style="width:16px;height:16px;border-radius:50%;background:${markerColor};box-shadow:0 0 0 4px ${markerColor}4D, 0 0 12px ${markerColor};animation:leafletPulse 2s infinite;"></div>`,
                        iconSize: [16, 16],
                        iconAnchor: [8, 8],
                      });
                      return (
                        <LeafletMarker key={i} position={[m.lat, m.lon]} icon={icon}>
                          <Popup>
                            <div style={{ minWidth: 200, fontFamily: 'JetBrains Mono, monospace' }}>
                              <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8, color: '#f8fafc' }}>{m.country}</div>
                              <div style={{ fontSize: 12, color: '#22d3ee', marginBottom: 4 }}>{m.source_ip}</div>
                              <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>{m.threat_type}</div>
                              <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4 }}>
                                <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 999, background: `${markerColor}25`, color: markerColor, border: `1px solid ${markerColor}50` }}>{m.severity}</span>
                                <span style={{ fontSize: 10, color: '#3b82f6' }}>{m.mitre_code}</span>
                              </div>
                              <div style={{ fontSize: 10, color: '#64748b' }}>{m.bytes_transferred?.toLocaleString()} bytes</div>
                            </div>
                          </Popup>
                        </LeafletMarker>
                      );
                    })}
                  </MapContainer>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }} className="aegis-card">
            <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-4 flex items-center gap-2 text-slate-500">
              <Activity size={16} /> ATTACK TYPE DISTRIBUTION
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={barData} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" stroke="#334155" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <YAxis type="category" dataKey="name" width={120} tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono' }} stroke="transparent" />
                <Tooltip contentStyle={{ background: 'rgba(10,15,30,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, color: '#f1f5f9', fontFamily: 'JetBrains Mono', fontSize: 12 }} />
                <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={20}>
                  {barData.map((_, i) => <Cell key={i} fill={i < 2 ? '#ef4444' : i < 4 ? '#f59e0b' : '#3b82f6'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </motion.div>
        </div>

        {/* ATTACK TIMELINE */}
        <AttackTimeline timeline={timeline} onSelectThreat={handleSelectThreat} />

        {/* THREAT LOG TABLE */}
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.8 }} className="aegis-card overflow-hidden mb-8">
          <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            <h3 className="font-mono text-xs tracking-[0.15em] uppercase flex items-center gap-2 text-slate-500">
              <Filter size={16} /> THREAT LOG — {threats.length} ENTRIES
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="threat-table">
              <thead>
                <tr>
                  {['#', 'Timestamp', 'Source IP', 'Type', 'Severity', 'MITRE'].map(col => (
                    <th key={col}
                      onClick={() => handleSort(col === '#' ? 'id' : col === 'Source IP' ? 'source_ip' : col === 'Type' ? 'threat_type' : col === 'Severity' ? 'severity_score' : col === 'MITRE' ? 'mitre_code' : 'timestamp')}
                      className="cursor-pointer hover:text-white transition-colors"
                    >
                      {col} {sortField === col.toLowerCase().replace(' ', '_') && (sortDir === 'desc' ? '↓' : '↑')}
                    </th>
                  ))}
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedThreats.slice(0, 50).map(t => (
                  <tr key={t.id} onClick={() => handleSelectThreat(t)}>
                    <td className="font-mono text-xs text-slate-500">{t.id}</td>
                    <td className="font-mono text-xs text-slate-400">{String(t.timestamp).slice(0, 19)}</td>
                    <td className="ip-highlight text-sm">{t.source_ip}</td>
                    <td className="text-sm">{t.threat_type}</td>
                    <td><span className={`badge-${t.severity.toLowerCase()}`}>{t.severity}</span></td>
                    <td><span className="badge-mitre">{t.mitre_code}</span></td>
                    <td>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleSelectThreat(t); }}
                        className="font-mono text-xs px-3 py-1 rounded transition-all hover:bg-blue-500/20 text-blue-400 hover:shadow-[0_0_8px_rgba(59,130,246,0.3)]"
                        aria-label={`View threat ${t.id} details`}
                      >
                        VIEW
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* ATTACK TYPE CARDS */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-5 mb-8">
          {Object.entries(attack_types).map(([type, count], i) => (
            <motion.div
              key={type}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.9 + i * 0.05, ease: EASE }}
              className="aegis-card text-center"
            >
              <div className="font-display text-2xl mb-1"><AnimatedNumber value={count as number} /></div>
              <div className="font-mono text-[10px] tracking-[0.15em] uppercase text-slate-500">{type}</div>
            </motion.div>
          ))}
        </div>
      </main>

      {/* FLOATING REPORT BUTTON — RED GLOW PULSE */}
      <motion.button
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1 }}
        onClick={() => navigate(`/report/${scanId}`)}
        className="fixed bottom-6 right-6 z-30 cta-button report-btn-glow"
        style={{ borderColor: 'rgba(239,68,68,0.4)' }}
        whileHover={{ scale: 1.05 }}
        aria-label="Generate AEGIS incident report"
      >
        GENERATE AEGIS INCIDENT REPORT →
      </motion.button>

      {/* THREAT DETAIL SIDE PANEL */}
      <AnimatePresence>
        {selectedThreat && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="side-panel-backdrop"
              onClick={() => setSelectedThreat(null)}
            />
            <ThreatDetailPanel threat={selectedThreat} onClose={() => setSelectedThreat(null)} />
          </>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
