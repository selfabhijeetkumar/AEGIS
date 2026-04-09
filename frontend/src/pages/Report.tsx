import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Download, History, Menu, Shield, Check, ShieldAlert
} from 'lucide-react';
import { getScanResults, getHistory, type ScanResult, type ScanSummary } from '../services/api';
import jsPDF from 'jspdf';

const EASE = [0.16, 1, 0.3, 1] as const;

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

/* ===== REPORT PREVIEW (CHANGE-20) ===== */
function ReportPreview({ data }: { data: ScanResult }) {
  const { metrics, commander_brief, threats } = data;

  return (
    <div className="rounded-2xl shadow-2xl overflow-hidden relative" style={{ minWidth: 580, maxHeight: '85vh', overflowY: 'auto', background: '#0a0f1a', color: '#e2e8f0' }}>
      {/* AEGIS Shield watermark */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <Shield size={256} className="opacity-[0.06] text-blue-900" />
      </div>

      {/* Cover Page */}
      <div className="text-center border-b-2 border-blue-900/50 flex flex-col items-center justify-center relative" style={{ minHeight: 480, padding: 40, background: 'linear-gradient(180deg, #0d1526 0%, #0a0f1a 100%)' }}>
        {/* Dark header bar */}
        <div className="absolute top-0 left-0 right-0 h-1" style={{ background: 'linear-gradient(90deg, #3b82f6, #06b6d4, #10b981)' }} />
        
        {/* Classified header */}
        <div className="font-mono text-[10px] tracking-[0.3em] text-blue-500/60 mb-6 mt-8">
          ADVANCED ENGINE FOR GUIDED INTELLIGENCE & SURVEILLANCE
        </div>
        <h1 className="text-4xl font-extrabold tracking-tight text-white mb-2" style={{ textShadow: '0 0 30px rgba(59,130,246,0.3)' }}>AEGIS</h1>
        <h2 className="text-2xl font-bold text-blue-400 mb-8">INCIDENT REPORT</h2>

        {/* CONFIDENTIAL stamp (CHANGE-20) */}
        <div className="classified-stamp mb-8" style={{ color: '#dc2626', borderColor: '#dc2626', boxShadow: '0 0 20px rgba(220,38,38,0.3)' }}>
          CONFIDENTIAL — EYES ONLY
        </div>

        <div className="max-w-sm mx-auto text-left space-y-3 mt-4" style={{ borderLeft: '2px solid rgba(59,130,246,0.3)', paddingLeft: '1rem' }}>
          {[
            ['SCAN ID', data.scan_id],
            ['DATE', new Date(data.timestamp).toLocaleString()],
            ['CLASSIFICATION', metrics.overall_severity],
            ['TOTAL THREATS', String(metrics.total_threats)],
            ['CRITICAL ALERTS', String(metrics.critical_count)],
            ['THREAT SCORE', `${metrics.overall_threat_score}/100`],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between border-b border-blue-900/30 pb-2">
              <span className="font-mono text-xs text-blue-400/60">{label}</span>
              <span className="font-mono text-sm text-white font-semibold">{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Executive Summary */}
      <div className="border-b border-blue-900/50" style={{ padding: 40, background: 'linear-gradient(180deg, #0d1526 0%, #0a0f1a 100%)', minHeight: 280, overflow: 'visible' }}>
        <h3 className="text-lg font-bold text-white mb-4 tracking-wide">EXECUTIVE SUMMARY</h3>
        <div className="mb-4" style={{ overflow: 'visible' }}>
          <h4 className="font-mono text-xs text-blue-500 tracking-wider mb-2">COMMANDER'S BRIEF</h4>
          {commander_brief.lines.map((line, i) => (
            <p key={i} className="text-sm text-blue-200/80 leading-relaxed mb-1">▸ {line}</p>
          ))}
        </div>

        <div className="grid grid-cols-4 gap-3 mt-6">
          {[
            { label: 'Total Threats', value: metrics.total_threats },
            { label: 'Critical', value: metrics.critical_count },
            { label: 'Unique IPs', value: metrics.unique_ips },
            { label: 'Scan Time', value: `${metrics.scan_duration}s` },
          ].map((m, i) => (
            <div key={i} className="rounded-lg p-3 text-center" style={{ background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)' }}>
              <div className="text-xl font-bold text-white">{m.value}</div>
              <div className="text-[10px] font-mono text-blue-400/60 mt-1">{m.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Threat Table */}
      <div className="border-b border-blue-900/50" style={{ padding: 40, background: 'linear-gradient(180deg, #0d1526 0%, #0a0f1a 100%)' }}>
        <h3 className="text-lg font-bold text-white mb-4 tracking-wide">THREAT INVENTORY</h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b-2 border-blue-900/50">
              <th className="text-left py-2 font-mono text-xs text-blue-500/60">#</th>
              <th className="text-left py-2 font-mono text-xs text-blue-500/60">TIME</th>
              <th className="text-left py-2 font-mono text-xs text-blue-500/60">SOURCE IP</th>
              <th className="text-left py-2 font-mono text-xs text-blue-500/60">TYPE</th>
              <th className="text-left py-2 font-mono text-xs text-blue-500/60">SEVERITY</th>
              <th className="text-left py-2 font-mono text-xs text-blue-500/60">MITRE</th>
            </tr>
          </thead>
          <tbody>
            {threats.slice(0, 15).map(t => (
              <tr key={t.id} className="border-b border-blue-900/30">
                <td className="py-2 font-mono text-xs text-blue-400/60">{t.id}</td>
                <td className="py-2 font-mono text-xs text-blue-300/80">{String(t.timestamp).slice(11, 19)}</td>
                <td className="py-2 font-mono text-xs text-blue-400">{t.source_ip}</td>
                <td className="py-2 text-xs text-blue-200">{t.threat_type}</td>
                <td className="py-2">
                  <span className="text-xs font-bold px-2 py-0.5 rounded" style={{
                    color: SEVERITY_COLORS[t.severity],
                    background: `${SEVERITY_COLORS[t.severity]}15`,
                  }}>
                    {t.severity}
                  </span>
                </td>
                <td className="py-2 font-mono text-xs text-blue-500">{t.mitre_code}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {threats.length > 15 && (
          <p className="text-xs text-blue-500/50 mt-2 font-mono">
            + {threats.length - 15} additional entries in full PDF report
          </p>
        )}
      </div>

      {/* AI Analysis Preview */}
      <div className="border-b border-blue-900/50" style={{ padding: 40, background: 'linear-gradient(180deg, #0d1526 0%, #0a0f1a 100%)' }}>
        <h3 className="text-lg font-bold text-white mb-4 tracking-wide">AI INTELLIGENCE ANALYSIS</h3>
        {threats.filter(t => t.severity === 'CRITICAL').slice(0, 3).map(t => (
          <div key={t.id} className="mb-4 p-4 rounded-lg" style={{ background: 'rgba(239,68,68,0.08)', borderLeft: '3px solid #ef4444' }}>
            <h4 className="font-bold text-sm text-white mb-1">{t.threat_type} — {t.mitre_code}</h4>
            <p className="text-xs text-blue-200/70 leading-relaxed">{t.ai_explanation}</p>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="p-4 text-center" style={{ background: '#0d1526' }}>
        <p className="font-mono text-[10px] text-blue-600">
          AEGIS v2.1 | CLASSIFIED | {data.scan_id} | Generated {new Date().toISOString().slice(0, 10)}
        </p>
      </div>
    </div>
  );
}

/* ===== MAIN REPORT PAGE ===== */
export default function Report() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        if (scanId) {
          const result = await getScanResults(scanId);
          setData(result);
        }
        const hist = await getHistory();
        setHistory(hist.scans);
      } catch (e) {
        console.error(e);
      }
      setLoading(false);
    };
    load();
  }, [scanId]);

  const handleDownload = () => {
    if (!scanId || !data) return;
    setDownloading(true);
    
    try {
      const doc = new jsPDF();
      let y = 20;
      
      // Header
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(59, 130, 246); // blue
      doc.setFontSize(24);
      doc.text('AEGIS INCIDENT REPORT', 105, y, { align: 'center' });
      y += 10;
      
      // Confidential stamp
      doc.setTextColor(239, 68, 68); // red
      doc.setFontSize(14);
      doc.text('CONFIDENTIAL EYES ONLY', 105, y, { align: 'center' });
      y += 20;
      
      // Metadata
      doc.setTextColor(0, 0, 0);
      doc.setFontSize(10);
      doc.text(`SCAN ID: ${data.scan_id}`, 20, y);
      doc.text(`DATE: ${new Date().toLocaleString()}`, 20, y + 6);
      doc.text(`CLASSIFICATION: CRITICAL`, 20, y + 12);
      
      doc.text(`TOTAL THREATS: ${data.metrics.total_threats}`, 120, y);
      doc.text(`CRITICAL ALERTS: ${data.metrics.critical_count}`, 120, y + 6);
      doc.text(`THREAT SCORE: ${data.metrics.overall_threat_score}/100`, 120, y + 12);
      y += 30;
      
      // Commander's Brief
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text("COMMANDER'S BRIEF", 20, y);
      y += 8;
      
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cb = data.commander_brief as any;
      const briefText = Array.isArray(cb) ? cb.join(' | ') : (cb?.lines || cb?.bullets || cb?.text || Object.values(cb || {}).join(' | '));
      const briefStr = Array.isArray(briefText) ? briefText.join(' | ') : String(briefText || 'No brief available');
      const textLines = doc.splitTextToSize(briefStr, 170);
      doc.text(textLines, 20, y);
      y += (textLines.length * 6) + 10;
      
      // Threat inventory
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('THREAT INVENTORY (CRITICAL)', 20, y);
      y += 10;
      
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('TIMESTAMP', 20, y);
      doc.text('SOURCE IP', 60, y);
      doc.text('THREAT TYPE', 100, y);
      doc.text('SEVERITY', 150, y);
      doc.text('MITRE', 175, y);
      y += 6;
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      data.threats.filter(t => t.severity === 'CRITICAL').slice(0, 20).forEach(t => {
        if (y > 270) {
          doc.addPage();
          y = 20;
        }
        doc.text(String(t.timestamp).slice(0, 19), 20, y);
        doc.text(t.source_ip, 60, y);
        doc.text(t.threat_type.slice(0, 20), 100, y);
        doc.setTextColor(239, 68, 68);
        doc.text(t.severity, 150, y);
        doc.setTextColor(0, 0, 0);
        doc.text(t.mitre_code, 175, y);
        y += 6;
      });
      
      // Save
      doc.save(`AEGIS-Incident-Report-${scanId.slice(0, 8)}.pdf`);
    } catch (e) {
      console.error('PDF error', e);
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center z-10 relative">
        <div className="text-center">
          <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: 'linear' }}>
            <ShieldAlert size={32} className="text-blue-400 mx-auto" />
          </motion.div>
          <p className="font-mono text-sm mt-4 text-slate-500">GENERATING REPORT...</p>
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="relative z-10 min-h-screen"
    >
      {/* NAV BAR (CHANGE-21) */}
      <motion.header
        initial={{ y: -64 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.5, ease: EASE }}
        className="fixed top-0 left-0 right-0 h-16 z-30 flex items-center justify-between"
        style={{ background: 'rgba(5,10,24,0.8)', backdropFilter: 'blur(20px)', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}
      >
        <div className="flex items-center gap-3">
          <ShieldAlert size={20} className="text-blue-400" />
          <span className="font-bold tracking-wider text-sm">AEGIS</span>
        </div>
        <nav className="hidden md:flex items-center">
          <div className="flex items-center gap-4 rounded-xl p-1.5" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <span onClick={() => scanId && navigate(`/dashboard/${scanId}`)} className="rounded-lg px-6 py-2 font-mono text-sm tracking-wider cursor-pointer text-slate-500 hover:text-white hover:bg-white/[0.05] transition-all font-medium">Dashboard</span>
            <span className="rounded-lg px-6 py-2 font-mono text-sm tracking-wider cursor-pointer font-medium transition-colors" style={{ background: 'rgba(59,130,246,0.15)', color: '#60a5fa' }}>Report</span>
          </div>
        </nav>
        <button onClick={() => navigate('/upload')} className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-mono tracking-[0.1em] rounded-lg px-4 py-1.5 transition-colors">
          NEW SCAN
        </button>
      </motion.header>

      <main className="pt-20 pb-24 max-w-[1440px] mx-auto" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
          {/* PDF Preview - Left (CHANGE-20) */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, ease: EASE }}
            className="lg:col-span-3"
          >
            <h2 className="section-label section-label-blue mb-4">
              AEGIS INCIDENT REPORT — PREVIEW
            </h2>
            {data ? (
              <ReportPreview data={data} />
            ) : (
              <div className="aegis-card p-12 text-center">
                <p className="font-mono text-sm text-slate-500">No scan data available</p>
              </div>
            )}
          </motion.div>

          {/* Actions Panel - Right */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.2, ease: EASE }}
            className="lg:col-span-2 space-y-8" style={{ minWidth: 320, paddingTop: 32, paddingBottom: 32 }}
          >
            {/* Download */}
            <div className="aegis-card" style={{ padding: '32px 24px' }}>
              <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-6 flex items-center gap-2 text-slate-500">
                <Download size={16} /> ACTIONS
              </h3>

              <div className="mt-4">
                <button
                  onClick={handleDownload}
                  disabled={downloading || !scanId}
                  className="w-full py-3 rounded-lg font-mono text-sm tracking-wider flex items-center justify-center gap-2 text-white relative overflow-hidden transition-all"
                  style={{
                    background: 'linear-gradient(to right, #2563eb, #3b82f6)',
                    opacity: downloading ? 0.5 : 1,
                  }}
                >
                  {/* Glow underneath */}
                  <div className="absolute inset-0 -z-10 blur-xl opacity-30" style={{ background: 'rgba(59,130,246,0.5)' }} />
                  {downloading ? 'GENERATING...' : 'DOWNLOAD AEGIS INCIDENT REPORT PDF'}
                </button>
              </div>

              {data && (
                <div className="font-mono text-xs text-center mt-4 text-slate-500">
                  {data.scan_id} · {data.metrics.total_threats} threats documented
                </div>
              )}
            </div>

            {/* Report Contents (CHANGE-20) */}
            <div className="aegis-card" style={{ padding: 32 }}>
              <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-4 flex items-center gap-2 text-slate-500">
                <Menu size={16} /> REPORT INCLUDES
              </h3>
              <ul className="space-y-2">
                {[
                  'Commander\'s Brief',
                  'Executive Summary',
                  'Full Threat Inventory',
                  'MITRE ATT&CK Mapping',
                  'AI Intelligence Analysis',
                  'Attack Timeline',
                  'IP Geolocation Data',
                  'Recommended Actions',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm text-slate-400">
                    <Check size={16} className="text-blue-400" /> {item}
                  </li>
                ))}
              </ul>
            </div>

            {/* Scan History (CHANGE-20) */}
            <div className="aegis-card" style={{ padding: 32 }}>
              <h3 className="font-mono text-xs tracking-[0.15em] uppercase mb-4 flex items-center gap-2 text-slate-500">
                <History size={16} /> SCAN HISTORY — THE ARCHIVE
              </h3>

              {history.length === 0 ? (
                <p className="font-mono text-xs text-slate-600">No archived scans</p>
              ) : (
                <div className="space-y-3">
                  {history.map((scan) => (
                    <div
                      key={scan.scan_id}
                      className="aegis-card p-3 cursor-pointer transition-all hover:bg-white/[0.05] hover:border-blue-500/25"
                      onClick={() => navigate(`/dashboard/${scan.scan_id}`)}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-xs ip-highlight">{scan.scan_id}</span>
                        <span className={`badge-${scan.overall_severity.toLowerCase()}`}>{scan.overall_severity}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-slate-600">
                          {new Date(scan.timestamp).toLocaleString()}
                        </span>
                        <span className="font-mono text-[10px] text-slate-500">
                          {scan.total_threats} threats · {scan.scan_duration}s
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        </div>
      </main>
    </motion.div>
  );
}
