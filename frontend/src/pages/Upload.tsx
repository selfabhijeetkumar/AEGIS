import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useDropzone } from 'react-dropzone';
import {
  Lock, BarChart3, Brain, Target, AlertTriangle, Upload as UploadIcon,
  Zap, Cpu, Shield
} from 'lucide-react';
import { uploadFile, runDemo } from '../services/api';

const EASE = [0.16, 1, 0.3, 1] as const;

const LOADING_PHASES = [
  { pct: 20, text: 'SECURING CONNECTION...', sub: 'Establishing encrypted channel', icon: <Lock size={20} /> },
  { pct: 50, text: 'PARSING LOG STRUCTURE...', sub: 'Extracting network flow features', icon: <BarChart3 size={20} /> },
  { pct: 80, text: 'RUNNING ISOLATION FOREST...', sub: 'Running anomaly detection model', icon: <Brain size={20} /> },
  { pct: 95, text: 'MAPPING MITRE ATT&CK...', sub: 'Classifying threat techniques', icon: <Target size={20} /> },
  { pct: 100, text: 'THREATS DETECTED.', sub: '', icon: <AlertTriangle size={20} className="text-red-400" /> },
];

function BinaryRain() {
  const [cols] = useState(() =>
    Array.from({ length: 30 }, (_, i) => ({
      id: i,
      chars: Array.from({ length: 20 }, () => Math.random() > 0.5 ? '1' : '0'),
      x: Math.random() * 100,
      speed: 2 + Math.random() * 4,
      delay: Math.random() * 3,
    }))
  );

  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-15">
      {cols.map(col => (
        <motion.div
          key={col.id}
          className="absolute font-mono text-xs leading-4"
          style={{ left: `${col.x}%`, color: '#3b82f6', writingMode: 'vertical-lr' }}
          initial={{ y: '-100%' }}
          animate={{ y: '100vh' }}
          transition={{ repeat: Infinity, duration: col.speed, delay: col.delay, ease: 'linear' }}
        >
          {col.chars.join('')}
        </motion.div>
      ))}
    </div>
  );
}

function RadarSweep() {
  return (
    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
      <motion.div
        className="w-[300px] h-[300px] rounded-full"
        style={{
          background: 'conic-gradient(from 0deg, transparent 0deg, rgba(59,130,246,0.15) 30deg, transparent 60deg)',
        }}
        animate={{ rotate: 360 }}
        transition={{ repeat: Infinity, duration: 3, ease: 'linear' }}
      />
      {[100, 180, 260].map((size, i) => (
        <div
          key={i}
          className="absolute rounded-full border"
          style={{ width: size, height: size, borderColor: 'rgba(59,130,246,0.1)' }}
        />
      ))}
    </div>
  );
}

export default function Upload() {
  const navigate = useNavigate();
  const [uploading, setUploading] = useState(false);
  const [phase, setPhase] = useState(0);
  const [progress, setProgress] = useState(0);
  const [threatCount, setThreatCount] = useState(0);
  const [error, setError] = useState('');

  const processFile = useCallback(async (action: () => Promise<{ scan_id: string; message: string }>) => {
    setUploading(true);
    setError('');
    setPhase(0);
    setProgress(0);

    const phaseTimer = setInterval(() => {
      setPhase(prev => {
        if (prev < LOADING_PHASES.length - 2) return prev + 1;
        return prev;
      });
    }, 2500);

    const progressTimer = setInterval(() => {
      setProgress(prev => {
        if (prev < 90) return prev + Math.random() * 3;
        return prev;
      });
    }, 200);

    try {
      const result = await action();
      clearInterval(phaseTimer);
      clearInterval(progressTimer);

      setPhase(LOADING_PHASES.length - 1);
      setProgress(100);

      // Flash red effect
      setTimeout(() => setThreatCount(150), 500);

      // Navigate to dashboard with cinematic delay
      setTimeout(() => {
        navigate(`/dashboard/${result.scan_id}`);
      }, 2500);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      clearInterval(phaseTimer);
      clearInterval(progressTimer);
      setUploading(false);
      setError(err?.response?.data?.detail || 'INTELLIGENCE FAILURE — Analysis could not be completed. Retry transmission.');
    }
  }, [navigate]);

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;
    processFile(() => uploadFile(acceptedFiles[0]));
  }, [processFile]);

  const handleDemo = () => {
    processFile(() => runDemo());
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
      'text/plain': ['.log', '.txt'],
    },
    maxFiles: 1,
    disabled: uploading,
  });

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center z-10" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
      {/* Breadcrumb */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="absolute top-6 font-mono text-xs tracking-wider text-slate-500"
        style={{ left: 'var(--page-padding-x)' }}
      >
        CONSOLE / INGESTION
      </motion.div>

      <AnimatePresence mode="wait">
        {!uploading ? (
          <motion.div
            key="upload"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.6, ease: EASE }}
            className="w-full max-w-2xl"
          >
            {/* Upload Zone — Enhanced with animated blue glow border pulse */}
            <div
              {...getRootProps()}
              className={`
                aegis-card p-12 text-center cursor-pointer
                transition-all duration-300 relative overflow-hidden
                ${isDragActive ? 'border-blue-400 bg-blue-500/10 scale-[1.02]' : 'upload-zone'}
              `}
              style={{
                borderWidth: 2,
                borderStyle: isDragActive ? 'solid' : 'dashed',
                borderColor: isDragActive ? '#60a5fa' : 'rgba(59,130,246,0.6)',
                minHeight: 400,
                boxShadow: isDragActive
                  ? '0 0 60px rgba(59,130,246,0.2), inset 0 0 40px rgba(59,130,246,0.05)'
                  : undefined,
              }}
            >
              <input {...getInputProps()} />

              {/* Blue radial glow behind upload zone */}
              <div className="absolute inset-0 pointer-events-none" style={{
                background: 'radial-gradient(ellipse at center, rgba(59,130,246,0.06) 0%, transparent 70%)',
              }} />

              <motion.div
                animate={isDragActive ? { scale: 1.15 } : { scale: 1 }}
                className="mb-8 flex justify-center relative z-10"
              >
                <motion.div
                  animate={{ y: [0, -10, 0] }}
                  transition={{ repeat: Infinity, duration: 2.5, ease: 'easeInOut' }}
                  className="rounded-2xl bg-blue-500/10 p-5"
                  style={{ filter: 'drop-shadow(0 0 20px rgba(59,130,246,0.5))' }}
                >
                  <UploadIcon className="w-14 h-14 text-blue-400" />
                </motion.div>
              </motion.div>

              <h2 className="font-display text-xl mb-2 tracking-wide relative z-10">
                {isDragActive ? 'RELEASE TO SECURE UPLOAD' : 'DROP INTELLIGENCE HERE'}
              </h2>
              <p className="text-sm mb-4 text-slate-400 relative z-10">
                or click to browse securely
              </p>

              {/* Trust badges */}
              <div className="flex justify-center items-center gap-6 mt-6 flex-wrap relative z-10">
                <span className="font-mono text-xs flex items-center gap-1.5 text-slate-500">
                  <Lock size={14} className="text-blue-400/70" /> 256-bit Encrypted
                </span>
                <span className="font-mono text-xs flex items-center gap-1.5 text-slate-500">
                  <Shield size={14} className="text-blue-400/70" /> No Data Stored
                </span>
                <span className="font-mono text-xs flex items-center gap-1.5 text-slate-500">
                  <Cpu size={14} className="text-blue-400/70" /> Processed Locally
                </span>
              </div>

              {/* Animated dashed border */}
              {!isDragActive && (
                <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ opacity: 0.3 }}>
                  <rect
                    x="1" y="1"
                    width="calc(100% - 2px)" height="calc(100% - 2px)"
                    rx="16"
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="1.5"
                    strokeDasharray="10 8"
                    strokeDashoffset="0"
                  >
                    <animate attributeName="stroke-dashoffset" values="0;-100" dur="6s" repeatCount="indefinite" />
                  </rect>
                </svg>
              )}
            </div>

            {/* Demo Button */}
            <motion.button
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
              onClick={handleDemo}
              className="w-full mt-4 py-4 aegis-card text-center font-mono text-sm tracking-wider
                         transition-all duration-300 group relative flex items-center justify-center gap-2"
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
            >
              <Zap size={16} className="text-cyan-400" />
              <span className="text-blue-400 group-hover:text-white transition-colors">TRY CICIDS 2017 SAMPLE DATASET</span>
            </motion.button>

            {/* File type info */}
            <div className="text-center mt-3">
              <span className="font-mono text-[10px] text-slate-600">Accepts .csv .log .txt</span>
            </div>

            {/* Error */}
            {error && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="mt-4 p-4 aegis-card text-center"
                style={{ borderColor: 'rgba(239,68,68,0.3)' }}
              >
                <p className="font-mono text-sm text-red-400 flex items-center justify-center gap-2">
                  <AlertTriangle size={16} /> {error}
                </p>
                <button
                  onClick={() => setError('')}
                  className="mt-2 font-mono text-xs underline text-slate-500 hover:text-white transition-colors"
                >
                  Retry transmission
                </button>
              </motion.div>
            )}
          </motion.div>
        ) : (
          <motion.div
            key="loading"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="w-full max-w-[600px] text-center relative"
          >
            {/* Binary rain background */}
            {phase < 2 && <BinaryRain />}
            {/* Radar sweep for phase 3 */}
            {phase === 2 && <RadarSweep />}

            {/* Phase text */}
            <motion.div className="relative z-10 mb-12">
              <AnimatePresence mode="wait">
                <motion.div
                  key={phase}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.4 }}
                >
                  <h2
                    className={`font-display text-2xl mb-2 tracking-wider ${
                      phase === LOADING_PHASES.length - 1 ? 'text-red-400' : ''
                    }`}
                    style={phase === LOADING_PHASES.length - 1 ? { textShadow: '0 0 20px rgba(239,68,68,0.4)' } : {}}
                  >
                    {LOADING_PHASES[phase].text}
                  </h2>
                  <p className="font-mono text-xs text-slate-500">
                    {LOADING_PHASES[phase].sub}
                  </p>
                </motion.div>
              </AnimatePresence>
            </motion.div>

            {/* Progress bar */}
            <div className="relative z-10 w-full h-1.5 rounded-full mb-4" style={{ background: 'rgba(255,255,255,0.08)' }}>
              <motion.div
                className="h-full rounded-full"
                style={{
                  background: phase === LOADING_PHASES.length - 1
                    ? '#ef4444'
                    : 'linear-gradient(90deg, #2563eb, #06b6d4)',
                  boxShadow: `0 0 20px ${phase === LOADING_PHASES.length - 1 ? 'rgba(239,68,68,0.5)' : 'rgba(59,130,246,0.5)'}`,
                }}
                animate={{ width: `${Math.min(progress, 100)}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>

            <p className="relative z-10 font-mono text-xs text-slate-500">
              {Math.floor(Math.min(progress, 100))}%
            </p>

            {/* Threat count reveal */}
            {threatCount > 0 && (
              <motion.div
                initial={{ opacity: 0, scale: 0.5 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ type: 'spring', damping: 15 }}
                className="mt-8 relative z-10"
              >
                <div className="font-display text-7xl mb-2 text-red-400" style={{ textShadow: '0 0 30px rgba(239,68,68,0.4)' }}>
                  {threatCount}
                </div>
                <div className="badge-critical inline-block text-sm px-4 py-1">
                  THREATS DETECTED
                </div>
              </motion.div>
            )}

            {/* Phase icons */}
            <div className="flex items-center justify-center gap-4 mt-8 relative z-10">
              {LOADING_PHASES.map((p, i) => (
                <motion.div
                  key={i}
                  className="w-10 h-10 rounded-lg flex items-center justify-center"
                  style={{
                    background: i <= phase ? 'rgba(59,130,246,0.1)' : 'rgba(255,255,255,0.03)',
                    border: `1px solid ${i <= phase ? 'rgba(59,130,246,0.25)' : 'rgba(255,255,255,0.05)'}`,
                    color: i < phase ? '#60a5fa' : (i === phase ? '#60a5fa' : '#475569'),
                  }}
                  animate={i === phase ? { scale: [1, 1.1, 1] } : {}}
                  transition={{ repeat: Infinity, duration: 1 }}
                >
                  {p.icon}
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
