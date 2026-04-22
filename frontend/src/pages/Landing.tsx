import React, { useEffect, useRef, useState, Suspense, lazy, ErrorInfo, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, useScroll, useTransform } from 'framer-motion';
import {
  Brain, Target, Sparkles, Globe, LayoutDashboard, FileText,
  UploadCloud, Activity, Zap, ShieldCheck, AlertTriangle
} from 'lucide-react';

const HolographicShield = lazy(() => import('../components/HolographicShield'));

const EASE = [0.16, 1, 0.3, 1] as const;

/* ===== Fallback components for 3D shield ===== */
function StaticShieldFallback() {
  return (
    <div className="flex items-center justify-center w-full h-full">
      <svg viewBox="0 0 100 120" className="w-48 h-48 drop-shadow-[0_0_15px_rgba(6,182,212,0.6)]">
        <path d="M50 5 L90 25 L90 60 C90 90 50 115 50 115 C50 115 10 90 10 60 L10 25 Z" fill="none" stroke="#3b82f6" strokeWidth="2" />
        <path d="M50 15 L80 30 L80 60 C80 85 50 105 50 105 C50 105 20 85 20 60 L20 30 Z" fill="rgba(6,182,212,0.1)" stroke="#06b6d4" strokeWidth="1" strokeDasharray="4 2" />
      </svg>
    </div>
  );
}

class ShieldErrorBoundary extends React.Component<{ children: ReactNode, fallback: ReactNode }, { hasError: boolean }> {
  constructor(props: { children: ReactNode, fallback: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() { return { hasError: true }; }
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("HolographicShield error caught:", error, errorInfo);
  }
  render() {
    if (this.state.hasError) return this.props.fallback;
    return this.props.children;
  }
}

/* ===== Animated counter (CHANGE-16) ===== */
function AnimatedCounter({ target, suffix = '', duration = 1500 }: { target: number; suffix?: string; duration?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const countRef = useRef(0);
  const [display, setDisplay] = useState(0);
  const started = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true;
        const startTime = performance.now();
        const animate = (now: number) => {
          const elapsed = now - startTime;
          const progress = Math.min(elapsed / duration, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          countRef.current = Math.round(eased * target * 100) / 100;
          if (progress < 1) {
            requestAnimationFrame(animate);
          } else {
            countRef.current = target;
          }
          setDisplay(countRef.current);
        };
        requestAnimationFrame(animate);
      }
    }, { threshold: 0.3 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [target, duration]);

  return <span ref={ref}>{Number.isInteger(target) ? Math.floor(display) : display.toFixed(2)}{suffix}</span>;
}

/* ===== Typewriter text (CHANGE-19) ===== */
function TypewriterText({ text, delay = 0, speed = 80 }: { text: string; delay?: number; speed?: number }) {
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
    }, speed);
    return () => clearInterval(timer);
  }, [started, text, speed]);

  return (
    <span>
      {displayed}
      {displayed.length < text.length && <span className="typewriter-cursor" />}
    </span>
  );
}

/* ===== Terminal log ===== */
const LOG_DATA = [
  { text: '2026-04-02 02:31:45 TCP 185.220.101.42:4822 → 10.0.0.1:22 SYN', type: 'normal' },
  { text: '2026-04-02 02:31:46 TCP 185.220.101.42:4822 → 10.0.0.1:22 SYN ACK', type: 'normal' },
  { text: '2026-04-02 02:31:47 TCP 185.220.101.42:4823 → 10.0.0.1:22 AUTH FAILED', type: 'danger' },
  { text: '2026-04-02 02:31:48 TCP 185.220.101.42:4824 → 10.0.0.1:22 AUTH FAILED', type: 'danger' },
  { text: '2026-04-02 02:32:01 UDP 10.0.0.5:53 → 8.8.8.8:53 DNS QUERY', type: 'normal' },
  { text: '2026-04-02 02:32:15 TCP 10.0.0.12:443 → 142.250.80.46:443 TLS OK', type: 'safe' },
  { text: '2026-04-02 02:32:44 TCP 103.75.190.11:8080 → 10.0.0.1:445 SMB SCAN', type: 'danger' },
  { text: '2026-04-02 02:33:01 TCP 10.0.0.25:80 → 198.51.100.1:80 HTTP 200', type: 'normal' },
  { text: '2026-04-02 02:33:22 TCP 91.219.236.222:6667 → 10.0.0.5:4444 REVERSE SHELL', type: 'critical' },
  { text: '2026-04-02 02:34:05 TCP 10.0.0.1:22 → 185.220.101.42:4830 DATA 4.7GB', type: 'critical' },
  { text: '2026-04-02 02:34:33 UDP 10.0.0.12:123 → 129.6.15.28:123 NTP SYNC', type: 'normal' },
  { text: '2026-04-02 02:35:01 TCP 5.188.86.172:9001 → 10.0.0.25:3389 RDP BRUTE', type: 'danger' },
  { text: '2026-04-02 02:35:44 TCP 10.0.0.100:443 → 151.101.1.140:443 TLS OK', type: 'safe' },
  { text: '2026-04-02 02:36:12 TCP 218.92.0.107:55123 → 10.0.0.1:80 HTTP FLOOD', type: 'critical' },
];

function TerminalLog() {
  const [visibleLogs, setVisibleLogs] = useState<typeof LOG_DATA>([]);

  useEffect(() => {
    let i = 0;
    const timer = setInterval(() => {
      setVisibleLogs(prev => {
        const next = [...prev, LOG_DATA[i % LOG_DATA.length]];
        if (next.length > 12) next.shift();
        return next;
      });
      i++;
    }, 800);
    return () => clearInterval(timer);
  }, []);

  const getColor = (type: string) => {
    switch (type) {
      case 'critical': return '#ef4444';
      case 'danger': return '#f59e0b';
      case 'safe': return '#10b981';
      default: return '#64748b';
    }
  };

  return (
    <div className="aegis-card p-4 overflow-hidden h-[320px]" style={{ background: 'rgba(0,0,0,0.6)' }}>
      <div className="flex items-center gap-2 mb-3 pb-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <div className="w-3 h-3 rounded-full" style={{ background: '#ef4444' }} />
        <div className="w-3 h-3 rounded-full" style={{ background: '#f59e0b' }} />
        <div className="w-3 h-3 rounded-full" style={{ background: '#10b981' }} />
        <span className="font-mono text-xs ml-2 text-slate-500">aegis-terminal — live-feed</span>
      </div>
      <div className="space-y-1 overflow-hidden">
        {visibleLogs.map((log, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className="font-mono text-xs leading-5"
            style={{ color: getColor(log.type) }}
          >
            {log.type === 'critical' && <AlertTriangleIcon />}{log.text}
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function AlertTriangleIcon() {
  return <AlertTriangle size={12} className="inline-block mr-1 text-slate-400" />;
}

/* ===== MAIN LANDING ===== */
export default function Landing() {
  const navigate = useNavigate();
  const { scrollYProgress } = useScroll();
  const heroOpacity = useTransform(scrollYProgress, [0, 0.15], [1, 0]);

  const features = [
    { title: 'AI Anomaly Detection', desc: 'Isolation Forest ML identifies hidden threats in millions of log entries', icon: <Brain size={24} /> },
    { title: 'MITRE ATT&CK Mapping', desc: 'Every threat auto-classified with official technique codes and tactics', icon: <Target size={24} /> },
    { title: 'Gemini AI Explanations', desc: 'Plain-language intelligence briefs for every detected threat event', icon: <Sparkles size={24} /> },
    { title: 'IP Geolocation Tracking', desc: 'Trace every attacker to their origin — country, city, ISP', icon: <Globe size={24} /> },
    { title: 'Visual Command Dashboard', desc: 'Real-time threat visualization: gauges, timelines, world maps', icon: <LayoutDashboard size={24} /> },
    { title: 'PDF Incident Report', desc: 'Military-grade branded AEGIS report — ready for command review', icon: <FileText size={24} /> },
  ];

  const steps = [
    { num: '01', title: 'INGEST', desc: 'Upload any log file — CSV, raw text, CICIDS format', icon: <UploadCloud size={32} className="text-blue-400" /> },
    { num: '02', title: 'ANALYZE', desc: 'Isolation Forest + feature extraction identifies anomalies', icon: <Activity size={32} className="text-blue-400" /> },
    { num: '03', title: 'CLASSIFY', desc: 'MITRE ATT&CK mapping with AI-powered explanations', icon: <Zap size={32} className="text-slate-400" /> },
    { num: '04', title: 'BRIEF', desc: 'Full incident report with Commander\'s Brief generated', icon: <ShieldCheck size={32} className="text-slate-400" /> },
  ];

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="relative"
    >

      {/* ===== HERO SECTION ===== */}
      <motion.section
        style={{ opacity: heroOpacity, paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}
        className="relative min-h-screen flex items-center z-10 overflow-hidden"
      >
        <div className="max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          {/* Left Content */}
          <div className="max-w-xl">
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3, duration: 0.8 }}
              className="section-label section-label-blue mb-6"
            >
              CLASSIFIED // THREAT INTELLIGENCE PLATFORM
            </motion.p>

            <motion.h1
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.8, duration: 0.5 }}
              className="font-display text-[80px] lg:text-[96px] leading-none tracking-tight mb-4"
              style={{ letterSpacing: '-0.02em', fontWeight: 800 }}
            >
              <TypewriterText text="AEGIS" delay={800} speed={100} />
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.4, duration: 0.8, ease: EASE }}
              className="text-2xl mb-6 italic"
              style={{ color: '#94a3b8', fontFamily: "'Playfair Display', Georgia, serif" }}
            >
              Intelligence, Redefined.
            </motion.p>

            <motion.p
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.6, duration: 0.8, ease: EASE }}
              className="text-base leading-relaxed mb-8 max-w-[60ch]"
              style={{ color: '#94a3b8' }}
            >
              Upload a log file. Let AI decode every threat. Receive a military-grade
              incident report in seconds, not hours.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.8, duration: 0.8, ease: EASE }}
              className="flex flex-col sm:flex-row items-start gap-4"
            >
              <button
                onClick={() => navigate('/upload')}
                className="cta-button"
                aria-label="Initiate threat scan"
              >
                INITIATE SCAN
                <motion.span animate={{ x: [0, 4, 0] }} transition={{ repeat: Infinity, duration: 1.5 }}>→</motion.span>
              </button>
              <a
                href="#how-it-works"
                className="font-mono text-xs tracking-wider pt-4 transition-colors hover:text-white text-slate-500"
              >
                View the protocol →
              </a>
            </motion.div>
          </div>

          {/* Right — 3D Shield */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.5, duration: 1.5, ease: EASE }}
            className="hidden lg:flex items-center justify-center relative h-[600px]"
          >
            <ShieldErrorBoundary fallback={<StaticShieldFallback />}>
              <Suspense fallback={
                <div className="w-32 h-32 rounded-full border-2 border-blue-500/10 animate-pulse" style={{ background: 'rgba(10,15,30,0.5)' }} />
              }>
                <HolographicShield />
              </Suspense>
            </ShieldErrorBoundary>
          </motion.div>
        </div>
      </motion.section>

      {/* ===== SECTION 2: THE PROBLEM ===== */}
      <section className="relative flex items-center z-10 min-h-screen py-32 md:py-40" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        <div className="max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-5 gap-16 items-center">
          <div className="lg:col-span-3">
            <motion.p
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.7, ease: EASE }}
              className="section-label section-label-red mb-4"
            >
              THE THREAT
            </motion.p>

            <motion.h2
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.7, delay: 0.1, ease: EASE }}
              className="font-display text-4xl lg:text-5xl leading-tight mb-6"
            >
              500,000 LOG LINES.<br />ONE ANALYST.<br />ZERO CHANCE.
            </motion.h2>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.7, delay: 0.2, ease: EASE }}
              className="text-base leading-relaxed mb-10 max-w-[55ch] text-slate-400"
            >
              Defence networks generate millions of log entries daily. Hidden inside: brute force attacks,
              data exfiltration, reconnaissance probes. Manual analysis takes 8 hours.
              By then, the damage is done.
            </motion.p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
              {[
                { value: 8, suffix: '+ HRS', label: 'Manual Review' },
                { value: 67, suffix: '%', label: 'Threats Missed' },
                { value: 4.45, suffix: 'M', label: 'Avg Breach Cost', prefix: '$' },
              ].map((stat, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: '-80px' }}
                  transition={{ duration: 0.5, delay: 0.3 + i * 0.1, ease: EASE }}
                  className="aegis-card p-5 text-center"
                >
                  <div className="font-display text-3xl text-white mb-1">
                    {stat.prefix || ''}<AnimatedCounter target={stat.value} suffix={stat.suffix} />
                  </div>
                  <div className="font-mono text-xs text-slate-500">{stat.label}</div>
                </motion.div>
              ))}
            </div>
          </div>

          <motion.div
            className="lg:col-span-2"
            initial={{ opacity: 0, x: 30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: '-80px' }}
            transition={{ duration: 0.8, delay: 0.3, ease: EASE }}
          >
            <TerminalLog />
          </motion.div>
        </div>
      </section>

      {/* ===== SECTION 3: THE SOLUTION ===== */}
      <section id="how-it-works" className="relative flex items-center z-10 min-h-screen py-32 md:py-40" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        <div className="max-w-7xl mx-auto w-full">
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, margin: '-80px' }}
            className="section-label section-label-blue mb-4 text-center border-l-0"
            transition={{ duration: 0.7, ease: EASE }}
          >
            THE SOLUTION
          </motion.p>

          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-80px' }}
            transition={{ duration: 0.7, ease: EASE }}
            className="font-display text-4xl lg:text-5xl text-center mb-16"
          >
            UPLOAD. DETECT. REPORT.<br />
            <span className="text-gradient">In 12 Seconds.</span>
          </motion.h2>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 relative">
            {/* Animated dashed connector arrows between steps */}
            <svg className="hidden md:block absolute inset-0 w-full h-full pointer-events-none z-0" style={{ width: '100%', height: '100%' }}>
              <defs>
                <linearGradient id="connectorGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="rgba(59,130,246,0.1)" />
                  <stop offset="50%" stopColor="rgba(59,130,246,0.4)" />
                  <stop offset="100%" stopColor="rgba(59,130,246,0.1)" />
                </linearGradient>
              </defs>
              {/* Connector line 1 → 2 */}
              <line x1="25%" y1="50%" x2="75%" y2="50%" stroke="url(#connectorGradient)" strokeWidth="2" strokeDasharray="8 4" className="step-connector" />
              {/* Connector line 2 → 3 */}
              <line x1="25%" y1="50%" x2="75%" y2="50%" stroke="url(#connectorGradient)" strokeWidth="2" strokeDasharray="8 4" className="step-connector" style={{ animationDelay: '0.3s' }} />
              {/* Connector line 3 → 4 */}
              <line x1="25%" y1="50%" x2="75%" y2="50%" stroke="url(#connectorGradient)" strokeWidth="2" strokeDasharray="8 4" className="step-connector" style={{ animationDelay: '0.6s' }} />
              {/* Arrow heads */}
              <polygon points="75,45 82,50 75,55" fill="rgba(59,130,246,0.5)" />
              <polygon points="75,45 82,50 75,55" fill="rgba(59,130,246,0.5)" style={{ transform: 'translateX(25%)' }} />
              <polygon points="75,45 82,50 75,55" fill="rgba(59,130,246,0.5)" style={{ transform: 'translateX(50%)' }} />
            </svg>

            {steps.map((step, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 40 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-80px' }}
                transition={{ duration: 0.5, delay: i * 0.15, ease: EASE }}
                className="aegis-card relative z-10 text-center"
              >
                <div className="font-mono text-xs mb-3 text-slate-500">{step.num}</div>
                <div className="mb-3 flex justify-center">{step.icon}</div>
                <h3 className="font-display text-lg mb-2">{step.title}</h3>
                <p className="text-sm text-slate-400">{step.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ===== SECTION 4: FEATURES BENTO ===== */}
      <section className="relative z-10 min-h-screen py-32 md:py-40 flex items-center" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        <div className="max-w-7xl mx-auto">
          <motion.p
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            className="section-label section-label-cyan mb-4 text-center border-l-0"
            transition={{ duration: 0.7, ease: EASE }}
          >
            CAPABILITIES
          </motion.p>

          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, ease: EASE }}
            className="font-display text-4xl text-center mb-16"
          >
            FULL SPECTRUM INTELLIGENCE
          </motion.h2>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feat, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, scale: 0.95 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true, margin: '-50px' }}
                transition={{ duration: 0.5, delay: i * 0.08, ease: EASE }}
                className="aegis-card group"
              >
                <motion.div
                  className="mb-4 w-12 h-12 rounded-lg flex items-center justify-center text-blue-400"
                  style={{ background: 'rgba(59, 130, 246, 0.1)' }}
                  animate={{ y: [0, -4, 0] }}
                  transition={{ repeat: Infinity, duration: 3, delay: i * 0.3 }}
                >
                  {feat.icon}
                </motion.div>
                <h3 className="font-display text-base mb-2 tracking-wide">{feat.title}</h3>
                <p className="text-sm text-slate-400">{feat.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ===== SECTION 5: STATS BAR ===== */}
      <section className="relative z-10 py-20 overflow-hidden" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        {/* Radial glow behind cards */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="w-[800px] h-[400px] rounded-full" style={{ background: 'radial-gradient(ellipse at center, rgba(59,130,246,0.08) 0%, rgba(6,182,212,0.04) 40%, transparent 70%)' }} />
        </div>
        <div className="max-w-7xl mx-auto w-full relative">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
            {[
              { stat: '3.4 billion', desc: 'attacks detected daily worldwide' },
              { stat: '287 days', desc: 'average breach discovery time' },
              { stat: '12 seconds', desc: 'AEGIS detection time' },
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 40 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.7, delay: i * 0.15, ease: EASE }}
                className="text-center py-12 px-6 aegis-card"
              >
                <div className="text-3xl lg:text-4xl mb-3 text-white italic" style={{ fontFamily: "'Playfair Display', serif" }}>{item.stat}</div>
                <div className="font-mono text-xs tracking-wider text-slate-500">{item.desc}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ===== SECTION 6: FINAL CTA ===== */}
      <section className="relative min-h-[80vh] flex items-center justify-center z-10" style={{ paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        {/* Radar sweep background */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <motion.div
            className="w-[600px] h-[600px] rounded-full"
            style={{ background: 'conic-gradient(from 0deg, transparent, rgba(59,130,246,0.08), transparent)' }}
            animate={{ rotate: 360 }}
            transition={{ repeat: Infinity, duration: 10, ease: 'linear' }}
          />
        </div>

        <div className="text-center relative z-10">
          <motion.h2
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, ease: EASE }}
            className="font-display text-5xl lg:text-7xl xl:text-[96px] mb-8 leading-none"
          >
            YOU HAVE<br />CLEARANCE
          </motion.h2>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, delay: 0.3, ease: EASE }}
          >
            <button
              onClick={() => navigate('/upload')}
              className="cta-button text-lg px-10 py-5 report-btn-glow"
              style={{ borderColor: 'rgba(239,68,68,0.4)' }}
              aria-label="Enter AEGIS platform"
            >
              ENTER AEGIS
              <motion.span animate={{ x: [0, 4, 0] }} transition={{ repeat: Infinity, duration: 1.5 }}>→</motion.span>
            </button>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 py-8 text-center border-t" style={{ borderColor: 'rgba(255,255,255,0.06)', paddingLeft: 'var(--page-padding-x)', paddingRight: 'var(--page-padding-x)' }}>
        <p className="font-mono text-xs text-slate-500">
          AEGIS v2.1 · Advanced Engine for Guided Intelligence & Surveillance · CODE CLASH 2026
        </p>
      </footer>
    </motion.div>
  );
}
