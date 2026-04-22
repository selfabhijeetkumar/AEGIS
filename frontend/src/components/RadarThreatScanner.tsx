import { useRef, useEffect, useMemo } from 'react';
import type { ThreatEvent } from '../services/api';

interface RadarThreatScannerProps {
  threats: ThreatEvent[];
  threatScore: number;
  overallSeverity: string;
}

interface ThreatDot {
  angle: number;
  distance: number;
  severity: 'CRITICAL' | 'MEDIUM' | 'LOW';
  radius: number;
  color: string;
  glowColor: string;
  pulseSpeed: number;
  lastFlash: number;
}

const SEVERITY_CONFIG = {
  CRITICAL: {
    color: '#ef4444',
    glowColor: 'rgba(239,68,68,0.8)',
    radius: 4,
    distRange: [0.70, 0.95],
    pulseSpeed: 1.5,
  },
  MEDIUM: {
    color: '#f59e0b',
    glowColor: 'rgba(245,158,11,0.6)',
    radius: 3,
    distRange: [0.40, 0.70],
    pulseSpeed: 2.5,
  },
  LOW: {
    color: '#10b981',
    glowColor: 'rgba(16,185,129,0.4)',
    radius: 2,
    distRange: [0.20, 0.45],
    pulseSpeed: 0,
  },
};

function seededRandom(seed: number) {
  const x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

export default function RadarThreatScanner({ threats, threatScore, overallSeverity }: RadarThreatScannerProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const containerRef = useRef<HTMLDivElement>(null);

  const scoreColor = threatScore >= 66 ? '#ef4444' : threatScore >= 31 ? '#f59e0b' : '#10b981';
  const severityLabel = overallSeverity || (threatScore >= 66 ? 'CRITICAL' : threatScore >= 31 ? 'MEDIUM' : 'LOW');

  // Generate fixed dot positions from threat data
  const dots: ThreatDot[] = useMemo(() => {
    return threats.map((t, i) => {
      const cfg = SEVERITY_CONFIG[t.severity] || SEVERITY_CONFIG.LOW;
      const angle = seededRandom(t.id * 7 + i * 13) * Math.PI * 2;
      const dist = cfg.distRange[0] + seededRandom(t.id * 11 + i * 17) * (cfg.distRange[1] - cfg.distRange[0]);
      return {
        angle,
        distance: dist,
        severity: t.severity,
        radius: cfg.radius,
        color: cfg.color,
        glowColor: cfg.glowColor,
        pulseSpeed: cfg.pulseSpeed,
        lastFlash: 0,
      };
    });
  }, [threats]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = 0;
    let height = 0;

    const resize = () => {
      const rect = container.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      width = rect.width;
      height = rect.height;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const ro = new ResizeObserver(resize);
    ro.observe(container);
    resize();

    const SWEEP_DURATION = 2000; // ms per rotation
    const SWEEP_ARC = (60 * Math.PI) / 180; // 60 degrees in radians
    const FLASH_DURATION = 300;

    const draw = (time: number) => {
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;
      const maxRadius = Math.min(cx, cy) - 16;

      // --- Background ---
      ctx.fillStyle = '#0a0f1e';
      ctx.fillRect(0, 0, width, height);

      // --- Concentric grid rings at 25%, 50%, 75%, 100% ---
      for (const pct of [0.25, 0.5, 0.75, 1.0]) {
        const r = maxRadius * pct;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(6,182,212,0.15)';
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }

      // --- Crosshair lines ---
      ctx.strokeStyle = 'rgba(6,182,212,0.1)';
      ctx.lineWidth = 0.5;
      ctx.beginPath();
      ctx.moveTo(cx - maxRadius, cy);
      ctx.lineTo(cx + maxRadius, cy);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(cx, cy - maxRadius);
      ctx.lineTo(cx, cy + maxRadius);
      ctx.stroke();

      // --- Polar grid lines every 30 degrees ---
      for (let deg = 0; deg < 360; deg += 30) {
        if (deg % 90 === 0) continue; // skip crosshair lines already drawn
        const rad = (deg * Math.PI) / 180;
        ctx.strokeStyle = 'rgba(6,182,212,0.08)';
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + maxRadius * Math.cos(rad), cy + maxRadius * Math.sin(rad));
        ctx.stroke();
      }

      // --- Outer ring with glow ---
      ctx.save();
      ctx.shadowColor = 'rgba(30,58,95,0.6)';
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.arc(cx, cy, maxRadius, 0, Math.PI * 2);
      ctx.strokeStyle = '#1e3a5f';
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.restore();

      // --- Rotating sweep ---
      const sweepAngle = ((time % SWEEP_DURATION) / SWEEP_DURATION) * Math.PI * 2 - Math.PI / 2;

      // Draw filled conic sector (gradient from leading edge)
      const steps = 30;
      for (let i = 0; i < steps; i++) {
        const frac = i / steps;
        const a0 = sweepAngle - SWEEP_ARC * frac;
        const a1 = sweepAngle - SWEEP_ARC * ((i + 1) / steps);
        const alpha = 0.6 * (1 - frac); // fades from 0.6 to 0
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, maxRadius, a0, a1, true);
        ctx.closePath();
        ctx.fillStyle = `rgba(30,58,95,${alpha})`;
        ctx.fill();
      }

      // Bright leading edge line
      ctx.save();
      ctx.shadowColor = 'rgba(30,58,95,0.8)';
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + maxRadius * Math.cos(sweepAngle), cy + maxRadius * Math.sin(sweepAngle));
      ctx.strokeStyle = 'rgba(30,58,95,0.9)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.restore();

      // --- Threat dots ---
      for (const dot of dots) {
        const dx = cx + Math.cos(dot.angle) * dot.distance * maxRadius;
        const dy = cy + Math.sin(dot.angle) * dot.distance * maxRadius;

        // Check if sweep just passed over this dot
        const dotAngleN = ((dot.angle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
        const sweepN = ((sweepAngle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
        let diff = sweepN - dotAngleN;
        if (diff < 0) diff += Math.PI * 2;
        if (diff < 0.15) {
          dot.lastFlash = time;
        }

        const timeSinceFlash = time - dot.lastFlash;
        const isFlashing = timeSinceFlash < FLASH_DURATION && dot.lastFlash > 0;
        const flashIntensity = isFlashing ? 1 - timeSinceFlash / FLASH_DURATION : 0;

        // Pulse effect for critical/medium
        let pulseScale = 1;
        if (dot.pulseSpeed > 0) {
          pulseScale = 1 + 0.3 * Math.sin(time / 1000 * dot.pulseSpeed * Math.PI);
        }

        // Glow
        const glowSize = (8 + 4 * pulseScale + flashIntensity * 8);
        ctx.save();
        ctx.shadowColor = dot.glowColor;
        ctx.shadowBlur = glowSize;
        ctx.beginPath();
        ctx.arc(dx, dy, dot.radius * (1 + flashIntensity * 0.5), 0, Math.PI * 2);
        ctx.fillStyle = isFlashing
          ? '#ffffff'
          : dot.color;
        ctx.fill();
        ctx.restore();

        // Core dot
        ctx.beginPath();
        ctx.arc(dx, dy, dot.radius * 0.6, 0, Math.PI * 2);
        ctx.fillStyle = isFlashing ? '#ffffff' : dot.color;
        ctx.globalAlpha = 0.9;
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // --- Center display ---
      // Score number
      ctx.font = "800 48px 'Inter', sans-serif";
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.save();
      ctx.shadowColor = `${scoreColor}40`;
      ctx.shadowBlur = 20;
      ctx.fillStyle = scoreColor;
      ctx.fillText(String(threatScore), cx, cy - 12);
      ctx.restore();

      // Severity label
      ctx.font = "600 11px 'JetBrains Mono', monospace";
      ctx.letterSpacing = '0.15em';
      ctx.fillStyle = scoreColor;
      ctx.fillText(severityLabel, cx, cy + 20);

      // "THREATS DETECTED" subtext
      ctx.font = "400 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = '#64748b';
      ctx.fillText('THREATS DETECTED', cx, cy + 36);

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animRef.current);
      ro.disconnect();
    };
  }, [dots, threats.length, threatScore, scoreColor, severityLabel]);

  return (
    <div className="flex flex-col items-center w-full h-full">
      {/* Header label */}
      <div className="flex items-center gap-2 mb-3">
        <div
          className="w-2 h-2 rounded-full"
          style={{
            background: '#10b981',
            boxShadow: '0 0 6px rgba(16,185,129,0.8)',
            animation: 'pulse 2s ease-in-out infinite',
          }}
        />
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          letterSpacing: '0.15em',
          color: '#22d3ee',
        }}>
          THREAT RADAR — ACTIVE SCAN
        </span>
      </div>

      {/* Canvas container */}
      <div
        ref={containerRef}
        className="relative w-full"
        style={{ aspectRatio: '1 / 1', maxWidth: 280, maxHeight: 280 }}
      >
        <canvas
          ref={canvasRef}
          className="absolute inset-0 rounded-full"
          style={{ width: '100%', height: '100%' }}
        />
      </div>
    </div>
  );
}
