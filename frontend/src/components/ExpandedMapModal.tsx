import { useEffect, useRef, useState, useCallback } from 'react';
import { ShieldAlert, X } from 'lucide-react';
import type { ThreatEvent } from '../services/api';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const GEOJSON_URL = 'https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson';

interface AttackerMarker extends ThreatEvent {
  count: number;
}

interface ExpandedMapModalProps {
  attackerMarkers: AttackerMarker[];
  onClose: () => void;
}

// Mercator projection: lon/lat → canvas x/y
function projectX(lon: number, width: number): number {
  return (lon + 180) * (width / 360);
}

function projectY(lat: number, height: number): number {
  return (90 - lat) * (height / 180);
}

interface TooltipData {
  x: number;
  y: number;
  marker: AttackerMarker;
}

export default function ExpandedMapModal({ attackerMarkers, onClose }: ExpandedMapModalProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const geoDataRef = useRef<any>(null);
  const animFrameRef = useRef<number>(0);
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);
  const markersScreenRef = useRef<{ x: number; y: number; r: number; marker: AttackerMarker }[]>([]);

  // Escape key closes the modal
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  // Fetch GeoJSON
  useEffect(() => {
    fetch(GEOJSON_URL)
      .then(r => r.json())
      .then(data => {
        geoDataRef.current = data;
      })
      .catch(() => {
        // Silently fail — map will render without country outlines
      });
  }, []);

  // Main canvas render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let startTime = performance.now();

    const render = (now: number) => {
      const elapsed = now - startTime;
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      const w = rect.width;
      const h = rect.height;

      // Set canvas resolution
      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }

      // Clear with background
      ctx.fillStyle = '#0a0f1e';
      ctx.fillRect(0, 0, w, h);

      // Draw countries if GeoJSON loaded
      const geo = geoDataRef.current;
      if (geo && geo.features) {
        ctx.fillStyle = '#1e293b';
        ctx.strokeStyle = '#334155';
        ctx.lineWidth = 0.5;

        for (const feature of geo.features) {
          const geom = feature.geometry;
          if (!geom) continue;
          const type = geom.type;
          const coords = geom.coordinates;

          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const drawPolygon = (rings: any[]) => {
            for (const ring of rings) {
              if (!ring || ring.length === 0) continue;
              ctx.beginPath();
              for (let j = 0; j < ring.length; j++) {
                const px = projectX(ring[j][0], w);
                const py = projectY(ring[j][1], h);
                if (j === 0) ctx.moveTo(px, py);
                else ctx.lineTo(px, py);
              }
              ctx.closePath();
              ctx.fill();
              ctx.stroke();
            }
          };

          if (type === 'Polygon') {
            drawPolygon(coords);
          } else if (type === 'MultiPolygon') {
            for (const polygon of coords) {
              drawPolygon(polygon);
            }
          }
        }
      }

      // Draw grid lines
      ctx.strokeStyle = 'rgba(51, 65, 85, 0.15)';
      ctx.lineWidth = 0.5;
      for (let lon = -180; lon <= 180; lon += 30) {
        const x = projectX(lon, w);
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let lat = -90; lat <= 90; lat += 30) {
        const y = projectY(lat, h);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      // Draw attacker markers with pulse animation
      const pulsePhase = (elapsed % 2000) / 2000; // 0 to 1 over 2 seconds
      const screenMarkers: { x: number; y: number; r: number; marker: AttackerMarker }[] = [];

      for (const m of attackerMarkers) {
        const color = SEVERITY_COLORS[m.severity] || '#ef4444';
        const baseRadius = m.severity === 'CRITICAL' ? 8 : m.severity === 'MEDIUM' ? 6 : 5;
        const cx = projectX(m.lon, w);
        const cy = projectY(m.lat, h);

        screenMarkers.push({ x: cx, y: cy, r: baseRadius + 6, marker: m });

        // Outer pulsing ring
        const pulseRadius = baseRadius + pulsePhase * 8;
        const pulseOpacity = 1 - pulsePhase;
        ctx.beginPath();
        ctx.arc(cx, cy, pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.globalAlpha = pulseOpacity * 0.6;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Second pulse ring (offset phase)
        const phase2 = ((elapsed + 800) % 2000) / 2000;
        const pulseRadius2 = baseRadius + phase2 * 8;
        const pulseOpacity2 = 1 - phase2;
        ctx.beginPath();
        ctx.arc(cx, cy, pulseRadius2, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        ctx.globalAlpha = pulseOpacity2 * 0.3;
        ctx.stroke();
        ctx.globalAlpha = 1;

        // Glow shadow
        ctx.save();
        ctx.shadowColor = color;
        ctx.shadowBlur = 12;

        // Filled circle
        ctx.beginPath();
        ctx.arc(cx, cy, baseRadius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.restore();

        // White center dot
        ctx.beginPath();
        ctx.arc(cx, cy, 2, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255,255,255,0.7)';
        ctx.fill();
      }

      markersScreenRef.current = screenMarkers;

      animFrameRef.current = requestAnimationFrame(render);
    };

    startTime = performance.now();
    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animFrameRef.current);
    };
  }, [attackerMarkers]);

  // Mouse move handler for tooltips
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    for (const sm of markersScreenRef.current) {
      const dx = mx - sm.x;
      const dy = my - sm.y;
      if (dx * dx + dy * dy <= sm.r * sm.r) {
        setTooltip({ x: e.clientX, y: e.clientY, marker: sm.marker });
        return;
      }
    }
    setTooltip(null);
  }, []);

  const handleMouseLeave = useCallback(() => {
    setTooltip(null);
  }, []);

  const criticalCount = attackerMarkers.filter(m => m.severity === 'CRITICAL').length;
  const mediumCount = attackerMarkers.filter(m => m.severity === 'MEDIUM').length;
  const lowCount = attackerMarkers.filter(m => m.severity === 'LOW').length;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        zIndex: 9999,
        background: 'rgba(0,0,0,0.95)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Header bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 24px',
          background: '#000000',
          borderBottom: '1px solid rgba(255,255,255,0.08)',
          flexShrink: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={18} style={{ color: '#06b6d4' }} />
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              letterSpacing: '0.15em',
              textTransform: 'uppercase',
              color: '#06b6d4',
            }}
          >
            IP GEOLOCATION — ATTACKER ORIGINS
          </span>
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              padding: '2px 8px',
              borderRadius: 999,
              background: 'rgba(239,68,68,0.15)',
              color: '#ef4444',
              border: '1px solid rgba(239,68,68,0.3)',
            }}
          >
            {attackerMarkers.length} ORIGINS
          </span>
        </div>
        <button
          onClick={onClose}
          aria-label="Close expanded map"
          style={{
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            color: '#ffffff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 6,
            borderRadius: 6,
            transition: 'color 0.2s ease',
          }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.color = '#ef4444'; }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.color = '#ffffff'; }}
        >
          <X size={22} />
        </button>
      </div>

      {/* Canvas map area */}
      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        <canvas
          ref={canvasRef}
          style={{ width: '100%', height: '85vh', display: 'block', cursor: tooltip ? 'pointer' : 'crosshair' }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        />

        {/* Tooltip */}
        {tooltip && (
          <div
            style={{
              position: 'fixed',
              left: tooltip.x + 16,
              top: tooltip.y - 10,
              zIndex: 10002,
              background: 'rgba(10,15,30,0.95)',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 10,
              padding: '12px 16px',
              pointerEvents: 'none',
              backdropFilter: 'blur(16px)',
              boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
              minWidth: 200,
            }}
          >
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 13,
                color: '#22d3ee',
                marginBottom: 4,
                fontWeight: 600,
              }}
            >
              {tooltip.marker.source_ip}
            </div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#f8fafc', marginBottom: 4 }}>
              {tooltip.marker.country}
            </div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>
              {tooltip.marker.threat_type}
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: 999,
                  background: `${SEVERITY_COLORS[tooltip.marker.severity]}25`,
                  color: SEVERITY_COLORS[tooltip.marker.severity],
                  border: `1px solid ${SEVERITY_COLORS[tooltip.marker.severity]}50`,
                }}
              >
                {tooltip.marker.severity}
              </span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: '#3b82f6' }}>
                {tooltip.marker.mitre_code}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Bottom legend bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 32,
          padding: '10px 24px',
          background: '#000000',
          borderTop: '1px solid rgba(255,255,255,0.08)',
          flexShrink: 0,
        }}
      >
        {[
          { label: 'CRITICAL', color: '#ef4444', count: criticalCount },
          { label: 'MEDIUM', color: '#f59e0b', count: mediumCount },
          { label: 'LOW', color: '#10b981', count: lowCount },
        ].map((item) => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: item.color,
                boxShadow: `0 0 8px ${item.color}`,
              }}
            />
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: '#94a3b8',
                letterSpacing: '0.08em',
              }}
            >
              {item.label}
            </span>
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: item.color,
                fontWeight: 700,
              }}
            >
              {item.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
