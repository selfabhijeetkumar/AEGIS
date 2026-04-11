import { useEffect, useRef, useState, useCallback } from 'react';
import { ShieldAlert } from 'lucide-react';
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

interface TooltipData {
  x: number;
  y: number;
  marker: AttackerMarker;
}

// Mercator projection with zoom + pan
function projectX(lon: number, width: number, zoom: number, offsetX: number): number {
  return (lon + 180) * (width / 360) * zoom + offsetX;
}

function projectY(lat: number, height: number, zoom: number, offsetY: number): number {
  return (90 - lat) * (height / 180) * zoom + offsetY;
}

// Compute centroid of a polygon ring
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function computeCentroid(coords: any[]): [number, number] {
  let sumX = 0, sumY = 0, count = 0;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const flatten = (rings: any[]) => {
    for (const ring of rings) {
      if (Array.isArray(ring) && typeof ring[0] === 'number') {
        sumX += ring[0];
        sumY += ring[1];
        count++;
      } else if (Array.isArray(ring)) {
        flatten(ring);
      }
    }
  };
  flatten(coords);
  return count > 0 ? [sumX / count, sumY / count] : [0, 0];
}

export default function ExpandedMapModal({ attackerMarkers, onClose }: ExpandedMapModalProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const geoDataRef = useRef<any>(null);
  const animFrameRef = useRef<number>(0);
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);
  const markersScreenRef = useRef<{ x: number; y: number; r: number; marker: AttackerMarker }[]>([]);

  // Zoom & pan state stored in refs so the render loop always reads latest
  const zoomRef = useRef(1);
  const offsetRef = useRef({ x: 0, y: 0 });
  const isDraggingRef = useRef(false);
  const dragStartRef = useRef({ x: 0, y: 0 });
  const dragOffsetStartRef = useRef({ x: 0, y: 0 });

  // Force re-render for zoom button UI
  const [zoomLevel, setZoomLevel] = useState(1);

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
      .catch(() => { /* silent */ });
  }, []);

  // Main canvas render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const startTime = performance.now();

    const render = (now: number) => {
      const elapsed = now - startTime;
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      const w = rect.width;
      const h = rect.height;
      const zoom = zoomRef.current;
      const ox = offsetRef.current.x;
      const oy = offsetRef.current.y;

      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // Clear — deep ocean blue water
      ctx.fillStyle = '#0d3b6e';
      ctx.fillRect(0, 0, w, h);

      // Draw grid lines
      ctx.strokeStyle = 'rgba(51, 65, 85, 0.12)';
      ctx.lineWidth = 0.5;
      for (let lon = -180; lon <= 180; lon += 30) {
        const x = projectX(lon, w, zoom, ox);
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let lat = -90; lat <= 90; lat += 30) {
        const y = projectY(lat, h, zoom, oy);
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // Draw countries
      const geo = geoDataRef.current;
      if (geo && geo.features) {
        ctx.fillStyle = '#1e293b';
        ctx.strokeStyle = '#334155';
        ctx.lineWidth = 0.5;

        for (const feature of geo.features) {
          const geom = feature.geometry;
          if (!geom) continue;

          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const drawPolygon = (rings: any[]) => {
            for (const ring of rings) {
              if (!ring || ring.length === 0) continue;
              ctx.beginPath();
              for (let j = 0; j < ring.length; j++) {
                const px = projectX(ring[j][0], w, zoom, ox);
                const py = projectY(ring[j][1], h, zoom, oy);
                if (j === 0) ctx.moveTo(px, py);
                else ctx.lineTo(px, py);
              }
              ctx.closePath();
              ctx.fill();
              ctx.stroke();
            }
          };

          if (geom.type === 'Polygon') {
            drawPolygon(geom.coordinates);
          } else if (geom.type === 'MultiPolygon') {
            for (const polygon of geom.coordinates) {
              drawPolygon(polygon);
            }
          }

          // Draw country name at centroid
          const name = feature.properties?.name;
          if (name) {
            const [cLon, cLat] = computeCentroid(geom.coordinates);
            const cx = projectX(cLon, w, zoom, ox);
            const cy = projectY(cLat, h, zoom, oy);
            // Only draw if visible on screen
            if (cx > -100 && cx < w + 100 && cy > -50 && cy < h + 50) {
              ctx.font = "10px 'JetBrains Mono', monospace";
              ctx.fillStyle = 'rgba(148,163,184,0.6)';
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillText(name, cx, cy);
              // Reset fill for next country
              ctx.fillStyle = '#1e293b';
            }
          }
        }
      }

      // Draw attacker markers with pulse
      const pulsePhase = (elapsed % 2000) / 2000;
      const screenMarkers: { x: number; y: number; r: number; marker: AttackerMarker }[] = [];

      for (const m of attackerMarkers) {
        const color = SEVERITY_COLORS[m.severity] || '#ef4444';
        const baseRadius = m.severity === 'CRITICAL' ? 8 : m.severity === 'MEDIUM' ? 6 : 5;
        const cx = projectX(m.lon, w, zoom, ox);
        const cy = projectY(m.lat, h, zoom, oy);

        // Skip if off-screen
        if (cx < -20 || cx > w + 20 || cy < -20 || cy > h + 20) continue;

        screenMarkers.push({ x: cx, y: cy, r: (baseRadius + 6) * zoom, marker: m });

        // Pulse ring 1
        const pr1 = baseRadius + pulsePhase * 10;
        ctx.beginPath(); ctx.arc(cx, cy, pr1, 0, Math.PI * 2);
        ctx.strokeStyle = color; ctx.lineWidth = 1.5;
        ctx.globalAlpha = (1 - pulsePhase) * 0.6;
        ctx.stroke(); ctx.globalAlpha = 1;

        // Pulse ring 2 (offset)
        const p2 = ((elapsed + 800) % 2000) / 2000;
        const pr2 = baseRadius + p2 * 10;
        ctx.beginPath(); ctx.arc(cx, cy, pr2, 0, Math.PI * 2);
        ctx.strokeStyle = color; ctx.lineWidth = 1;
        ctx.globalAlpha = (1 - p2) * 0.3;
        ctx.stroke(); ctx.globalAlpha = 1;

        // Glow + filled circle
        ctx.save();
        ctx.shadowColor = color; ctx.shadowBlur = 14;
        ctx.beginPath(); ctx.arc(cx, cy, baseRadius, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.fill();
        ctx.restore();

        // White center
        ctx.beginPath(); ctx.arc(cx, cy, 2, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255,255,255,0.8)'; ctx.fill();
      }

      markersScreenRef.current = screenMarkers;
      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [attackerMarkers]);

  // Mouse move for tooltips
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isDraggingRef.current) {
      // Handle panning
      const dx = e.clientX - dragStartRef.current.x;
      const dy = e.clientY - dragStartRef.current.y;
      offsetRef.current = {
        x: dragOffsetStartRef.current.x + dx,
        y: dragOffsetStartRef.current.y + dy,
      };
      setTooltip(null);
      return;
    }

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

  const handleMouseDown = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    isDraggingRef.current = true;
    dragStartRef.current = { x: e.clientX, y: e.clientY };
    dragOffsetStartRef.current = { ...offsetRef.current };
  }, []);

  const handleMouseUp = useCallback(() => {
    isDraggingRef.current = false;
  }, []);

  const handleMouseLeave = useCallback(() => {
    isDraggingRef.current = false;
    setTooltip(null);
  }, []);

  // Zoom handlers
  const handleZoomIn = useCallback(() => {
    const newZoom = Math.min(zoomRef.current * 1.3, 8);
    zoomRef.current = newZoom;
    setZoomLevel(newZoom);
  }, []);

  const handleZoomOut = useCallback(() => {
    const newZoom = Math.max(zoomRef.current * 0.77, 0.5);
    zoomRef.current = newZoom;
    setZoomLevel(newZoom);
  }, []);

  const handleResetView = useCallback(() => {
    zoomRef.current = 1;
    offsetRef.current = { x: 0, y: 0 };
    setZoomLevel(1);
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
      {/* ===== CLOSE BUTTON — top-right, always visible, OUTSIDE canvas ===== */}
      <div
        style={{
          position: 'absolute',
          top: 24,
          right: 24,
          zIndex: 10000,
        }}
      >
        <button
          onClick={onClose}
          aria-label="Close expanded map"
          style={{
            background: 'rgba(0,0,0,0.9)',
            border: '1px solid rgba(255,255,255,0.3)',
            borderRadius: 8,
            padding: '8px 16px',
            cursor: 'pointer',
            color: '#ffffff',
            fontSize: 18,
            fontWeight: 700,
            fontFamily: "'JetBrains Mono', monospace",
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(239,68,68,0.8)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(0,0,0,0.9)';
          }}
        >
          ✕ CLOSE
        </button>
      </div>

      {/* Header bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
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
      </div>

      {/* Canvas map area */}
      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        <canvas
          ref={canvasRef}
          style={{
            width: '100%',
            height: '100%',
            display: 'block',
            cursor: isDraggingRef.current ? 'grabbing' : 'grab',
          }}
          onMouseMove={handleMouseMove}
          onMouseDown={handleMouseDown}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseLeave}
        />

        {/* Zoom controls — bottom-right */}
        <div
          style={{
            position: 'absolute',
            bottom: 20,
            right: 20,
            zIndex: 10000,
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}
        >
          <button
            onClick={handleZoomIn}
            aria-label="Zoom in"
            style={{
              width: 36,
              height: 36,
              background: 'rgba(0,0,0,0.8)',
              border: '1px solid rgba(255,255,255,0.2)',
              borderRadius: 6,
              color: '#e2e8f0',
              fontSize: 18,
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
              fontFamily: "'JetBrains Mono', monospace",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(59,130,246,0.3)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(0,0,0,0.8)'; }}
          >
            +
          </button>
          <button
            onClick={handleZoomOut}
            aria-label="Zoom out"
            style={{
              width: 36,
              height: 36,
              background: 'rgba(0,0,0,0.8)',
              border: '1px solid rgba(255,255,255,0.2)',
              borderRadius: 6,
              color: '#e2e8f0',
              fontSize: 18,
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
              fontFamily: "'JetBrains Mono', monospace",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(59,130,246,0.3)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(0,0,0,0.8)'; }}
          >
            −
          </button>
          <button
            onClick={handleResetView}
            aria-label="Reset view"
            style={{
              width: 36,
              height: 36,
              background: 'rgba(0,0,0,0.8)',
              border: '1px solid rgba(255,255,255,0.2)',
              borderRadius: 6,
              color: '#94a3b8',
              fontSize: 10,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
              fontFamily: "'JetBrains Mono', monospace",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(59,130,246,0.3)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(0,0,0,0.8)'; }}
          >
            {zoomLevel.toFixed(1)}x
          </button>
        </div>

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
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: '#22d3ee', marginBottom: 4, fontWeight: 600 }}>
              {tooltip.marker.source_ip}
            </div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#f8fafc', marginBottom: 4 }}>
              {tooltip.marker.country}
            </div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>
              {tooltip.marker.threat_type}
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 10, fontWeight: 700,
                padding: '2px 8px', borderRadius: 999,
                background: `${SEVERITY_COLORS[tooltip.marker.severity]}25`,
                color: SEVERITY_COLORS[tooltip.marker.severity],
                border: `1px solid ${SEVERITY_COLORS[tooltip.marker.severity]}50`,
              }}>
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
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: item.color, boxShadow: `0 0 8px ${item.color}` }} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94a3b8', letterSpacing: '0.08em' }}>
              {item.label}
            </span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: item.color, fontWeight: 700 }}>
              {item.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
