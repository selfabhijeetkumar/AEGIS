import { useEffect } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import { X } from 'lucide-react';
import L from 'leaflet';
import type { ThreatEvent } from '../services/api';

// Fix Leaflet default icon bug
import markerIcon from 'leaflet/dist/images/marker-icon.png';
import markerShadow from 'leaflet/dist/images/marker-shadow.png';
L.Icon.Default.mergeOptions({ iconUrl: markerIcon, shadowUrl: markerShadow });

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

interface AttackerMarker extends ThreatEvent {
  count: number;
}

interface ExpandedMapModalProps {
  attackerMarkers: AttackerMarker[];
  onClose: () => void;
}

export default function ExpandedMapModal({ attackerMarkers, onClose }: ExpandedMapModalProps) {
  // Escape key closes the modal
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(0,0,0,0.95)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Scoped dark tile style — ONLY affects tiles inside this modal */}
      <style>{`
        .aegis-expanded-map .leaflet-tile {
          filter: invert(100%) hue-rotate(180deg) brightness(95%) contrast(90%);
        }
        .aegis-expanded-map .leaflet-container {
          background: #050a18 !important;
        }
      `}</style>

      {/* Title — top-left */}
      <div
        style={{
          position: 'absolute',
          top: 20,
          left: 24,
          zIndex: 10001,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 13,
          letterSpacing: '0.15em',
          textTransform: 'uppercase' as const,
          color: '#94a3b8',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <span style={{ color: '#3b82f6' }}>◆</span>
        IP GEOLOCATION — ATTACKER ORIGINS
      </div>

      {/* Close button — top-right */}
      <button
        onClick={onClose}
        aria-label="Close expanded map"
        style={{
          position: 'absolute',
          top: 16,
          right: 16,
          zIndex: 10001,
          background: 'rgba(255,255,255,0.08)',
          border: '1px solid rgba(255,255,255,0.12)',
          borderRadius: 8,
          padding: 8,
          cursor: 'pointer',
          color: '#94a3b8',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'all 0.2s ease',
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLButtonElement).style.background = 'rgba(239,68,68,0.2)';
          (e.currentTarget as HTMLButtonElement).style.color = '#ef4444';
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.08)';
          (e.currentTarget as HTMLButtonElement).style.color = '#94a3b8';
        }}
      >
        <X size={20} />
      </button>

      {/* Leaflet Map */}
      <div className="aegis-expanded-map" style={{ width: '100%', height: '90vh', marginTop: '5vh' }}>
        <MapContainer
          center={[20, 0]}
          zoom={2}
          scrollWheelZoom={true}
          style={{ height: '100%', width: '100%' }}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          {attackerMarkers.map((m, i) => {
            const color = SEVERITY_COLORS[m.severity] || '#ef4444';
            const radius = m.severity === 'CRITICAL' ? 10 : m.severity === 'MEDIUM' ? 8 : 6;
            return (
              <CircleMarker
                key={i}
                center={[m.lat, m.lon]}
                radius={radius}
                pathOptions={{
                  color: color,
                  fillColor: color,
                  fillOpacity: 0.7,
                  weight: 2,
                  opacity: 0.9,
                }}
              >
                <Popup>
                  <div style={{ minWidth: 220, fontFamily: "'JetBrains Mono', monospace" }}>
                    <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 6, color: '#1e293b' }}>
                      {m.country}
                    </div>
                    <div style={{ fontSize: 12, color: '#0369a1', marginBottom: 4 }}>
                      IP: {m.source_ip}
                    </div>
                    <div style={{ fontSize: 11, color: '#475569', marginBottom: 6 }}>
                      {m.threat_type}
                    </div>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}>
                      <span style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: 999,
                        background: `${color}25`,
                        color: color,
                        border: `1px solid ${color}50`,
                      }}>
                        {m.severity}
                      </span>
                      <span style={{ fontSize: 10, color: '#3b82f6' }}>{m.mitre_code}</span>
                    </div>
                    <div style={{ fontSize: 10, color: '#94a3b8' }}>
                      {m.bytes_transferred?.toLocaleString()} bytes
                    </div>
                  </div>
                </Popup>
              </CircleMarker>
            );
          })}
        </MapContainer>
      </div>

      {/* Legend — bottom-left */}
      <div
        style={{
          position: 'absolute',
          bottom: 'calc(5vh + 16px)',
          left: 24,
          zIndex: 10001,
          background: 'rgba(0,0,0,0.8)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8,
          padding: '10px 14px',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        {[
          { label: 'CRITICAL', color: '#ef4444' },
          { label: 'MEDIUM', color: '#f59e0b' },
          { label: 'LOW', color: '#10b981' },
        ].map((item) => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div
              style={{
                width: 10,
                height: 10,
                borderRadius: '50%',
                background: item.color,
                boxShadow: `0 0 8px ${item.color}`,
              }}
            />
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                letterSpacing: '0.08em',
                color: '#94a3b8',
              }}
            >
              {item.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
