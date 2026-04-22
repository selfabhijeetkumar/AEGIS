import { useEffect, useRef } from 'react';

const TRAIL_LENGTH = 20;

export default function CursorTrail() {
  const containerRef = useRef<HTMLDivElement>(null);
  const points = useRef<{ x: number; y: number }[]>([]);
  const mousePos = useRef({ x: -100, y: -100 });
  const rafId = useRef<number>(0);
  const dotsRef = useRef<HTMLDivElement[]>([]);

  useEffect(() => {
    // Check for reduced motion preference
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) return;

    const container = containerRef.current;
    if (!container) return;

    // Create dot elements
    for (let i = 0; i < TRAIL_LENGTH; i++) {
      const dot = document.createElement('div');
      dot.style.position = 'fixed';
      dot.style.pointerEvents = 'none';
      dot.style.zIndex = '9999';
      dot.style.borderRadius = '50%';
      dot.style.transform = 'translate(-50%, -50%)';
      dot.style.willChange = 'transform, opacity';
      dot.style.left = '-100px';
      dot.style.top = '-100px';
      container.appendChild(dot);
      dotsRef.current.push(dot);
      points.current.push({ x: -100, y: -100 });
    }

    const handleMouseMove = (e: MouseEvent) => {
      mousePos.current = { x: e.clientX, y: e.clientY };
    };

    const animate = () => {
      // Shift trail points — head follows mouse, rest follow previous
      points.current[0] = { ...mousePos.current };
      for (let i = TRAIL_LENGTH - 1; i > 0; i--) {
        const prev = points.current[i - 1];
        const curr = points.current[i];
        curr.x += (prev.x - curr.x) * 0.35;
        curr.y += (prev.y - curr.y) * 0.35;
      }

      // Update DOM directly — no React state
      for (let i = 0; i < TRAIL_LENGTH; i++) {
        const dot = dotsRef.current[i];
        const t = i / (TRAIL_LENGTH - 1); // 0 = head, 1 = tail

        const opacity = 1 - t * 0.95;
        const scale = 1 - t * 0.9;
        const size = Math.max(12 * scale, 1);

        // Interpolate from cyan (#06b6d4 = 6,182,212) to deep blue (#1e40af = 30,64,175)
        const r = Math.round(6 + t * (30 - 6));
        const g = Math.round(182 + t * (64 - 182));
        const b = Math.round(212 + t * (175 - 212));

        dot.style.left = `${points.current[i].x}px`;
        dot.style.top = `${points.current[i].y}px`;
        dot.style.width = `${size}px`;
        dot.style.height = `${size}px`;
        dot.style.opacity = `${opacity}`;
        dot.style.background = `rgba(${r},${g},${b},${opacity})`;

        if (i === 0) {
          dot.style.boxShadow = '0 0 12px rgba(6,182,212,0.9), 0 0 24px rgba(6,182,212,0.5)';
        } else if (i < 5) {
          dot.style.boxShadow = `0 0 ${8 - i * 1.5}px rgba(6,182,212,${0.5 - i * 0.1})`;
        } else {
          dot.style.boxShadow = 'none';
        }
      }

      rafId.current = requestAnimationFrame(animate);
    };

    window.addEventListener('mousemove', handleMouseMove);
    rafId.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      cancelAnimationFrame(rafId.current);
      dotsRef.current.forEach(dot => dot.remove());
      dotsRef.current = [];
    };
  }, []);

  return <div ref={containerRef} style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 9999 }} />;
}
