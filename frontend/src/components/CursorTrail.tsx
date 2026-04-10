import { useEffect, useRef, useCallback } from 'react';

/* ──────────────────────────────────────────────────
   AEGIS Custom Cursor — Obsidian Assembly inspired
   3 layers: dot · ring · geometric line trails
   ────────────────────────────────────────────────── */

const LERP_RING = 0.12;
const TRAIL_POINTS = 8;
const TRAIL_FADE_MS = 800;
const SHAPE_INTERVAL_MS = 400;
const SHAPE_FADE_MS = 1200;

// ── Geometric shape factories ──────────────────────
type ShapeKind = 'triangle' | 'cross' | 'diamond';
const SHAPE_KINDS: ShapeKind[] = ['triangle', 'cross', 'diamond'];

function createShapeSVG(kind: ShapeKind, size: number): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', `${size}`);
  svg.setAttribute('height', `${size}`);
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.style.overflow = 'visible';

  const half = size / 2;

  if (kind === 'triangle') {
    const poly = document.createElementNS(ns, 'polygon');
    poly.setAttribute('points', `${half},2 ${size - 2},${size - 2} 2,${size - 2}`);
    poly.setAttribute('fill', 'none');
    poly.setAttribute('stroke', 'rgba(59,130,246,0.08)');
    poly.setAttribute('stroke-width', '1');
    svg.appendChild(poly);
  } else if (kind === 'cross') {
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('stroke', 'rgba(59,130,246,0.08)');
    g.setAttribute('stroke-width', '1');
    const l1 = document.createElementNS(ns, 'line');
    l1.setAttribute('x1', `${half}`); l1.setAttribute('y1', '2');
    l1.setAttribute('x2', `${half}`); l1.setAttribute('y2', `${size - 2}`);
    const l2 = document.createElementNS(ns, 'line');
    l2.setAttribute('x1', '2'); l2.setAttribute('y1', `${half}`);
    l2.setAttribute('x2', `${size - 2}`); l2.setAttribute('y2', `${half}`);
    g.appendChild(l1);
    g.appendChild(l2);
    svg.appendChild(g);
  } else {
    // diamond
    const poly = document.createElementNS(ns, 'polygon');
    poly.setAttribute('points', `${half},2 ${size - 2},${half} ${half},${size - 2} 2,${half}`);
    poly.setAttribute('fill', 'none');
    poly.setAttribute('stroke', 'rgba(59,130,246,0.08)');
    poly.setAttribute('stroke-width', '1');
    svg.appendChild(poly);
  }

  return svg;
}

// ── Component ──────────────────────────────────────
export default function CursorTrail() {
  const containerRef = useRef<HTMLDivElement>(null);
  const rafId = useRef(0);

  // Mutable state refs (no React re-renders)
  const mouse = useRef({ x: -100, y: -100 });
  const ringPos = useRef({ x: -100, y: -100 });
  const trail = useRef<{ x: number; y: number; t: number }[]>([]);
  const isHover = useRef(false);
  const lastShapeTime = useRef(0);
  const lastMoveTime = useRef(0);
  const isMoving = useRef(false);

  // DOM element refs
  const dotEl = useRef<HTMLDivElement | null>(null);
  const ringEl = useRef<HTMLDivElement | null>(null);
  const svgEl = useRef<SVGSVGElement | null>(null);
  const shapesContainer = useRef<HTMLDivElement | null>(null);

  const buildDOM = useCallback(() => {
    const c = containerRef.current;
    if (!c) return;

    // Layer 1 — Dot
    const dot = document.createElement('div');
    Object.assign(dot.style, {
      position: 'fixed',
      width: '6px',
      height: '6px',
      borderRadius: '50%',
      background: '#3b82f6',
      boxShadow: '0 0 8px rgba(59,130,246,0.9)',
      pointerEvents: 'none',
      zIndex: '99999',
      transform: 'translate(-50%,-50%)',
      transition: 'width 0.25s, height 0.25s, background 0.25s, box-shadow 0.25s',
      willChange: 'transform, left, top',
      left: '-100px',
      top: '-100px',
    });
    c.appendChild(dot);
    dotEl.current = dot;

    // Layer 2 — Ring
    const ring = document.createElement('div');
    Object.assign(ring.style, {
      position: 'fixed',
      width: '24px',
      height: '24px',
      borderRadius: '50%',
      border: '1px solid rgba(59,130,246,0.4)',
      background: 'transparent',
      pointerEvents: 'none',
      zIndex: '99999',
      transform: 'translate(-50%,-50%)',
      transition: 'width 0.25s, height 0.25s, border-color 0.25s',
      willChange: 'transform, left, top',
      left: '-100px',
      top: '-100px',
    });
    c.appendChild(ring);
    ringEl.current = ring;

    // Layer 3a — SVG line trails
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    Object.assign(svg.style, {
      position: 'fixed',
      inset: '0',
      pointerEvents: 'none',
      zIndex: '99999',
      overflow: 'visible',
    });
    c.appendChild(svg);
    svgEl.current = svg;

    // Layer 3b — Geometric shapes container
    const shapes = document.createElement('div');
    Object.assign(shapes.style, {
      position: 'fixed',
      inset: '0',
      pointerEvents: 'none',
      zIndex: '99999',
    });
    c.appendChild(shapes);
    shapesContainer.current = shapes;
  }, []);

  useEffect(() => {
    // Bail on touch devices
    if (window.matchMedia('(pointer: coarse)').matches) return;

    // Hide default cursor
    document.body.style.cursor = 'none';

    buildDOM();

    // ── Mouse move handler ──
    const onMove = (e: MouseEvent) => {
      mouse.current = { x: e.clientX, y: e.clientY };
      lastMoveTime.current = performance.now();
      isMoving.current = true;
    };

    // ── Hover detection ──
    const CLICKABLE = 'a, button, [role="button"], input[type="submit"], input[type="button"], .clickable, tr[data-clickable], [onclick], label[for], select, textarea, input';

    const onOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (target.closest(CLICKABLE)) {
        isHover.current = true;
      }
    };
    const onOut = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (target.closest(CLICKABLE)) {
        isHover.current = false;
      }
    };

    // ── Spawn geometric shape ──
    function spawnShape(x: number, y: number) {
      const sc = shapesContainer.current;
      if (!sc) return;
      const kind = SHAPE_KINDS[Math.floor(Math.random() * SHAPE_KINDS.length)];
      const size = 20 + Math.random() * 20; // 20-40px
      const svg = createShapeSVG(kind, size);
      const wrapper = document.createElement('div');
      Object.assign(wrapper.style, {
        position: 'fixed',
        left: `${x}px`,
        top: `${y}px`,
        transform: 'translate(-50%,-50%) rotate(0deg)',
        pointerEvents: 'none',
        zIndex: '99999',
        opacity: '1',
        transition: `opacity ${SHAPE_FADE_MS}ms ease-out, transform ${SHAPE_FADE_MS}ms ease-out`,
      });
      wrapper.appendChild(svg);
      sc.appendChild(wrapper);

      // Trigger fade + rotation
      requestAnimationFrame(() => {
        const rot = (Math.random() - 0.5) * 90;
        wrapper.style.opacity = '0';
        wrapper.style.transform = `translate(-50%,-50%) rotate(${rot}deg)`;
      });

      setTimeout(() => wrapper.remove(), SHAPE_FADE_MS + 50);
    }

    // ── Animation loop ──
    const animate = (now: number) => {
      const { x: mx, y: my } = mouse.current;

      // Stop moving flag after 100ms idle
      if (now - lastMoveTime.current > 100) {
        isMoving.current = false;
      }

      // --- Layer 1: Dot follows exactly ---
      const dot = dotEl.current;
      if (dot) {
        dot.style.left = `${mx}px`;
        dot.style.top = `${my}px`;
        if (isHover.current) {
          dot.style.width = '15px';
          dot.style.height = '15px';
          dot.style.background = '#ef4444';
          dot.style.boxShadow = '0 0 12px rgba(239,68,68,0.9), 0 0 24px rgba(239,68,68,0.4)';
        } else {
          dot.style.width = '6px';
          dot.style.height = '6px';
          dot.style.background = '#3b82f6';
          dot.style.boxShadow = '0 0 8px rgba(59,130,246,0.9)';
        }
      }

      // --- Layer 2: Ring with lerp ---
      ringPos.current.x += (mx - ringPos.current.x) * LERP_RING;
      ringPos.current.y += (my - ringPos.current.y) * LERP_RING;
      const ring = ringEl.current;
      if (ring) {
        ring.style.left = `${ringPos.current.x}px`;
        ring.style.top = `${ringPos.current.y}px`;
        if (isHover.current) {
          ring.style.width = '43px';  // 24 * 1.8
          ring.style.height = '43px';
          ring.style.borderColor = 'rgba(239,68,68,0.5)';
        } else {
          ring.style.width = '24px';
          ring.style.height = '24px';
          ring.style.borderColor = 'rgba(59,130,246,0.4)';
        }
      }

      // --- Layer 3a: SVG trail lines ---
      if (isMoving.current) {
        // Add new trail point
        trail.current.push({ x: mx, y: my, t: now });
        // Keep only last N
        if (trail.current.length > TRAIL_POINTS) {
          trail.current = trail.current.slice(-TRAIL_POINTS);
        }
      }

      // Prune expired points
      trail.current = trail.current.filter(p => now - p.t < TRAIL_FADE_MS);

      // Redraw SVG lines
      const svg = svgEl.current;
      if (svg) {
        // Clear previous lines
        while (svg.firstChild) svg.removeChild(svg.firstChild);

        const pts = trail.current;
        if (pts.length >= 2) {
          const ns = 'http://www.w3.org/2000/svg';
          for (let i = 1; i < pts.length; i++) {
            const age = (now - pts[i].t) / TRAIL_FADE_MS; // 0..1
            const alpha = Math.max(0, 0.15 * (1 - age));
            const line = document.createElementNS(ns, 'line');
            line.setAttribute('x1', `${pts[i - 1].x}`);
            line.setAttribute('y1', `${pts[i - 1].y}`);
            line.setAttribute('x2', `${pts[i].x}`);
            line.setAttribute('y2', `${pts[i].y}`);
            line.setAttribute('stroke', `rgba(59,130,246,${alpha.toFixed(3)})`);
            line.setAttribute('stroke-width', '1');
            line.setAttribute('stroke-linecap', 'round');
            svg.appendChild(line);
          }
        }
      }

      // --- Layer 3b: Geometric shapes ---
      if (isMoving.current && now - lastShapeTime.current > SHAPE_INTERVAL_MS) {
        spawnShape(mx, my);
        lastShapeTime.current = now;
      }

      rafId.current = requestAnimationFrame(animate);
    };

    window.addEventListener('mousemove', onMove);
    document.addEventListener('mouseover', onOver);
    document.addEventListener('mouseout', onOut);
    rafId.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseover', onOver);
      document.removeEventListener('mouseout', onOut);
      cancelAnimationFrame(rafId.current);
      document.body.style.cursor = '';
      // Clean up DOM
      const c = containerRef.current;
      if (c) c.innerHTML = '';
    };
  }, [buildDOM]);

  return (
    <div
      ref={containerRef}
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 99999,
      }}
    />
  );
}
