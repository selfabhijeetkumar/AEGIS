import * as THREE from 'three';
import { useRef, useMemo, useState, useEffect } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';

/* ===== CHANGE-07: 3D Holographic Shield ===== */

function ShieldMesh() {
  const groupRef = useRef<THREE.Group>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const scanRef = useRef<THREE.Mesh>(null);
  const diamondRef = useRef<THREE.Mesh>(null);
  const [mouse, setMouse] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMouse({
        x: (e.clientX / window.innerWidth - 0.5) * 0.3,
        y: (e.clientY / window.innerHeight - 0.5) * 0.3,
      });
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  // Heraldic military shield — flat top, straight sides, curved bottom to sharp point
  const shieldShape = useMemo(() => {
    try {
      const s = new THREE.Shape();
      s.moveTo(-1.5, 1.8);
      s.lineTo(1.5, 1.8);
      s.lineTo(1.5, 0.2);
      s.bezierCurveTo(1.5, -0.4, 0.8, -1.1, 0, -1.8);
      s.bezierCurveTo(-0.8, -1.1, -1.5, -0.4, -1.5, 0.2);
      s.closePath();
      return s;
    } catch (e) {
      console.error(e);
      return null;
    }
  }, []);

  const extrudeSettings = useMemo(() => {
    try {
      return {
        depth: 0.3,
        bevelEnabled: true,
        bevelThickness: 0.05,
        bevelSize: 0.03,
        bevelSegments: 3,
      };
    } catch {
      return { depth: 0 };
    }
  }, []);

  useFrame((state) => {
    try {
      const t = state.clock.elapsedTime;
      if (groupRef.current) {
        // Slow Y-axis rocking + gentle float
        groupRef.current.rotation.y = Math.sin(t * 0.4) * 0.15 + mouse.x;
        groupRef.current.rotation.x = Math.sin(t * 0.3) * 0.05 + mouse.y;
        groupRef.current.position.y = Math.sin(t * 0.6) * 0.1;
      }
      if (glowRef.current) {
        const mat = glowRef.current.material as THREE.MeshBasicMaterial;
        mat.opacity = 0.06 + Math.sin(t * 1.5) * 0.06;
      }
      if (scanRef.current) {
        scanRef.current.position.y = Math.sin(t * 2) * 1.5;
      }
      if (diamondRef.current) {
        diamondRef.current.rotation.y = t * 0.8;
        diamondRef.current.rotation.x = t * 0.3;
      }
    } catch (err) {
      // Ignore animate frame crashes to prevent app teardown
    }
  });

  if (!shieldShape) return null; // Shape failed to initialize, prevent render crash

  return (
    <group ref={groupRef} position={[0, 0, 0]}>
      {/* Main shield body */}
      <mesh position={[0, 0, -0.075]}>
        <extrudeGeometry args={[shieldShape, extrudeSettings]} />
        <meshPhysicalMaterial
          color="#0a2a5e"
          metalness={0.9}
          roughness={0.1}
          transparent
          opacity={0.7}
          clearcoat={1}
          clearcoatRoughness={0.1}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* Wireframe overlay */}
      <mesh position={[0, 0, -0.075]}>
        <extrudeGeometry args={[shieldShape, extrudeSettings]} />
        <meshBasicMaterial
          color="#3b82f6"
          wireframe
          transparent
          opacity={0.25}
        />
      </mesh>

      {/* Outer glow mesh */}
      <mesh ref={glowRef} scale={[1.15, 1.15, 1.15]} position={[0, 0, -0.075]}>
        <extrudeGeometry args={[shieldShape, { depth: 0.01, bevelEnabled: false }]} />
        <meshBasicMaterial
          color="#3b82f6"
          transparent
          opacity={0.1}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* Center diamond (octahedron) */}
      <mesh ref={diamondRef} position={[0, 0.1, 0.1]}>
        <octahedronGeometry args={[0.25, 0]} />
        <meshStandardMaterial
          color="#3b82f6"
          emissive="#3b82f6"
          emissiveIntensity={2}
          metalness={1}
          roughness={0}
          transparent
          opacity={0.9}
        />
      </mesh>

      {/* Cyan scan line sweeping up and down */}
      <mesh ref={scanRef} position={[0, 0, 0.15]}>
        <planeGeometry args={[3, 0.02]} />
        <meshBasicMaterial color="#06b6d4" transparent opacity={0.6} side={THREE.DoubleSide} />
      </mesh>
    </group>
  );
}

interface HolographicShieldProps {
  size?: number;
  className?: string;
}

export default function HolographicShield({ size, className = '' }: HolographicShieldProps) {
  const [webglSupported] = useState(() => {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      return !!gl;
    } catch {
      return false;
    }
  });

  if (!webglSupported) {
    // Fallback static shield
    return (
      <div className={`flex items-center justify-center ${className}`} style={size ? { width: size, height: size } : { width: '100%', height: '100%' }}>
        <div className="w-32 h-32 rounded-full border-2 border-blue-500/30 flex items-center justify-center"
          style={{ boxShadow: '0 0 40px rgba(59,130,246,0.2)' }}>
          <div className="w-8 h-8 rotate-45 bg-blue-500/20 border border-blue-500/40" />
        </div>
      </div>
    );
  }

  return (
    <div className={className} style={size ? { width: size, height: size } : { width: '100%', height: '100%' }}>
      <Canvas
        camera={{ position: [0, 0, 4.5], fov: 45 }}
        style={{ background: 'transparent' }}
        dpr={[1, 2]}
      >
        <ambientLight intensity={0.3} />
        <pointLight position={[5, 5, 5]} intensity={1} color="#3b82f6" />
        <pointLight position={[-5, -5, 5]} intensity={0.7} color="#06b6d4" />
        <pointLight position={[0, 0, 5]} intensity={0.5} color="#ffffff" />
        <ShieldMesh />
      </Canvas>
    </div>
  );
}
