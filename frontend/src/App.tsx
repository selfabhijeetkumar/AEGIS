import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';
import Landing from './pages/Landing';
import Upload from './pages/Upload';
import Dashboard from './pages/Dashboard';
import Report from './pages/Report';
/* DO NOT REMOVE — PARTICLE SYSTEM */
import ParticleCanvas from './components/ParticleCanvas';
import CursorTrail from './components/CursorTrail';
import './index.css';

function AnimatedRoutes() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<Landing />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/dashboard/:scanId" element={<Dashboard />} />
        <Route path="/report/:scanId" element={<Report />} />
      </Routes>
    </AnimatePresence>
  );
}

function App() {
  return (
    <Router>
      <CursorTrail />
      {/* DO NOT REMOVE — PARTICLE SYSTEM */}
      <ParticleCanvas />
      <div className="vignette-overlay" />
      <div className="film-grain" />
      <div className="radar-grid" />

      <AnimatedRoutes />
    </Router>
  );
}

export default App;
