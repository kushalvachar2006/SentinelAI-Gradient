import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Zap, Brain, GitBranch, MessageSquare, Filter, FileText } from 'lucide-react';
import Navbar from '../components/layout/Navbar';

const TERMINAL_LOGS = [
  '[14:32:01] INFO  Ingesting log stream from syslog-aggregator-01',
  '[14:32:02] SCAN  185.234.219.11 → api.prod.internal:443 — TLS fingerprint mismatch',
  '[14:32:02] WARN  Anomalous JWT structure detected in Authorization header',
  '[14:32:03] CRIT  SQL payload detected: \' OR 1=1; DROP TABLE users--',
  '[14:32:03] AI    Classifying event... confidence: 98.4% → SQL Injection',
  '[14:32:04] INFO  MITRE tag: T1190 (Exploit Public-Facing Application)',
  '[14:32:04] ALERT Creating incident T-001, notifying on-call analyst',
  '[14:32:05] INFO  185.234.219.11 lookup: RU / AS42793 / AbuseIPDB: 94/100',
  '[14:32:06] SCAN  91.108.56.34 → workstation-14.corp:4444 — beacon pattern',
  '[14:32:07] CRIT  C2 beacon: 60s interval, encrypted, known ransomware infra',
  '[14:32:07] AI    Classifying... confidence: 96.1% → Ransomware C2',
  '[14:32:08] ALERT Creating incident T-002, auto-isolating endpoint',
  '[14:32:09] INFO  Processing 2,847 log lines from bastion-01.infra',
  '[14:32:10] WARN  SSH brute force: 1,247 attempts in 180s from 203.0.113.45',
  '[14:32:10] AI    Risk score: 82 — HIGH severity',
];

const STATS = [
  { value: '10,000+', label: 'Alerts/day filtered' },
  { value: '<60s', label: 'Detection time' },
  { value: '94.7%', label: 'True positive rate' },
];

const features = [
  { icon: Zap, title: 'Threat Prioritization', desc: 'AI-ranked alert queue so your team focuses on what matters. Risk scores from 0–100 calculated in real-time.' },
  { icon: Brain, title: 'AI Explanation', desc: 'Every alert explained in plain English or expert mode. No more log archaeology — context delivered instantly.' },
  { icon: GitBranch, title: 'Attack Chains', desc: 'Visualize multi-stage attack progressions with MITRE ATT&CK mapping and kill chain analysis.' },
  { icon: MessageSquare, title: 'SOC Chatbot', desc: 'Ask questions about your infrastructure in natural language. "Which IPs attacked us most this week?"' },
  { icon: Filter, title: 'False Positive Filter', desc: 'ML-powered noise reduction trained on 10M+ security events. Tune the signal, silence the noise.' },
  { icon: FileText, title: 'Incident Reports', desc: 'One-click PDF incident reports with timeline, indicators, and remediation steps. Board-ready in seconds.' },
];

function EclipseRing() {
  return (
    <div style={{ position: 'relative', width: 320, height: 320, margin: '0 auto 60px' }}>
      {/* Outer energy rings */}
      {[1.4, 1.25, 1.1].map((scale, i) => (
        <div key={i} style={{
          position: 'absolute', inset: 0,
          border: `1px solid rgba(255,107,0,${0.06 - i * 0.015})`,
          borderRadius: '50%',
          transform: `scale(${scale})`,
          top: '50%', left: '50%',
          width: '100%', height: '100%',
          marginTop: '-50%', marginLeft: '-50%',
          animation: `energy-wave ${2.5 + i * 0.8}s ease-out infinite`,
          animationDelay: `${i * 0.5}s`,
        }} />
      ))}
      {/* Main eclipse body */}
      <div style={{
        position: 'absolute', inset: 0,
        borderRadius: '50%',
        background: 'radial-gradient(circle at 35% 35%, #FF8C42, #FF6B00 40%, #CC4400)',
        boxShadow: '0 0 60px rgba(255,107,0,0.5), 0 0 120px rgba(255,107,0,0.25), 0 0 200px rgba(255,107,0,0.1)',
        animation: 'eclipse-pulse 4s ease-in-out infinite',
      }} />
      {/* Moon overlay — creates eclipse effect */}
      <div style={{
        position: 'absolute',
        top: '8%', left: '14%',
        width: '84%', height: '84%',
        borderRadius: '50%',
        background: '#090909',
      }} />
      {/* Corona glow filaments */}
      {[0, 45, 90, 135, 180, 225, 270, 315].map((deg, i) => (
        <div key={i} style={{
          position: 'absolute', top: '50%', left: '50%',
          width: `${50 + (i % 3) * 18}px`, height: '2px',
          background: `linear-gradient(90deg, rgba(255,${120 + i*10},0,0.8), transparent)`,
          transform: `rotate(${deg}deg) translateX(160px)`,
          transformOrigin: '0 50%',
          borderRadius: '1px',
        }} />
      ))}
      {/* Orbiting particles */}
      {[0, 120, 240].map((deg, i) => (
        <div key={i} style={{
          position: 'absolute', top: '50%', left: '50%',
          width: 8, height: 8,
          marginTop: -4, marginLeft: -4,
          animation: `orbit ${3 + i * 0.8}s linear infinite`,
          '--orbit-r': `${145 + i * 20}px`,
        }}>
          <div style={{
            width: '100%', height: '100%', borderRadius: '50%',
            background: '#FF6B00',
            boxShadow: '0 0 12px #FF6B00, 0 0 24px rgba(255,107,0,0.5)',
          }} />
        </div>
      ))}
    </div>
  );
}

function LiveTerminal() {
  const [lines, setLines] = useState([TERMINAL_LOGS[0]]);
  const [idx, setIdx] = useState(1);
  const ref = useRef();

  useEffect(() => {
    const interval = setInterval(() => {
      setIdx(i => {
        const next = i >= TERMINAL_LOGS.length ? 0 : i;
        setLines(prev => [...prev, TERMINAL_LOGS[next]].slice(-12));
        return next + 1;
      });
    }, 900);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  const getColor = (line) => {
    if (line.includes('CRIT')) return 'var(--sev-critical)';
    if (line.includes('WARN')) return 'var(--sev-high)';
    if (line.includes('AI')) return 'var(--warm)';
    if (line.includes('ALERT')) return 'var(--solar)';
    return 'var(--text-secondary)';
  };

  return (
    <div style={{
      background: 'rgba(9,9,9,0.95)',
      border: '1px solid rgba(255,107,0,0.2)',
      borderRadius: 'var(--radius-lg)',
      overflow: 'hidden',
      maxWidth: '860px',
      margin: '0 auto',
      boxShadow: '0 0 40px rgba(255,107,0,0.08), 0 24px 64px rgba(0,0,0,0.6)',
    }}>
      <div style={{
        padding: '12px 18px',
        background: 'rgba(255,107,0,0.04)',
        borderBottom: '1px solid rgba(255,107,0,0.12)',
        display: 'flex', alignItems: 'center', gap: '8px',
      }}>
        {['#FF3D71', '#FFD166', '#00D084'].map((c, i) => (
          <div key={i} style={{ width: 10, height: 10, borderRadius: '50%', background: c, opacity: 0.8 }} />
        ))}
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: '8px' }}>
          sentinel-ai — threat-analysis-engine v2.4.1
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--sev-low)', boxShadow: '0 0 6px var(--sev-low)', animation: 'pulse-soft 2s ease-in-out infinite' }} />
          <span style={{ fontSize: '10px', color: 'var(--sev-low)', fontFamily: 'var(--font-mono)' }}>LIVE</span>
        </div>
      </div>
      <div ref={ref} style={{
        padding: '16px', height: '280px', overflowY: 'auto',
        fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: '24px',
      }}>
        {lines.map((line, i) => (
          <motion.div
            key={i + line}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2 }}
            style={{ color: getColor(line), whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
          >
            {line}
          </motion.div>
        ))}
        <span style={{ color: 'var(--eclipse)', opacity: 0.7 }}>▋</span>
      </div>
    </div>
  );
}

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-base)', overflowX: 'hidden' }}>
      <Navbar landing />

      {/* Global background */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none',
        background: `
          radial-gradient(ellipse 80% 60% at 50% -20%, rgba(255,107,0,0.07) 0%, transparent 60%),
          radial-gradient(ellipse 40% 40% at 80% 80%, rgba(255,107,0,0.03) 0%, transparent 60%),
          radial-gradient(ellipse 60% 40% at 10% 60%, rgba(255,61,113,0.02) 0%, transparent 60%)
        `,
      }} />

      {/* Hero */}
      <section style={{
        position: 'relative', minHeight: '100vh',
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        padding: '80px 24px 60px',
        overflow: 'hidden',
        zIndex: 1,
      }}>
        {/* <EclipseRing /> */}

        <div style={{ position: 'relative', zIndex: 1, textAlign: 'center', maxWidth: '780px' }}>
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '8px',
              padding: '5px 16px', borderRadius: '20px',
              background: 'rgba(255,107,0,0.08)',
              border: '1px solid rgba(255,107,0,0.25)',
              marginBottom: '32px',
            }}
          >
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--sev-low)', boxShadow: '0 0 6px var(--sev-low)', animation: 'pulse-soft 2s ease-in-out infinite' }} />
            <span style={{ fontSize: '11px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)', letterSpacing: '0.12em' }}>
              AI THREAT INTELLIGENCE PLATFORM — v2.4.1
            </span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.5 }}
            style={{
              fontSize: 'clamp(40px, 4vw, 45px)',
              fontFamily: 'var(--font-display)',
              fontWeight: 800,
              lineHeight: 1.05,
              letterSpacing: '0.02em',
              textTransform: 'uppercase',
              marginBottom: '24px',
            }}
          >
            <span style={{ color: 'var(--text-primary)' }}>See Every</span>{' '}
            <span style={{ color: 'var(--eclipse)', textShadow: '0 0 40px rgba(255,107,0,0.5)' }}>Threat.</span>
            <br />
            <span style={{ color: 'var(--text-primary)' }}>Understand Every</span>{' '}
            <span style={{ color: 'var(--solar)' }}>Move.</span>
            <br />
            <span style={{ color: 'var(--text-primary)', opacity: 0.6 }}>Stop Everything.</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            style={{
              fontSize: '17px',
              color: 'var(--text-secondary)',
              maxWidth: '500px',
              margin: '0 auto 40px',
              lineHeight: 1.75,
            }}
          >
            An AI agent that reads your logs so your team doesn't have to.
            Real-time threat detection, triage, and response — all in one command center.
          </motion.p>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.5 }}
            style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap', marginBottom: '40px' }}
          >
            {STATS.map(({ value, label }) => (
              <div key={label} style={{
                padding: '10px 20px', borderRadius: 'var(--radius-md)',
                background: 'rgba(255,107,0,0.06)',
                border: '1px solid rgba(255,107,0,0.15)',
              }}>
                <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '18px', color: 'var(--eclipse)', marginBottom: '2px' }}>{value}</div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>{label}</div>
              </div>
            ))}
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.5 }}
            style={{ display: 'flex', gap: '14px', justifyContent: 'center', flexWrap: 'wrap' }}
          >
            <button
              onClick={() => navigate('/dashboard')}
              className="eclipse-btn-primary"
              style={{ padding: '14px 28px', fontSize: '14px', fontWeight: 600 }}
            >
              Start Free Trial →
            </button>
            <button
              onClick={() => document.getElementById('demo').scrollIntoView({ behavior: 'smooth' })}
              className="eclipse-btn-secondary"
              style={{ padding: '14px 28px', fontSize: '14px' }}
            >
              Explore Live Demo ↓
            </button>
          </motion.div>
        </div>
      </section>

      {/* Features */}
      <section style={{ padding: '100px 24px', maxWidth: '1100px', margin: '0 auto', position: 'relative', zIndex: 1 }}>
        <div style={{ textAlign: 'center', marginBottom: '60px' }}>
          <p style={{ fontSize: '11px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)', letterSpacing: '0.2em', marginBottom: '16px', textTransform: 'uppercase' }}>
            ◆ CAPABILITIES ◆
          </p>
          <h2 style={{
            fontSize: 'clamp(28px, 3vw, 40px)',
            fontFamily: 'var(--font-display)',
            fontWeight: 700,
            letterSpacing: '0.02em',
            textTransform: 'uppercase',
            color: 'var(--text-primary)',
          }}>
            Enterprise-grade intelligence,<br />
            <span style={{ color: 'var(--eclipse)' }}>zero analyst burnout</span>
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
          {features.map(({ icon: Icon, title, desc }, i) => (
            <motion.div
              key={title}
              initial={{ opacity: 0, y: 24 }} whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }} transition={{ delay: i * 0.08, duration: 0.4 }}
              className="eclipse-card"
              style={{ padding: '28px' }}
            >
              <div style={{
                width: 44, height: 44, borderRadius: 'var(--radius-md)',
                background: 'rgba(255,107,0,0.1)',
                border: '1px solid rgba(255,107,0,0.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                marginBottom: '18px',
                boxShadow: '0 0 16px rgba(255,107,0,0.1)',
              }}>
                <Icon size={20} color="var(--eclipse)" />
              </div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '10px', color: 'var(--text-primary)', fontFamily: 'var(--font-ui)' }}>{title}</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>{desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Live Demo */}
      <section id="demo" style={{ padding: '80px 24px', maxWidth: '1000px', margin: '0 auto', position: 'relative', zIndex: 1 }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }} transition={{ duration: 0.4 }}
          style={{ textAlign: 'center', marginBottom: '48px' }}
        >
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: '8px',
            padding: '5px 16px', borderRadius: '20px',
            background: 'rgba(255,61,113,0.08)',
            border: '1px solid rgba(255,61,113,0.2)',
            marginBottom: '20px',
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--sev-critical)', boxShadow: '0 0 6px var(--sev-critical)', animation: 'pulse-soft 1.5s ease-in-out infinite' }} />
            <span style={{ fontSize: '11px', color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)', letterSpacing: '0.12em' }}>
              LIVE ANALYSIS ENGINE
            </span>
          </div>
          <h3 style={{
            fontSize: 'clamp(22px, 2.5vw, 32px)',
            fontFamily: 'var(--font-display)',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.03em',
            color: 'var(--text-primary)', marginBottom: '12px',
          }}>
            Watch threats get detected in real-time
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '15px' }}>
            AI processes thousands of log lines per second, extracting signals from noise
          </p>
        </motion.div>
        <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}>
          <LiveTerminal />
        </motion.div>
      </section>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid rgba(255,107,0,0.08)',
        padding: '40px 24px',
        textAlign: 'center',
        position: 'relative', zIndex: 1,
      }}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '20px' }}>
          {['React', 'Vite', 'Zustand', 'Framer Motion', 'Recharts', 'React Flow'].map(t => (
            <span key={t} style={{
              padding: '3px 12px', borderRadius: 'var(--radius-sm)',
              fontSize: '11px', fontFamily: 'var(--font-mono)',
              background: 'rgba(255,107,0,0.06)', border: '1px solid rgba(255,107,0,0.1)',
              color: 'var(--text-muted)',
            }}>{t}</span>
          ))}
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          © 2026 SentinelAI — <span style={{ color: 'var(--sev-low)' }}>●</span> All systems operational
        </p>
      </footer>
    </div>
  );
}