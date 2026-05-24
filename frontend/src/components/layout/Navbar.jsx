import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, MessageSquare, BarChart3, Upload, Zap } from 'lucide-react';
import { useStore } from '../../store/useStore';

const navLinks = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/chat', label: 'SOC Chat', icon: MessageSquare },
  { to: '/ingest', label: 'Ingest', icon: Upload },
];

export default function Navbar({ landing = false }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { threats, analyst } = useStore();
  const hasCritical = threats.some(t => (t.severity || '').toUpperCase() === 'CRITICAL');

  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      background: 'rgba(9,9,9,0.85)',
      backdropFilter: 'blur(20px)',
      borderBottom: '1px solid rgba(255,107,0,0.12)',
      height: '60px',
      display: 'flex', alignItems: 'center',
      padding: '0 28px',
      gap: '24px',
    }}>
      {/* Ambient line */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0,
        height: '1px',
        background: 'linear-gradient(90deg, transparent, rgba(255,107,0,0.4), transparent)',
      }} />

      {/* Logo */}
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
        {/* Eclipse icon */}
        <div style={{ position: 'relative', width: 28, height: 28 }}>
          <div style={{
            width: 28, height: 28, borderRadius: '50%',
            background: 'radial-gradient(circle at 35% 40%, #FF8C42, #FF6B00)',
            boxShadow: '0 0 12px rgba(255,107,0,0.6), 0 0 24px rgba(255,107,0,0.3)',
            animation: 'eclipse-pulse 3s ease-in-out infinite',
          }} />
          <div style={{
            position: 'absolute', top: 3, left: 5, width: 22, height: 22, borderRadius: '50%',
            background: '#090909',
          }} />
        </div>
        <span style={{
          fontFamily: 'var(--font-display)',
          fontWeight: 700,
          fontSize: '14px',
          color: 'var(--text-primary)',
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
        }}>
          Sentinel<span style={{ color: 'var(--eclipse)' }}>AI</span>
        </span>
      </Link>

      <div style={{ flex: 1 }} />

      {/* Nav links */}
      {!landing && (
        <div style={{ display: 'flex', gap: '4px' }}>
          {navLinks.map(({ to, label, icon: Icon }) => {
            const active = location.pathname === to;
            return (
              <Link key={to} to={to} style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                padding: '7px 14px', borderRadius: 'var(--radius-sm)',
                textDecoration: 'none',
                fontSize: '13px', fontWeight: 500,
                color: active ? 'var(--eclipse)' : 'var(--text-secondary)',
                background: active ? 'rgba(255,107,0,0.08)' : 'transparent',
                border: active ? '1px solid rgba(255,107,0,0.15)' : '1px solid transparent',
                transition: 'all 0.2s',
                fontFamily: 'var(--font-ui)',
              }}
              onMouseEnter={e => { if (!active) { e.currentTarget.style.color = 'var(--text-primary)'; e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; } }}
              onMouseLeave={e => { if (!active) { e.currentTarget.style.color = 'var(--text-secondary)'; e.currentTarget.style.background = 'transparent'; } }}
              >
                <Icon size={14} />
                {label}
              </Link>
            );
          })}
        </div>
      )}

      {/* Critical dot */}
      {!landing && hasCritical && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: 'var(--sev-critical)',
            boxShadow: '0 0 8px var(--sev-critical)',
            animation: 'pulse-soft 1.5s ease-in-out infinite',
          }} />
          <span style={{ fontSize: '10px', color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)', letterSpacing: '0.1em' }}>CRITICAL</span>
        </div>
      )}

      {/* Analyst avatar */}
      {!landing && analyst && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '4px 12px 4px 4px',
          background: 'rgba(255,107,0,0.06)',
          border: '1px solid rgba(255,107,0,0.15)',
          borderRadius: '20px',
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: '50%',
            background: 'linear-gradient(135deg, #FF6B00, #FF8C42)',
            boxShadow: '0 0 8px rgba(255,107,0,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '10px', fontWeight: 700, color: '#fff',
            fontFamily: 'var(--font-display)',
          }}>
            {analyst.avatar}
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            {analyst.name}
          </span>
        </div>
      )}

      {/* Landing CTA */}
      {landing && (
        <button
          onClick={() => navigate('/dashboard')}
          className="eclipse-btn-primary"
          style={{ padding: '9px 20px', fontSize: '13px', fontWeight: 600 }}
        >
          Launch Dashboard →
        </button>
      )}
    </nav>
  );
}