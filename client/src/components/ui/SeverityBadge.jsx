const SEVERITY_CONFIG = {
  CRITICAL: { bg: 'rgba(255,61,113,0.12)', color: '#FF3D71', border: 'rgba(255,61,113,0.3)', label: 'Critical', glow: 'rgba(255,61,113,0.3)' },
  HIGH:     { bg: 'rgba(255,107,0,0.12)',  color: '#FF6B00', border: 'rgba(255,107,0,0.3)',  label: 'High',     glow: 'rgba(255,107,0,0.3)' },
  MEDIUM:   { bg: 'rgba(255,209,102,0.10)', color: '#FFD166', border: 'rgba(255,209,102,0.3)', label: 'Medium', glow: 'rgba(255,209,102,0.25)' },
  LOW:      { bg: 'rgba(0,208,132,0.10)',  color: '#00D084', border: 'rgba(0,208,132,0.3)',  label: 'Low',      glow: 'rgba(0,208,132,0.25)' },
};

export function SeverityBadge({ severity }) {
  const s = SEVERITY_CONFIG[(severity || '').toUpperCase()] || SEVERITY_CONFIG.LOW;
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.border}`,
      fontSize: '10px',
      fontWeight: 700,
      padding: '3px 10px',
      borderRadius: '20px',
      display: 'inline-block',
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      fontFamily: 'var(--font-mono)',
      boxShadow: `0 0 8px ${s.glow}`,
    }}>
      {s.label}
    </span>
  );
}

export function PulseDot({ severity = 'CRITICAL' }) {
  const s = SEVERITY_CONFIG[(severity || '').toUpperCase()] || SEVERITY_CONFIG.LOW;
  return (
    <span style={{
      width: 8, height: 8,
      borderRadius: '50%',
      background: s.color,
      display: 'inline-block',
      boxShadow: `0 0 8px ${s.glow}`,
      animation: 'pulse-soft 2s ease-in-out infinite',
    }} />
  );
}

export function MetricCard({ label, count, severity }) {
  const s = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.LOW;
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border-dim)',
      borderRadius: 'var(--radius-lg)',
      padding: '20px 24px',
      flex: 1,
      minWidth: 0,
      position: 'relative',
      overflow: 'hidden',
      transition: 'all 0.3s',
    }}
    onMouseEnter={e => { e.currentTarget.style.borderColor = s.border; e.currentTarget.style.boxShadow = `0 0 24px ${s.glow}`; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-dim)'; e.currentTarget.style.boxShadow = 'none'; }}
    >
      {/* Top accent bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${s.color}, transparent)`,
      }} />
      {/* Background glow */}
      <div style={{
        position: 'absolute', top: 0, right: 0, width: 80, height: 80,
        background: `radial-gradient(circle, ${s.bg} 0%, transparent 70%)`,
        borderRadius: '50%', transform: 'translate(20px, -20px)',
      }} />
      <div style={{
        fontSize: '10px', color: 'var(--text-muted)',
        textTransform: 'uppercase', letterSpacing: '0.1em',
        marginBottom: '10px', fontFamily: 'var(--font-mono)',
      }}>
        {label}
      </div>
      <div style={{
        fontSize: '32px',
        fontFamily: 'var(--font-display)',
        fontWeight: 700,
        color: s.color,
        textShadow: `0 0 20px ${s.glow}`,
        lineHeight: 1,
      }}>
        {String(count).padStart(2, '0')}
      </div>
    </div>
  );
}