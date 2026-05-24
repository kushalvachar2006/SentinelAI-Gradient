import { motion, AnimatePresence } from 'framer-motion';
import { X, Shield, AlertTriangle, UserPlus, XCircle, Loader, ExternalLink } from 'lucide-react';
import { useStore } from '../../store/useStore';
import { SeverityBadge } from '../ui/SeverityBadge';
import { format } from 'date-fns';
import { useNavigate } from 'react-router-dom';

export default function SlideOver() {
  const { slideOverOpen, selectedThreat: t, closeSlideOver, dismissThreat } = useStore();
  const navigate = useNavigate();

  const aiSummary = t?.aiExplanation?.summary || t?.explanation || null;
  const aiEli5 = t?.aiExplanation?.eli5_version || null;

  const sevColor = {
    CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)',
    MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)',
  }[(t?.severity || '').toUpperCase()] || 'var(--eclipse)';

  return (
    <AnimatePresence>
      {slideOverOpen && t && (
        <>
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={closeSlideOver}
            style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 200, backdropFilter: 'blur(4px)' }}
          />
          <motion.div
            initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
            transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
            style={{
              position: 'fixed', top: 0, right: 0, bottom: 0, width: '500px',
              background: 'var(--bg-surface)',
              borderLeft: `1px solid ${sevColor}30`,
              zIndex: 201, overflow: 'auto', display: 'flex', flexDirection: 'column',
              boxShadow: `-8px 0 40px rgba(0,0,0,0.6), -1px 0 0 ${sevColor}20`,
            }}
          >
            {/* Severity top bar */}
            <div style={{ height: 3, background: `linear-gradient(90deg, transparent, ${sevColor}, transparent)` }} />

            {/* Header */}
            <div style={{
              padding: '22px 26px',
              borderBottom: '1px solid rgba(255,107,0,0.08)',
              display: 'flex', alignItems: 'center', gap: '14px',
            }}>
              <SeverityBadge severity={t.severity} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '3px', fontFamily: 'var(--font-mono)' }}>
                  {t._id || t.id}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{(t.threatType || t.eventType || "—").replace(/_/g, " ")}</div>
              </div>
              <button onClick={() => navigate(`/threat/${t._id || t.id}`)} style={{
                background: 'rgba(255,107,0,0.08)', border: '1px solid rgba(255,107,0,0.2)',
                color: 'var(--eclipse)', padding: '6px 12px', borderRadius: 'var(--radius-sm)',
                fontSize: '11px', fontFamily: 'var(--font-mono)', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '4px',
              }}>
                <ExternalLink size={11} /> FULL
              </button>
              <button onClick={closeSlideOver} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '4px', display: 'flex' }}>
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '22px 26px', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Meta grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                {[
                  { label: 'Source IP', value: t.sourceIP || t.sourceIp },
                  { label: 'Target', value: t.targetAsset || t.target },
                  { label: 'Risk Score', value: `${t.riskScore}/100` },
                  { label: 'Country', value: t.enrichment?.geoIP?.country || t.enrichment?.geo?.country || t.country || '—' },
                  { label: 'Detected', value: t.timestamp ? format(new Date(t.timestamp), 'HH:mm:ss') : '—' },
                  { label: 'MITRE', value: t.mitreTechniques?.[0]?.tacticName || t.mitreTactic || t.mitreTag || '—' },
                ].map(({ label, value }) => (
                  <div key={label} style={{
                    padding: '12px 14px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(255,107,0,0.04)', border: '1px solid rgba(255,107,0,0.08)',
                  }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>{label}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{value || '—'}</div>
                  </div>
                ))}
              </div>

              {/* AI Summary */}
              {aiSummary && (
                <div style={{
                  padding: '16px',
                  background: 'rgba(255,107,0,0.06)',
                  border: '1px solid rgba(255,107,0,0.2)',
                  borderRadius: 'var(--radius-md)',
                }}>
                  <div style={{ fontSize: '10px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)', letterSpacing: '0.1em', marginBottom: '10px' }}>
                    ◆ AI ANALYSIS
                  </div>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>{aiSummary}</p>
                </div>
              )}

              {aiEli5 && (
                <div style={{
                  padding: '16px',
                  background: 'rgba(0,208,132,0.04)',
                  border: '1px solid rgba(0,208,132,0.15)',
                  borderRadius: 'var(--radius-md)',
                }}>
                  <div style={{ fontSize: '10px', color: 'var(--sev-low)', fontFamily: 'var(--font-mono)', letterSpacing: '0.1em', marginBottom: '10px' }}>
                    ◆ SIMPLE EXPLANATION
                  </div>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>{aiEli5}</p>
                </div>
              )}

              {/* Actions */}
              <div style={{ display: 'flex', gap: '10px', marginTop: 'auto', paddingTop: '8px' }}>
                <button
                  onClick={() => navigate(`/threat/${t._id || t.id}`)}
                  className="eclipse-btn-primary"
                  style={{ flex: 1, padding: '11px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                >
                  <Shield size={14} /> Investigate
                </button>
                <button
                  onClick={() => { dismissThreat(t._id || t.id); closeSlideOver(); }}
                  className="eclipse-btn-secondary"
                  style={{ flex: 1, padding: '11px', fontSize: '13px' }}
                >
                  Dismiss
                </button>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}