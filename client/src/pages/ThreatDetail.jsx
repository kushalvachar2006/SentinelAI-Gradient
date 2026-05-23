import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, Shield, Globe, AlertTriangle, CheckCircle, FileText, UserPlus, XCircle, Loader, RefreshCw, Zap } from 'lucide-react';
import Navbar from '../components/layout/Navbar';
import { SeverityBadge } from '../components/ui/SeverityBadge';

const API = import.meta.env.VITE_API_URL || '';
const AUTH_HEADERS = { 'Authorization': 'Bearer demo-token', 'Content-Type': 'application/json' };

function SkeletonBlock({ width = '100%', height = '16px' }) {
  return (
    <div style={{
      width, height,
      background: 'linear-gradient(90deg, rgba(255,107,0,0.04) 0%, rgba(255,107,0,0.08) 50%, rgba(255,107,0,0.04) 100%)',
      backgroundSize: '200% 100%',
      animation: 'shimmer 2s infinite',
      borderRadius: 'var(--radius-sm)',
    }} />
  );
}

function AttackTimeline({ steps }) {
  if (!steps?.length) return null;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0', overflowX: 'auto', padding: '20px 0' }}>
      {steps.map((step, i) => {
        const isFirst = i === 0;
        const stepColor = isFirst ? 'var(--sev-critical)' : i === steps.length - 1 ? 'var(--eclipse)' : 'var(--text-secondary)';
        return (
          <div key={step} style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: isFirst ? 'rgba(255,61,113,0.1)' : 'rgba(255,107,0,0.06)',
                border: `2px solid ${stepColor}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: stepColor,
                fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-display)',
                margin: '0 auto 10px',
                boxShadow: isFirst ? '0 0 12px rgba(255,61,113,0.3)' : '0 0 8px rgba(255,107,0,0.15)',
              }}>{i + 1}</div>
              <div style={{
                fontSize: '11px', color: stepColor,
                maxWidth: '90px', textAlign: 'center', fontFamily: 'var(--font-mono)',
                lineHeight: 1.4,
              }}>
                {step}
              </div>
            </div>
            {i < steps.length - 1 && (
              <div style={{ width: 56, height: 2, background: `linear-gradient(90deg, ${stepColor}, rgba(255,107,0,0.3))`, flexShrink: 0, margin: '0 0 26px' }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function ThreatDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [threat, setThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expertMode, setExpertMode] = useState(true);
  const [generatingAI, setGeneratingAI] = useState(false);

  const fetchThreat = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/threats/${id}`, { headers: AUTH_HEADERS });
      if (!res.ok) throw new Error('Threat not found');
      const data = await res.json();
      // API returns { threat, isSourceIPBlocked } — unwrap the threat object
      setThreat(data.threat || data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchThreat(); }, [id]);

  const generateAIExplanation = async () => {
    setGeneratingAI(true);
    try {
      await fetch(`${API}/api/threats/${id}/action`, {
        method: 'POST',
        headers: AUTH_HEADERS,
        body: JSON.stringify({ action: 'generate_explanation' }),
      });
      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        const res = await fetch(`${API}/api/threats/${id}`, { headers: AUTH_HEADERS });
        const data = await res.json();
        const t = data.threat || data;
        if (t.aiExplanation || attempts > 15) {
          clearInterval(poll);
          setThreat(t);
          setGeneratingAI(false);
        }
      }, 2000);
    } catch {
      setGeneratingAI(false);
    }
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-base)', paddingTop: '60px' }}>
        <Navbar />
        <div style={{ padding: '24px 28px', maxWidth: '1400px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <SkeletonBlock height="36px" width="280px" />
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '18px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {[1, 2, 3].map(i => <SkeletonBlock key={i} height="120px" />)}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {[1, 2].map(i => <SkeletonBlock key={i} height="150px" />)}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error || !threat) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-base)', paddingTop: '60px', display: 'flex', flexDirection: 'column' }}>
        <Navbar />
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '16px' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', fontFamily: 'var(--font-mono)' }}>{error || 'Threat not found'}</p>
          <button onClick={() => navigate('/dashboard')} className="eclipse-btn-secondary" style={{ padding: '9px 20px', fontSize: '14px' }}>
            ← Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  const sevColor = {
    CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)',
    MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)',
  }[(threat.severity || '').toUpperCase()] || 'var(--text-secondary)';

  const aiExplanation = threat.aiExplanation;
  const enrichment = threat.enrichment || {};
  const chain = threat.chain || threat.attackChain || [];
  const mitreTechniques = threat.mitreTechniques || threat.mitre || [];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-base)', paddingTop: '60px' }}>
      <Navbar />

      {/* Background */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none',
        background: `radial-gradient(ellipse 50% 40% at 50% 0%, ${sevColor}08 0%, transparent 60%)`,
      }} />

      {/* Top bar */}
      <div style={{
        padding: '14px 28px',
        borderBottom: '1px solid rgba(255,107,0,0.08)',
        display: 'flex', alignItems: 'center', gap: '16px',
        background: 'rgba(20,20,20,0.85)', backdropFilter: 'blur(12px)',
        position: 'relative', zIndex: 10,
      }}>
        <button onClick={() => navigate('/dashboard')} style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px',
          transition: 'color 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.color = 'var(--eclipse)'}
        onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
        >
          <ArrowLeft size={14} /> Dashboard
        </button>
        <div style={{ width: 1, height: 18, background: 'rgba(255,107,0,0.15)' }} />
        <SeverityBadge severity={threat.severity} />
        <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--text-primary)', fontFamily: 'var(--font-ui)' }}>
          {threat._id || threat.id} — {threat.eventType || threat.threatType?.replace(/_/g, " ")}
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="eclipse-btn-primary" style={{ padding: '8px 16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Shield size={13} /> Block IP
          </button>
          <button className="eclipse-btn-secondary" style={{ padding: '8px 16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <FileText size={13} /> Report
          </button>
          <button className="eclipse-btn-secondary" style={{ padding: '8px 16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <CheckCircle size={13} /> Resolve
          </button>
        </div>
      </div>

      <div style={{ padding: '24px 28px', display: 'grid', gridTemplateColumns: '1fr 380px', gap: '18px', maxWidth: '1400px', position: 'relative', zIndex: 1 }}>
        {/* LEFT */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>

          {/* Attack Timeline */}
          {chain.length > 0 && (
            <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.1)', borderRadius: 'var(--radius-lg)', padding: '22px', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ fontSize: '10px', color: 'var(--eclipse)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>◆ Attack Timeline</div>
              <AttackTimeline steps={chain} />
            </div>
          )}

          {/* IP Enrichment */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.1)', borderRadius: 'var(--radius-lg)', padding: '22px', boxShadow: 'var(--shadow-card)' }}>
            <div style={{ fontSize: '10px', color: 'var(--eclipse)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '18px', fontFamily: 'var(--font-mono)' }}>
              ◆ IP Enrichment — {threat.sourceIP || threat.sourceIp}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
              {[
                { label: 'Country', value: enrichment?.geoIP?.country || enrichment?.geo?.country || threat.country || '—' },
                { label: 'City', value: enrichment?.geoIP?.city || enrichment?.geo?.city || "—" || '—' },
                { label: 'ASN', value: enrichment?.geoIP?.asn || threat.asn || '—' },
                { label: 'AbuseIPDB', value: enrichment?.abuseIPDB?.abuseConfidenceScore != null ? `${enrichment.abuseIPDB.abuseConfidenceScore}/100` : "—", color: (enrichment?.abuseIPDB?.abuseConfidenceScore || 0) > 70 ? 'var(--sev-critical)' : undefined },
                { label: 'VirusTotal', value: enrichment?.virusTotal?.malicious != null ? `${enrichment.virusTotal.malicious} malicious` : "—", color: (enrichment?.virusTotal?.malicious || 0) > 20 ? 'var(--sev-critical)' : undefined },
                { label: 'Risk Score', value: `${threat.riskScore || '—'}/100`, color: sevColor },
                { label: 'Target', value: threat.targetAsset || threat.targetAsset || threat.target || '—' },
                { label: 'Event Type', value: threat.eventType || threat.threatType?.replace(/_/g, " ") || '—' },
              ].map(({ label, value, color }) => (
                <div key={label} style={{
                  background: 'rgba(255,107,0,0.04)', border: '1px solid rgba(255,107,0,0.08)',
                  borderRadius: 'var(--radius-md)', padding: '12px',
                  transition: 'all 0.2s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,107,0,0.2)'; e.currentTarget.style.background = 'rgba(255,107,0,0.07)'; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,107,0,0.08)'; e.currentTarget.style.background = 'rgba(255,107,0,0.04)'; }}
                >
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '6px', fontFamily: 'var(--font-mono)' }}>{label}</div>
                  <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: color || 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{String(value)}</div>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE Tags */}
          {mitreTechniques.length > 0 && (
            <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.1)', borderRadius: 'var(--radius-lg)', padding: '22px', boxShadow: 'var(--shadow-card)' }}>
              <div style={{ fontSize: '10px', color: 'var(--eclipse)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '14px', fontFamily: 'var(--font-mono)' }}>◆ MITRE ATT&CK Techniques</div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {mitreTechniques.map(tag => (
                  <div key={tag} style={{
                    padding: '7px 16px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(255,107,0,0.08)', border: '1px solid rgba(255,107,0,0.2)',
                    color: 'var(--solar)', fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '12px',
                    boxShadow: '0 0 10px rgba(255,107,0,0.1)',
                  }}>
                    {tag}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>

          {/* AI Explanation */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.12)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', boxShadow: 'var(--shadow-card)' }}>
            <div style={{
              padding: '16px 20px', borderBottom: '1px solid rgba(255,107,0,0.08)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              background: 'rgba(255,107,0,0.03)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Zap size={14} color="var(--eclipse)" />
                <span style={{ fontSize: '11px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)', letterSpacing: '0.1em' }}>AI ANALYSIS</span>
              </div>
              {aiExplanation && (
                <div style={{ display: 'flex', background: 'rgba(255,107,0,0.08)', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(255,107,0,0.15)', overflow: 'hidden' }}>
                  {[['Expert', true], ['Plain', false]].map(([label, val]) => (
                    <button key={String(val)} onClick={() => setExpertMode(val)}
                      style={{
                        padding: '4px 12px', border: 'none',
                        background: expertMode === val ? 'rgba(255,107,0,0.2)' : 'transparent',
                        color: expertMode === val ? 'var(--eclipse)' : 'var(--text-muted)',
                        fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >{label}</button>
                  ))}
                </div>
              )}
            </div>
            <div style={{ padding: '18px 20px' }}>
              <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', alignItems: 'center' }}>
                <div style={{
                  width: 30, height: 30, borderRadius: '50%',
                  background: 'radial-gradient(circle at 35% 35%, #FF8C42, #FF6B00)',
                  boxShadow: '0 0 10px rgba(255,107,0,0.35)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <Zap size={13} color="#fff" />
                </div>
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--eclipse)', fontWeight: 700, fontFamily: 'var(--font-display)', letterSpacing: '0.05em' }}>SENTINEL</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>AI Security Analyst</div>
                </div>
              </div>

              {aiExplanation ? (
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.75 }}>
                  {expertMode
                    ? (aiExplanation.what_happened || aiExplanation.summary)
                    : (aiExplanation.eli5_version || aiExplanation.summary)
                  }
                </p>
              ) : (
                <div>
                  <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: 1.65 }}>
                    AI explanation not yet generated for this incident.
                  </p>
                  <button
                    onClick={generateAIExplanation}
                    disabled={generatingAI}
                    className="eclipse-btn-primary"
                    style={{
                      padding: '10px 18px', fontSize: '13px',
                      display: 'flex', alignItems: 'center', gap: '8px',
                      opacity: generatingAI ? 0.7 : 1,
                      cursor: generatingAI ? 'wait' : 'pointer',
                    }}
                  >
                    {generatingAI ? (
                      <><Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> Generating...</>
                    ) : (
                      <><Zap size={13} /> Generate AI Explanation</>
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Actions */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.1)', borderRadius: 'var(--radius-lg)', padding: '20px', boxShadow: 'var(--shadow-card)' }}>
            <div style={{ fontSize: '10px', color: 'var(--eclipse)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '14px', fontFamily: 'var(--font-mono)' }}>◆ Actions</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { label: 'Block IP on Firewall', icon: Shield, style: 'primary' },
                { label: 'Assign to Analyst', icon: UserPlus, style: 'secondary' },
                { label: 'Mark Resolved', icon: CheckCircle, color: 'var(--sev-low)', border: 'rgba(0,208,132,0.2)', bg: 'rgba(0,208,132,0.06)' },
                { label: 'Mark as False Positive', icon: XCircle, color: 'var(--text-muted)', border: 'rgba(255,255,255,0.06)', bg: 'transparent' },
              ].map(({ label, icon: Icon, style: s, color, border, bg }) => (
                <button key={label}
                  className={s === 'primary' ? 'eclipse-btn-primary' : s === 'secondary' ? 'eclipse-btn-secondary' : ''}
                  style={{
                    padding: '10px 16px', borderRadius: 'var(--radius-md)',
                    fontSize: '13px', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 500,
                    ...(s ? {} : {
                      background: bg, border: `1px solid ${border}`, color,
                    }),
                    width: '100%',
                  }}
                >
                  <Icon size={14} /> {label}
                </button>
              ))}
            </div>
          </div>

          {/* Metadata */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.1)', borderRadius: 'var(--radius-lg)', padding: '20px', boxShadow: 'var(--shadow-card)' }}>
            <div style={{ fontSize: '10px', color: 'var(--eclipse)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: '14px', fontFamily: 'var(--font-mono)' }}>◆ Incident Metadata</div>
            {[
              { label: 'Incident ID', value: threat._id || threat.id || '—' },
              { label: 'Detection Method', value: threat.detectionMethod || 'AI — Behavioral' },
              { label: 'Source IP', value: threat.sourceIP || threat.sourceIp || '—' },
              { label: 'Target', value: threat.targetAsset || threat.targetAsset || threat.target || '—' },
            ].map(({ label, value }) => (
              <div key={label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '8px 0', borderBottom: '1px solid rgba(255,107,0,0.06)',
                fontSize: '13px',
              }}>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{label}</span>
                <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500, fontSize: '12px', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}