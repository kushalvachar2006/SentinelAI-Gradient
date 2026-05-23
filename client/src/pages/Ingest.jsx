import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileText, CheckCircle, X, AlertCircle, Zap } from 'lucide-react';
import Navbar from '../components/layout/Navbar';
import { useStore } from '../store/useStore';

const API = import.meta.env.VITE_API_URL || '';
const AUTH_HEADER = 'Bearer demo-token';
const FORMATS = ['Syslog', 'AWS CloudTrail', 'Custom JSON', 'CEF', 'LEEF'];

function ProgressBar({ percent, color }) {
  return (
    <div style={{ height: 4, background: 'rgba(255,107,0,0.08)', borderRadius: 2, overflow: 'hidden' }}>
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${percent}%` }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
        style={{
          height: '100%',
          background: color || 'linear-gradient(90deg, var(--eclipse), var(--solar))',
          borderRadius: 2,
          boxShadow: `0 0 8px ${color || 'rgba(255,107,0,0.5)'}`,
        }}
      />
    </div>
  );
}

export default function Ingest() {
  const navigate = useNavigate();
  const { loadDashboard } = useStore();
  const [dragging, setDragging] = useState(false);
  const [files, setFiles] = useState([]);
  const [format, setFormat] = useState('Syslog');
  const [stage, setStage] = useState('idle');
  const [jobResult, setJobResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const dropped = Array.from(e.dataTransfer?.files || []);
    if (dropped.length) setFiles(dropped);
  }, []);

  const handleFileInput = (e) => {
    const selected = Array.from(e.target.files || []);
    if (selected.length) setFiles(selected);
  };

  const handleAnalyse = async () => {
    if (!files[0]) return;
    setStage('uploading');
    const formData = new FormData();
    formData.append('logfile', files[0]);
    formData.append('source', format.toLowerCase().replace(' ', '_'));

    try {
      const res = await fetch(`${API}/api/logs/ingest`, {
        method: 'POST',
        headers: { 'Authorization': AUTH_HEADER },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Server error ${res.status}`);
      const { jobId } = data;
      setStage('processing');

      const poll = setInterval(async () => {
        try {
          const jobRes = await fetch(`${API}/api/logs/jobs/${jobId}`, {
            headers: { 'Authorization': AUTH_HEADER },
          });
          const job = await jobRes.json();
          if (job.status === 'completed') {
            clearInterval(poll);
            setJobResult(job);
            setStage('done');
          } else if (job.status === 'failed') {
            clearInterval(poll);
            setStage('error');
            setErrorMsg(job.errorMessage || 'Processing failed');
          }
        } catch (e) {
          clearInterval(poll);
          setStage('error');
          setErrorMsg(e.message);
        }
      }, 2000);
    } catch (err) {
      setStage('error');
      setErrorMsg(err.message);
    }
  };

  const handleViewDashboard = async () => {
    await loadDashboard();
    navigate('/dashboard');
  };

  const reset = () => { setStage('idle'); setFiles([]); setJobResult(null); setErrorMsg(''); };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-base)', paddingTop: '60px' }}>
      <Navbar />

      {/* Background */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 50% 40% at 50% 10%, rgba(255,107,0,0.04) 0%, transparent 60%)',
      }} />

      <div style={{ padding: '32px 28px', maxWidth: '860px', margin: '0 auto', position: 'relative', zIndex: 1 }}>
        <div style={{ marginBottom: '32px' }}>
          <div style={{ fontSize: '10px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)', letterSpacing: '0.15em', marginBottom: '10px' }}>◆ DATA INGESTION</div>
          <h1 style={{ fontSize: '26px', fontFamily: 'var(--font-display)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
            Log <span style={{ color: 'var(--eclipse)' }}>Ingestion</span>
          </h1>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.65 }}>Upload log files for AI-powered threat analysis and classification</p>
        </div>

        {/* Format selector */}
        <div style={{ marginBottom: '24px' }}>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '12px', fontFamily: 'var(--font-mono)' }}>
            Log Format
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {FORMATS.map(f => (
              <button key={f} onClick={() => setFormat(f)} style={{
                padding: '8px 16px', borderRadius: 'var(--radius-md)',
                border: `1px solid ${format === f ? 'rgba(255,107,0,0.35)' : 'rgba(255,107,0,0.1)'}`,
                background: format === f ? 'rgba(255,107,0,0.1)' : 'var(--bg-surface)',
                color: format === f ? 'var(--eclipse)' : 'var(--text-secondary)',
                fontSize: '13px', fontWeight: format === f ? 600 : 400,
                cursor: 'pointer', transition: 'all 0.2s',
                boxShadow: format === f ? '0 0 10px rgba(255,107,0,0.15)' : 'none',
                fontFamily: 'var(--font-mono)',
              }}>{f}</button>
            ))}
          </div>
        </div>

        {/* Drop zone */}
        {stage === 'idle' && (
          <motion.div
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
            onDragOver={e => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            style={{
              border: `2px dashed ${dragging ? 'var(--eclipse)' : files.length ? 'var(--sev-low)' : 'rgba(255,107,0,0.18)'}`,
              borderRadius: 'var(--radius-xl)', padding: '60px 24px',
              textAlign: 'center', cursor: 'pointer',
              background: dragging ? 'rgba(255,107,0,0.06)' : files.length ? 'rgba(0,208,132,0.03)' : 'var(--bg-surface)',
              transition: 'all 0.2s', marginBottom: '20px',
              boxShadow: dragging ? '0 0 30px rgba(255,107,0,0.1)' : 'none',
            }}
            onClick={() => !files.length && document.getElementById('file-input').click()}
          >
            <input id="file-input" type="file" multiple accept=".csv,.json,.log,.txt" style={{ display: 'none' }} onChange={handleFileInput} />

            {files.length > 0 ? (
              <div>
                <div style={{ width: 60, height: 60, borderRadius: '50%', background: 'rgba(0,208,132,0.1)', border: '2px solid var(--sev-low)', margin: '0 auto 20px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 20px rgba(0,208,132,0.2)' }}>
                  <CheckCircle size={28} color="var(--sev-low)" />
                </div>
                <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px', fontFamily: 'var(--font-ui)' }}>
                  {files[0].name}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '28px', fontFamily: 'var(--font-mono)' }}>
                  {(files[0].size / 1024).toFixed(1)} KB — {format}
                </div>
                <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleAnalyse(); }}
                    className="eclipse-btn-primary"
                    style={{ padding: '12px 28px', fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}
                  >
                    <Zap size={16} /> Analyse Logs
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); setFiles([]); }}
                    className="eclipse-btn-secondary"
                    style={{ padding: '12px 16px', fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <X size={14} /> Remove
                  </button>
                </div>
              </div>
            ) : (
              <div>
                <div style={{
                  width: 70, height: 70, borderRadius: '50%',
                  background: dragging ? 'rgba(255,107,0,0.12)' : 'rgba(255,107,0,0.06)',
                  border: `2px solid ${dragging ? 'var(--eclipse)' : 'rgba(255,107,0,0.2)'}`,
                  margin: '0 auto 24px',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 0.2s',
                  boxShadow: dragging ? '0 0 24px rgba(255,107,0,0.3)' : 'none',
                }}>
                  <Upload size={30} color={dragging ? 'var(--eclipse)' : 'var(--text-muted)'} />
                </div>
                <div style={{ fontSize: '16px', fontWeight: 600, color: dragging ? 'var(--eclipse)' : 'var(--text-primary)', marginBottom: '8px', fontFamily: 'var(--font-display)', letterSpacing: '0.03em', textTransform: 'uppercase' }}>
                  {dragging ? 'Drop files to analyze' : 'Drag & drop log files'}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '24px' }}>
                  Supports .csv, .json, .log, .txt — up to 2GB
                </div>
                <span className="eclipse-btn-secondary" style={{
                  display: 'inline-block',
                  padding: '9px 22px', fontSize: '13px', borderRadius: 'var(--radius-md)',
                  cursor: 'pointer',
                }}>
                  Or click to browse
                </span>
              </div>
            )}
          </motion.div>
        )}

        {/* Processing */}
        <AnimatePresence>
          {(stage === 'uploading' || stage === 'processing') && (
            <motion.div
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              style={{
                background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.12)',
                borderRadius: 'var(--radius-lg)', padding: '32px',
                boxShadow: 'var(--shadow-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '28px' }}>
                <div style={{
                  width: 44, height: 44, borderRadius: '50%',
                  background: 'rgba(255,107,0,0.1)', border: '1px solid rgba(255,107,0,0.2)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <FileText size={20} color="var(--eclipse)" />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-ui)' }}>{files[0]?.name}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {files[0]?.size ? `${(files[0].size / 1024).toFixed(1)} KB` : '—'} — {format}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {stage === 'uploading' ? 'Uploading log file...' : 'AI threat classification running...'}
                  </span>
                  <span style={{ fontSize: '12px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)', animation: 'glow-pulse 2s ease-in-out infinite' }}>
                    {stage === 'uploading' ? '45%' : 'ANALYZING'}
                  </span>
                </div>
                <ProgressBar percent={stage === 'uploading' ? 45 : 80} />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Done */}
        <AnimatePresence>
          {stage === 'done' && jobResult && (
            <motion.div
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
              style={{
                background: 'var(--bg-surface)', border: '1px solid rgba(0,208,132,0.15)',
                borderRadius: 'var(--radius-lg)', padding: '32px',
                boxShadow: '0 0 30px rgba(0,208,132,0.05), var(--shadow-card)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '24px' }}>
                <div style={{ width: 44, height: 44, borderRadius: '50%', background: 'rgba(0,208,132,0.1)', border: '1px solid rgba(0,208,132,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 12px rgba(0,208,132,0.2)' }}>
                  <CheckCircle size={22} color="var(--sev-low)" />
                </div>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--sev-low)' }}>Analysis Complete</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{files[0]?.name}</div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', marginBottom: '28px' }}>
                {[
                  { label: 'Lines Processed', value: jobResult.linesProcessed?.toLocaleString() || '—' },
                  { label: 'Threats Detected', value: jobResult.threatsDetected || '—' },
                ].map(({ label, value }) => (
                  <div key={label} style={{
                    flex: 1,
                    background: 'rgba(255,107,0,0.04)', border: '1px solid rgba(255,107,0,0.1)',
                    borderRadius: 'var(--radius-md)', padding: '16px 20px',
                  }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>{label}</div>
                    <div style={{ fontSize: '26px', fontFamily: 'var(--font-display)', fontWeight: 700, color: 'var(--eclipse)', textShadow: '0 0 20px rgba(255,107,0,0.4)' }}>{value}</div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <button onClick={handleViewDashboard} className="eclipse-btn-primary" style={{ padding: '12px 24px', fontSize: '14px', flex: 1 }}>
                  View in Dashboard →
                </button>
                <button onClick={reset} className="eclipse-btn-secondary" style={{ padding: '12px 20px', fontSize: '14px' }}>
                  Upload Another
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error */}
        <AnimatePresence>
          {stage === 'error' && (
            <motion.div
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
              style={{
                background: 'rgba(255,61,113,0.06)', border: '1px solid rgba(255,61,113,0.2)',
                borderRadius: 'var(--radius-lg)', padding: '20px 24px',
                display: 'flex', alignItems: 'center', gap: '14px',
              }}
            >
              <AlertCircle size={20} color="var(--sev-critical)" />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--sev-critical)', marginBottom: '2px' }}>Upload failed</div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{errorMsg}</div>
              </div>
              <button onClick={reset} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '4px' }}>
                <X size={16} />
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}