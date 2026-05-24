import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, ChevronRight, Zap } from 'lucide-react';
import Navbar from '../components/layout/Navbar';

const API = import.meta.env.VITE_API_URL || '';

const SUGGESTED = [
  'Show brute force in last 24h',
  'Which IPs are repeat offenders?',
  'Summarize critical alerts today',
  'List all MITRE T1190 matches',
  'Which assets are most targeted?',
];

// Lightweight markdown → JSX renderer (no external library needed)
function MarkdownContent({ text }) {
  if (!text) return null;

  const lines = text.split('\n');
  const elements = [];
  let i = 0;
  let keyCounter = 0;
  const key = () => keyCounter++;

  while (i < lines.length) {
    const line = lines[i];

    // Code block
    if (line.startsWith('```')) {
      const codeLines = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <pre key={key()} style={{
          background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,107,0,0.15)',
          borderRadius: '6px', padding: '12px 14px', overflowX: 'auto',
          fontFamily: 'var(--font-mono)', fontSize: '12px',
          color: 'var(--eclipse)', margin: '10px 0', lineHeight: 1.6,
        }}>
          <code>{codeLines.join('\n')}</code>
        </pre>
      );
      i++;
      continue;
    }

    // Heading ## or ###
    if (line.startsWith('### ')) {
      elements.push(
        <div key={key()} style={{ fontSize: '13px', fontWeight: 700, color: 'var(--eclipse)', margin: '12px 0 4px', fontFamily: 'var(--font-display)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {renderInline(line.slice(4))}
        </div>
      );
      i++; continue;
    }
    if (line.startsWith('## ')) {
      elements.push(
        <div key={key()} style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', margin: '14px 0 6px', borderBottom: '1px solid rgba(255,107,0,0.12)', paddingBottom: '4px' }}>
          {renderInline(line.slice(3))}
        </div>
      );
      i++; continue;
    }
    if (line.startsWith('# ')) {
      elements.push(
        <div key={key()} style={{ fontSize: '16px', fontWeight: 700, color: 'var(--eclipse)', margin: '14px 0 6px' }}>
          {renderInline(line.slice(2))}
        </div>
      );
      i++; continue;
    }

    // Horizontal rule
    if (line.match(/^[-*]{3,}$/)) {
      elements.push(<hr key={key()} style={{ border: 'none', borderTop: '1px solid rgba(255,107,0,0.12)', margin: '12px 0' }} />);
      i++; continue;
    }

    // Bullet list
    if (line.match(/^[-*+] /) || line.match(/^\d+\. /)) {
      const listItems = [];
      const isOrdered = line.match(/^\d+\. /);
      while (i < lines.length && (lines[i].match(/^[-*+] /) || lines[i].match(/^\d+\. /))) {
        const content = lines[i].replace(/^[-*+] /, '').replace(/^\d+\. /, '');
        listItems.push(
          <li key={key()} style={{ marginBottom: '4px', paddingLeft: '4px' }}>
            {renderInline(content)}
          </li>
        );
        i++;
      }
      const ListTag = isOrdered ? 'ol' : 'ul';
      elements.push(
        <ListTag key={key()} style={{
          margin: '8px 0', paddingLeft: '20px',
          color: 'var(--text-primary)', fontSize: '14px', lineHeight: 1.7,
        }}>
          {listItems}
        </ListTag>
      );
      continue;
    }

    // Blockquote
    if (line.startsWith('> ')) {
      elements.push(
        <div key={key()} style={{
          borderLeft: '3px solid var(--eclipse)', paddingLeft: '12px',
          margin: '8px 0', color: 'var(--text-secondary)', fontStyle: 'italic',
        }}>
          {renderInline(line.slice(2))}
        </div>
      );
      i++; continue;
    }

    // Empty line → spacer
    if (line.trim() === '') {
      elements.push(<div key={key()} style={{ height: '6px' }} />);
      i++; continue;
    }

    // Normal paragraph
    elements.push(
      <p key={key()} style={{ margin: '0 0 4px', lineHeight: 1.75, color: 'var(--text-primary)', fontSize: '14px' }}>
        {renderInline(line)}
      </p>
    );
    i++;
  }

  return <div>{elements}</div>;
}

function renderInline(text) {
  // Split on bold/italic/inline-code/links patterns
  const parts = [];
  const pattern = /(\*\*(.+?)\*\*|__(.+?)__|`([^`]+)`|\*(.+?)\*|_(.+?)_|\[(.+?)\]\((.+?)\))/g;
  let last = 0;
  let match;
  let idx = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(<span key={idx++}>{text.slice(last, match.index)}</span>);
    }
    if (match[2] || match[3]) {
      // Bold
      parts.push(<strong key={idx++} style={{ color: 'var(--text-primary)', fontWeight: 700 }}>{match[2] || match[3]}</strong>);
    } else if (match[4]) {
      // Inline code
      parts.push(
        <code key={idx++} style={{
          background: 'rgba(255,107,0,0.12)', border: '1px solid rgba(255,107,0,0.2)',
          borderRadius: '4px', padding: '1px 6px', fontFamily: 'var(--font-mono)',
          fontSize: '12px', color: 'var(--eclipse)',
        }}>{match[4]}</code>
      );
    } else if (match[5] || match[6]) {
      // Italic
      parts.push(<em key={idx++} style={{ color: 'var(--text-secondary)' }}>{match[5] || match[6]}</em>);
    } else if (match[7] && match[8]) {
      // Link
      parts.push(
        <a key={idx++} href={match[8]} target="_blank" rel="noopener noreferrer"
          style={{ color: 'var(--eclipse)', textDecoration: 'underline' }}>
          {match[7]}
        </a>
      );
    }
    last = pattern.lastIndex;
  }
  if (last < text.length) {
    parts.push(<span key={idx++}>{text.slice(last)}</span>);
  }
  return parts.length ? parts : text;
}

function TypingIndicator() {
  return (
    <div style={{ display: 'flex', gap: '5px', padding: '4px 0', alignItems: 'center' }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          width: 6, height: 6, borderRadius: '50%',
          background: 'var(--eclipse)',
          boxShadow: '0 0 6px rgba(255,107,0,0.5)',
          animation: 'pulse-soft 1.2s ease-in-out infinite',
          animationDelay: `${i * 0.2}s`,
        }} />
      ))}
    </div>
  );
}

export default function Chat() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: `SentinelAI online. I'm your SOC assistant — ask me anything about your threat feed, attack patterns, or incident investigation.`,
      done: true,
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const endRef = useRef();

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async (query) => {
    const q = query || input.trim();
    if (!q || loading) return;
    setInput('');

    const userMsg = { role: 'user', content: q, done: true };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    try {
      const res = await fetch(`${API}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer demo-token' },
        body: JSON.stringify({
          message: q,
          conversationHistory: messages.slice(-6).map(m => ({ role: m.role, content: m.content })),
        }),
      });
      const data = await res.json();
      const answer = data.answer || data.error || 'No response';
      setMessages(prev => [...prev, { role: 'assistant', content: answer, done: true }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: `Error: ${err.message}`, done: true }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-base)', paddingTop: '60px' }}>
      <Navbar />

      {/* Background */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 60% 50% at 50% 0%, rgba(255,107,0,0.04) 0%, transparent 60%)',
      }} />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative', zIndex: 1 }}>
        {/* Sidebar */}
        <div style={{
          width: '220px',
          borderRight: '1px solid rgba(255,107,0,0.08)',
          background: 'var(--bg-surface)',
          display: 'flex', flexDirection: 'column',
          padding: '20px 0', flexShrink: 0,
        }}>
          {/* AI Identity */}
          <div style={{ padding: '0 18px 20px', borderBottom: '1px solid rgba(255,107,0,0.08)', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: 'radial-gradient(circle at 35% 35%, #FF8C42, #FF6B00)',
                boxShadow: '0 0 12px rgba(255,107,0,0.4)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Zap size={16} color="#fff" />
              </div>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-display)', letterSpacing: '0.05em' }}>SENTINEL</div>
                <div style={{ fontSize: '10px', color: 'var(--eclipse)', fontFamily: 'var(--font-mono)' }}>AI Analyst v2.4</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--sev-low)', boxShadow: '0 0 6px var(--sev-low)', animation: 'pulse-soft 2s ease-in-out infinite' }} />
              <span style={{ fontSize: '10px', color: 'var(--sev-low)', fontFamily: 'var(--font-mono)' }}>ONLINE</span>
            </div>
          </div>

          <div style={{ padding: '0 18px 12px', fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>
            Suggested Queries
          </div>
          {SUGGESTED.map(q => (
            <button
              key={q}
              onClick={() => sendMessage(q)}
              style={{
                width: '100%', padding: '10px 18px',
                background: 'none', border: 'none',
                textAlign: 'left', fontSize: '12px',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '8px',
                transition: 'all 0.15s',
                borderLeft: '2px solid transparent',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.background = 'rgba(255,107,0,0.05)';
                e.currentTarget.style.color = 'var(--text-primary)';
                e.currentTarget.style.borderLeftColor = 'var(--eclipse)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.background = 'none';
                e.currentTarget.style.color = 'var(--text-secondary)';
                e.currentTarget.style.borderLeftColor = 'transparent';
              }}
            >
              <ChevronRight size={12} style={{ color: 'var(--eclipse)', flexShrink: 0 }} />
              {q}
            </button>
          ))}
        </div>

        {/* Chat area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <AnimatePresence initial={false}>
              {messages.map((msg, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25 }}
                  style={{
                    display: 'flex',
                    flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                    gap: '12px', alignItems: 'flex-start',
                  }}
                >
                  {/* Avatar */}
                  {msg.role === 'assistant' && (
                    <div style={{
                      width: 34, height: 34, borderRadius: '50%', flexShrink: 0,
                      background: 'radial-gradient(circle at 35% 35%, #FF8C42, #FF6B00)',
                      boxShadow: '0 0 10px rgba(255,107,0,0.35)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <Zap size={14} color="#fff" />
                    </div>
                  )}
                  <div style={{
                    maxWidth: '70%',
                    padding: '14px 18px',
                    borderRadius: msg.role === 'user' ? '18px 18px 4px 18px' : '4px 18px 18px 18px',
                    background: msg.role === 'user'
                      ? 'linear-gradient(135deg, rgba(255,107,0,0.18), rgba(255,140,66,0.12))'
                      : 'var(--bg-surface)',
                    border: msg.role === 'user'
                      ? '1px solid rgba(255,107,0,0.25)'
                      : '1px solid rgba(255,107,0,0.08)',
                    color: 'var(--text-primary)',
                    lineHeight: 1.7,
                    boxShadow: msg.role === 'user' ? '0 0 20px rgba(255,107,0,0.08)' : '0 2px 12px rgba(0,0,0,0.3)',
                  }}>
                    {msg.role === 'user' ? (
                      <span style={{ fontSize: '14px' }}>{msg.content}</span>
                    ) : (
                      <MarkdownContent text={msg.content} />
                    )}
                  </div>
                </motion.div>
              ))}
              {loading && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                  <div style={{
                    width: 34, height: 34, borderRadius: '50%',
                    background: 'radial-gradient(circle at 35% 35%, #FF8C42, #FF6B00)',
                    boxShadow: '0 0 10px rgba(255,107,0,0.35)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <Zap size={14} color="#fff" />
                  </div>
                  <div style={{
                    padding: '14px 18px', borderRadius: '4px 18px 18px 18px',
                    background: 'var(--bg-surface)', border: '1px solid rgba(255,107,0,0.08)',
                  }}>
                    <TypingIndicator />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
            <div ref={endRef} />
          </div>

          {/* Input */}
          <div style={{
            padding: '20px 32px',
            borderTop: '1px solid rgba(255,107,0,0.08)',
            background: 'rgba(20,20,20,0.8)',
            backdropFilter: 'blur(12px)',
          }}>
            <div style={{
              display: 'flex', gap: '12px', alignItems: 'center',
              background: 'var(--bg-surface)',
              border: '1px solid rgba(255,107,0,0.15)',
              borderRadius: 'var(--radius-lg)',
              padding: '12px 16px',
              boxShadow: '0 0 20px rgba(255,107,0,0.05)',
              transition: 'border-color 0.2s',
            }}
            onFocus={e => e.currentTarget.style.borderColor = 'rgba(255,107,0,0.35)'}
            onBlur={e => e.currentTarget.style.borderColor = 'rgba(255,107,0,0.15)'}
            >
              <textarea
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                placeholder="Ask about threats, IPs, attack patterns..."
                rows={1}
                style={{
                  flex: 1, background: 'none', border: 'none', outline: 'none',
                  color: 'var(--text-primary)', fontSize: '14px',
                  fontFamily: 'var(--font-ui)', resize: 'none', lineHeight: 1.5,
                  maxHeight: '120px', overflowY: 'auto',
                }}
              />
              <button
                onClick={() => sendMessage()}
                disabled={!input.trim() || loading}
                className="eclipse-btn-primary"
                style={{
                  padding: '9px 18px', fontSize: '13px',
                  display: 'flex', alignItems: 'center', gap: '6px',
                  flexShrink: 0,
                  opacity: (!input.trim() || loading) ? 0.4 : 1,
                  cursor: (!input.trim() || loading) ? 'not-allowed' : 'pointer',
                }}
              >
                <Send size={14} /> Send
              </button>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
              Enter to send · Shift+Enter for new line
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}