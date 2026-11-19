import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { runFullScan } from '../api/scanner';
import ScanProgress from '../components/ScanProgress';

const QUICK_TARGETS = [
  'https://httpbin.org',
  'https://example.com',
  'https://testphp.vulnweb.com',
];

const WHY_CHOOSE = [
  {
    icon: '⚡',
    title: 'AI-Powered Threat Detection',
    desc: 'Autonomous correlation engine driven by Groq 120B and Gemini LLMs to uncover high-impact attack chains and business logic risks.',
    action: 'Autonomous Reasoning ➔'
  },
  {
    icon: '🛡️',
    title: 'Seamless, Invisible Auditing',
    desc: 'Non-disruptive reconnaissance scanning covering multi-threaded socket discovery, TLS hygiene, and OWASP baseline protections.',
    action: 'Deep Target Inspection ➔'
  },
  {
    icon: '📊',
    title: 'Scalable & Adaptive Defense',
    desc: 'Automated executive PDF compliance reports, risk scoring algorithms, and instant prioritized remediation roadmaps.',
    action: 'Instant PDF Reports ➔'
  }
];

const CAPABILITIES = [
  { icon: '🔍', title: 'Target Reconnaissance', desc: 'Authoritative DNS records, nameservers & WHOIS registration footprint' },
  { icon: '🔌', title: 'Fast Socket Port Discovery', desc: 'Ultra-low latency multi-threaded socket discovery across top services' },
  { icon: '🛡️', title: 'Security Headers Audit', desc: 'Deep validation of CSP, HSTS, X-Frame-Options, Permissions-Policy' },
  { icon: '🍪', title: 'Session & Cookie Analysis', desc: 'Audit Secure, HttpOnly, SameSite attributes to prevent session hijacking' },
  { icon: '🔒', title: 'SSL/TLS Cryptography', desc: 'Certificate chain validity, expiration horizon, and cipher protocol checks' },
  { icon: '💉', title: 'SQL Injection Testing', desc: 'Automated lab-safe active vulnerability probing for SQL syntax errors' },
  { icon: '⚡', title: 'Cross-Site Scripting (XSS)', desc: 'Reflected and DOM-based vector testing in authorized testbeds' },
  { icon: '🤖', title: 'Executive AI Analyst', desc: 'Live LLM-synthesized executive briefs with prioritized remediation steps' },
];

const STAGE_NAMES = [
  'Connecting to target...',
  'Scanning security headers...',
  'Analyzing SSL/TLS certificate...',
  'Checking cookies...',
  'Running port discovery...',
  'DNS & WHOIS lookup...',
  'Technology detection...',
  'AI analysis & risk scoring...',
];

export default function Home() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [stages, setStages] = useState([]);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    let target = url.trim();
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
    }

    setError('');
    setScanning(true);

    const initialStages = STAGE_NAMES.map((name, i) => ({
      name,
      status: i === 0 ? 'running' : 'pending',
    }));
    setStages(initialStages);

    // Fast-advancing visual timeline for responsive feedback
    const intervals = [
      setTimeout(() => advanceStage(1), 150),
      setTimeout(() => advanceStage(2), 350),
      setTimeout(() => advanceStage(3), 550),
      setTimeout(() => advanceStage(4), 850),
      setTimeout(() => advanceStage(5), 1150),
      setTimeout(() => advanceStage(6), 1450),
      setTimeout(() => advanceStage(7), 1750),
    ];

    function advanceStage(targetIdx) {
      setStages((prev) =>
        prev.map((s, idx) => {
          if (idx < targetIdx) return { ...s, status: 'completed' };
          if (idx === targetIdx) return { ...s, status: 'running' };
          return s;
        })
      );
    }

    try {
      const response = await runFullScan(target);
      const payload = response.data || response;

      intervals.forEach(clearTimeout);
      setStages((prev) => prev.map((s) => ({ ...s, status: 'completed' })));

      setTimeout(() => {
        navigate('/results', { state: { data: payload, url: target } });
      }, 400);
    } catch (err) {
      intervals.forEach(clearTimeout);
      setScanning(false);
      setStages([]);
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Scan failed. Check the URL and server connection.'
      );
    }
  };

  return (
    <main className="app-layout">
      <div className="grid-bg" />
      <div className="container">
        {/* Eyeshield Hero Section */}
        <section className="hero">
          <div className="hero-badge">
            <span className="hero-badge-dot"></span>
            ✦ AI-POWERED CYBERSECURITY PLATFORM
          </div>
          <h1 className="hero-title">
            AI-Powered Cybersecurity,<br />
            <span className="gradient-text">Invisible Protection.</span>
          </h1>
          <p className="hero-subtitle">
            Next-generation automated penetration testing and threat intelligence. Scan target infrastructure
            for critical misconfigurations, weak headers, open attack vectors, and exploit risks with real-time AI reasoning.
          </p>

          {/* Scan Console */}
          <div className="scan-form-container">
            {!scanning ? (
              <div className="glass-card scan-form">
                <div className="form-header-bar">
                  <span className="form-label-title">🎯 TARGET HOST OR DOMAIN</span>
                  <span className="form-status-tag">REAL-TIME DUAL-LLM ENGINE</span>
                </div>
                <form onSubmit={handleScan}>
                  <div className="input-wrapper">
                    <span className="input-icon">🌐</span>
                    <input
                      className="target-input"
                      type="text"
                      placeholder="https://target.example.com"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      disabled={scanning}
                    />
                    <button className="scan-btn" type="submit" disabled={scanning || !url.trim()}>
                      <span>Start Assessment</span>
                      <span className="btn-arrow">➔</span>
                    </button>
                  </div>
                </form>

                <div className="quick-targets">
                  <span className="quick-label">⚡ Fast Audit:</span>
                  {QUICK_TARGETS.map((t) => (
                    <button key={t} className="quick-btn" type="button" onClick={() => setUrl(t)}>
                      {t.replace('https://', '').replace('http://', '')}
                    </button>
                  ))}
                </div>

                {error && (
                  <div className="error-banner">
                    <span>⚠️</span> {error}
                  </div>
                )}
              </div>
            ) : (
              <ScanProgress stages={stages} target={url} />
            )}
          </div>
        </section>

        {/* "Why Choose EYESHIELD?" Section */}
        <section id="why-eyeshield" className="why-section">
          <div className="section-header-centered">
            <div className="section-eyebrow">INTELLIGENT DEFENSE ARCHITECTURE</div>
            <h2 className="section-title">
              Why Choose <span className="gradient-text">EYESHIELD?</span>
            </h2>
            <div className="section-divider"></div>
            <p className="section-desc">
              Engineered for security teams and developers needing instant, accurate vulnerability assessments without operational friction.
            </p>
          </div>

          <div className="why-grid">
            {WHY_CHOOSE.map((item) => (
              <div key={item.title} className="glass-card why-card">
                <div className="why-icon-circle">
                  <span>{item.icon}</span>
                </div>
                <h3 className="why-title">{item.title}</h3>
                <p className="why-desc">{item.desc}</p>
                <div className="why-action-link">{item.action}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Deep Capabilities Grid */}
        <section id="capabilities" className="capabilities-section">
          <div className="section-header-centered">
            <div className="section-eyebrow">COMPREHENSIVE AUDIT MODULES</div>
            <h2 className="section-title">Deep Security Capabilities</h2>
            <div className="section-divider"></div>
            <p className="section-desc">
              Eight dedicated testing vectors inspect your surface area from socket connections to application headers.
            </p>
          </div>

          <div className="features-grid">
            {CAPABILITIES.map((f) => (
              <div key={f.title} className="glass-card feature-card">
                <div className="feature-icon">{f.icon}</div>
                <div className="feature-title">{f.title}</div>
                <div className="feature-desc">{f.desc}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Bottom Banner */}
        <section className="cta-banner glass-card">
          <div className="cta-content">
            <h3 className="cta-title">Advance Protection For Your Digital Infrastructure</h3>
            <p className="cta-desc">
              Run automated zero-friction vulnerability diagnostics on any domain or API endpoint in seconds.
            </p>
          </div>
          <button className="scan-btn" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            <span>Audit Target Now</span>
            <span className="btn-arrow">➔</span>
          </button>
        </section>
      </div>
    </main>
  );
}
