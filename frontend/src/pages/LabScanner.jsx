import { useState } from 'react';
import { runLabScan } from '../api/scanner';

export default function LabScanner() {
  const [authorized, setAuthorized] = useState(false);
  const [url, setUrl] = useState('http://127.0.0.1:5000');
  const [maxPages, setMaxPages] = useState(10);
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    if (!authorized) { setError('Please confirm authorization before scanning.'); return; }
    setError('');
    setScanning(true);
    setFindings(null);
    try {
      const data = await runLabScan(url, maxPages);
      setFindings(data.findings || []);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Lab scan failed.');
    } finally {
      setScanning(false);
    }
  };

  const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sorted = findings ? [...findings].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)) : [];

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  sorted.forEach((f) => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  return (
    <main className="app-layout">
      <div className="grid-bg" />
      <div className="container lab-page">
        <h1 style={{ fontSize: '1.8rem', fontWeight: 800, marginBottom: '0.5rem' }}>🧪 Lab Scanner</h1>
        <p style={{ color: 'var(--text-muted)', marginBottom: '2rem', fontSize: '0.88rem' }}>
          Active vulnerability scanner for authorized local lab environments.
        </p>

        {/* Warning Banner */}
        <div className="lab-warning">
          <div className="lab-warning-icon">⚠️</div>
          <div>
            <div className="lab-warning-title">Authorized Use Only</div>
            <div className="lab-warning-text">
              This scanner actively tests for SQL Injection, XSS, CSRF, IDOR, and authentication flaws.
              Only scan systems you own or have explicit written authorization to test.
              Unauthorized scanning is illegal under the Computer Fraud and Abuse Act and similar laws.
              The included VulnLab app (<code style={{ background: 'rgba(255,255,255,0.08)', padding: '1px 4px', borderRadius: '3px' }}>http://127.0.0.1:5000</code>) is a safe, intentionally vulnerable target.
            </div>
          </div>
        </div>

        {/* Authorization Checkbox */}
        <label className="auth-checkbox">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
          />
          <span className="auth-checkbox-text">
            <strong style={{ color: 'var(--accent-green)' }}>I confirm</strong> that I have explicit authorization to scan the target system.
            I understand this tool is for educational and authorized security testing only.
          </span>
        </label>

        {/* Scan Controls */}
        <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
          <form onSubmit={handleScan}>
            <div className="lab-controls">
              <div className="lab-input-group">
                <label className="form-label">🎯 Target URL</label>
                <input
                  className="lab-input"
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="http://127.0.0.1:5000"
                  disabled={scanning}
                />
              </div>
              <div className="lab-input-group">
                <label className="form-label">Max Pages</label>
                <input
                  className="lab-num-input"
                  type="number"
                  value={maxPages}
                  onChange={(e) => setMaxPages(Number(e.target.value))}
                  min={1}
                  max={50}
                  disabled={scanning}
                />
              </div>
              <div className="lab-input-group" style={{ justifyContent: 'flex-end' }}>
                <label className="form-label">&nbsp;</label>
                <button
                  className="scan-btn"
                  type="submit"
                  disabled={scanning || !authorized}
                  style={{ height: '40px' }}
                >
                  {scanning ? <><span className="spinner" /> Scanning...</> : '🔬 Start Lab Scan'}
                </button>
              </div>
            </div>
            {error && (
              <div className="error-banner" style={{ marginTop: '1rem' }}>
                <span>⚠️</span> {error}
              </div>
            )}
          </form>
        </div>

        {/* VulnLab instructions */}
        <div className="glass-card" style={{ padding: '1.25rem 1.5rem', marginBottom: '2rem', borderColor: 'rgba(16,185,129,0.2)' }}>
          <div style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
            💡 <strong style={{ color: 'var(--accent-green)' }}>Start VulnLab first:</strong>&nbsp;
            <code style={{ background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '4px', fontSize: '0.82rem' }}>
              cd vulnlab && python app.py
            </code>
            &nbsp;— then scan <code style={{ background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '4px', fontSize: '0.82rem' }}>http://127.0.0.1:5000</code>
          </div>
        </div>

        {/* Results */}
        {scanning && (
          <div className="glass-card" style={{ padding: '3rem', textAlign: 'center' }}>
            <div className="spinner-lg" />
            <p style={{ marginTop: '1.5rem', color: 'var(--text-muted)', fontSize: '0.88rem' }}>
              Crawling and testing for vulnerabilities...
            </p>
          </div>
        )}

        {findings !== null && !scanning && (
          <div>
            {/* Stats */}
            <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
              {Object.entries(counts).map(([sev, n]) => (
                <div key={sev} className={`glass-card stat-card ${sev.toLowerCase()}`}>
                  <div className="stat-value">{n}</div>
                  <div className="stat-label">{sev}</div>
                </div>
              ))}
            </div>

            <div className="glass-card">
              <div className="module-header">
                <span className="module-title">🔎 Findings</span>
                <span className="text-muted" style={{ fontSize: '0.82rem' }}>{findings.length} vulnerabilities found</span>
              </div>
              <div className="module-body">
                {findings.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-state-icon">✅</div>
                    <div className="empty-state-title">No vulnerabilities detected</div>
                  </div>
                ) : (
                  sorted.map((f, i) => <FindingCard key={i} finding={f} />)
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className={`finding-card ${finding.severity}`}
      onClick={() => setOpen(!open)}
    >
      <div className="finding-header">
        <span className="finding-title">{finding.title || finding.name || 'Finding'}</span>
        <span className={`severity-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span>
      </div>
      {open && (
        <div className="finding-body">
          {finding.description && <p>{finding.description}</p>}
          {finding.url && (
            <div className="finding-evidence">
              🔗 {finding.url}
            </div>
          )}
          {finding.evidence && (
            <div className="finding-evidence">
              📋 {finding.evidence}
            </div>
          )}
          {finding.recommendation && (
            <div className="vuln-rec" style={{ marginTop: '0.75rem' }}>
              <div className="vuln-rec-label">Recommendation</div>
              {finding.recommendation}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

