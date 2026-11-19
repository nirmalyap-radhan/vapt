import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import SecurityScoreCard from '../components/SecurityScoreCard';
import AIAnalystCard from '../components/AIAnalystCard';
import ReportDownload from '../components/ReportDownload';
import HeadersTab from '../components/tabs/HeadersTab';
import CookiesTab from '../components/tabs/CookiesTab';
import SSLTab from '../components/tabs/SSLTab';
import PortsTab from '../components/tabs/PortsTab';
import DNSTab from '../components/tabs/DNSTab';
import TechTab from '../components/tabs/TechTab';

export default function Results() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');

  if (!state?.data) {
    return (
      <div className="container" style={{ padding: '5rem 1.5rem', textAlign: 'center' }}>
        <div className="empty-state glass-card" style={{ padding: '3rem', maxWidth: '480px', margin: '0 auto' }}>
          <div className="empty-state-icon" style={{ fontSize: '3rem', marginBottom: '1rem' }}>📭</div>
          <div className="empty-state-title" style={{ fontSize: '1.3rem', fontWeight: 700 }}>No scan results found</div>
          <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginTop: '0.6rem', marginBottom: '1.8rem' }}>
            Please initiate an authorized target audit from the scanner console.
          </p>
          <button className="scan-btn" onClick={() => navigate('/')}>
            ← Return to Scanner Console
          </button>
        </div>
      </div>
    );
  }

  const { data, url } = state;
  const targetUrl = url || data.target_url || 'Target Domain';

  // Safely extract findings lists
  const headerFindings = Array.isArray(data.headers?.findings)
    ? data.headers.findings
    : Array.isArray(data.headers)
    ? data.headers
    : [];

  const cookieFindings = Array.isArray(data.cookies?.findings)
    ? data.cookies.findings
    : Array.isArray(data.cookies)
    ? data.cookies
    : [];

  const sslData = data.ssl || data.ssl_tls || {};
  const sslFindings = Array.isArray(sslData?.findings) ? sslData.findings : [];

  const portFindings = Array.isArray(data.ports?.open_ports)
    ? data.ports.open_ports.map((p) => p.finding || { name: `Port ${p.port} (${p.service || 'Open'})`, severity: p.severity || 'Info', description: p.description }).filter(Boolean)
    : [];

  const dnsFindings = Array.isArray(data.dns?.findings) ? data.dns.findings : [];

  // Aggregate all findings for overview
  const allFindings = [
    ...headerFindings,
    ...cookieFindings,
    ...sslFindings,
    ...portFindings,
    ...dnsFindings,
  ];

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  allFindings.forEach((f) => {
    const sev = f?.severity || 'Info';
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const TABS = [
    { id: 'overview', label: '📊 All Findings', count: allFindings.length },
    { id: 'headers', label: '🛡️ Headers', count: headerFindings.length },
    { id: 'cookies', label: '🍪 Cookies', count: cookieFindings.length },
    { id: 'ssl', label: '🔒 SSL/TLS', count: sslFindings.length },
    { id: 'ports', label: '🔌 Ports', count: data.ports?.open_ports?.length ?? 0 },
    { id: 'dns', label: '🌐 DNS & WHOIS', count: dnsFindings.length },
    { id: 'tech', label: '⚙️ Technologies', count: Object.keys(data.technologies?.technologies || {}).length },
  ];

  return (
    <main className="app-layout">
      <div className="grid-bg" />
      <div className="container results-page">
        {/* Top Header & Action Alignment */}
        <div className="results-top-bar">
          <div className="results-info-group">
            <div className="target-pill-badge">
              <span className="live-pulse-green"></span>
              <span className="target-url-text">{targetUrl}</span>
            </div>
            <h1 className="results-headline">Security Audit & Risk Assessment</h1>
            <div className="results-meta-strip">
              <span>Audited via <strong>VAPTProX Engine</strong></span>
              <span>•</span>
              <span>Scan Status: <strong style={{ color: 'var(--accent-green)' }}>Completed</strong></span>
              <span>•</span>
              <span>Target Host: <strong>{new URL(targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl).hostname}</strong></span>
            </div>
          </div>

          <div className="results-actions-group">
            <button className="back-scan-btn" onClick={() => navigate('/')}>
              ← New Scan
            </button>
            <ReportDownload scanData={data} url={targetUrl} />
          </div>
        </div>

        {/* Executive 2-Column Grid: Score Card + AI Analyst Panel */}
        <div className="executive-dashboard-grid">
          <SecurityScoreCard score={data.security_score} counts={counts} />
          <AIAnalystCard data={data} />
        </div>

        {/* Severity Metrics Row */}
        <div className="stats-grid metrics-row">
          {Object.entries(counts).map(([sev, n]) => (
            <div key={sev} className={`glass-card stat-card ${sev.toLowerCase()}`}>
              <div className="stat-value">{n}</div>
              <div className="stat-label">{sev}</div>
            </div>
          ))}
          <div className="glass-card stat-card ports">
            <div className="stat-value">{data.ports?.open_ports?.length ?? 0}</div>
            <div className="stat-label">Open Ports</div>
          </div>
        </div>

        {/* Module Tabs Navigation */}
        <div className="tab-nav-wrapper">
          <div className="tab-nav">
            {TABS.map((t) => (
              <button
                key={t.id}
                className={`tab-btn${activeTab === t.id ? ' active' : ''}`}
                onClick={() => setActiveTab(t.id)}
              >
                <span>{t.label}</span>
                {t.count !== undefined && (
                  <span className={`tab-count-badge ${t.count > 0 ? 'has-items' : ''}`}>
                    {t.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Tab Module Content Panel */}
        <div className="tab-content-container animate-in">
          {activeTab === 'overview' && (
            <div className="glass-card module-card-shell">
              <div className="module-header">
                <div className="module-title">
                  <span>📊</span> Consolidated Vulnerability Inventory
                </div>
                <span className="module-badge-counter">{allFindings.length} Total Findings Detected</span>
              </div>
              <div className="module-body">
                {allFindings.length === 0 ? (
                  <div className="empty-state clean-target">
                    <div className="empty-state-icon">🛡️</div>
                    <div className="empty-state-title">Target Surface Hardened</div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.5rem' }}>
                      No critical misconfigurations or missing baseline defense headers were discovered.
                    </p>
                  </div>
                ) : (
                  allFindings.map((f, i) => (
                    <VulnRow key={i} finding={f} />
                  ))
                )}
              </div>
            </div>
          )}

          {activeTab === 'headers' && <HeadersTab data={data.headers} />}
          {activeTab === 'cookies' && <CookiesTab data={cookieFindings} />}
          {activeTab === 'ssl' && <SSLTab data={sslData} />}
          {activeTab === 'ports' && <PortsTab data={data.ports} />}
          {activeTab === 'dns' && <DNSTab data={data.dns} whois={data.whois} />}
          {activeTab === 'tech' && <TechTab data={data.technologies} />}
        </div>
      </div>
    </main>
  );
}

function VulnRow({ finding }) {
  const [open, setOpen] = useState(false);
  const sev = (finding?.severity || 'info').toLowerCase();
  return (
    <div className={`vuln-card glass-card ${sev}`} onClick={() => setOpen(!open)}>
      <div className="vuln-header">
        <div className="vuln-title-wrap">
          <span className="vuln-bullet-point"></span>
          <span className="vuln-title">{finding?.header || finding?.name || finding?.title || 'Finding'}</span>
        </div>
        <div className="vuln-header-meta">
          <span className={`severity-badge ${sev}`}>{finding?.severity || 'Info'}</span>
          <span className="accordion-arrow">{open ? '▲' : '▼'}</span>
        </div>
      </div>
      {open && (
        <div className="vuln-body">
          {finding?.description && (
            <div className="vuln-description-wrap">
              <span className="field-label">Issue Description:</span>
              <p className="vuln-description">{finding.description}</p>
            </div>
          )}
          {finding?.recommendation && (
            <div className="vuln-rec">
              <div className="vuln-rec-label">
                <span>🛡️</span> Recommended Remediation
              </div>
              <div className="vuln-rec-text">{finding.recommendation}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
