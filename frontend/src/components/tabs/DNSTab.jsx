import React from 'react';

export default function DNSTab({ data, whois }) {
  const records = data?.records || data?.dns_records || {};
  const findings = data?.findings || [];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1.5rem' }}>
      {/* DNS Records */}
      <div className="glass-card">
        <div className="module-header">
          <span className="module-title">🌐 DNS Records & Configurations</span>
        </div>
        <div className="module-body">
          <div className="dns-grid">
            <div>
              <div className="dns-section-title">Resolved Records</div>
              {Object.keys(records).length === 0 ? (
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>No DNS records returned.</div>
              ) : (
                Object.entries(records).map(([type, values]) => {
                  const valList = Array.isArray(values) ? values : [values];
                  return valList.map((val, idx) => (
                    <div key={`${type}-${idx}`} className="dns-record">
                      <span className="dns-type">{type}</span>
                      <span className="dns-value">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span>
                    </div>
                  ));
                })
              )}
            </div>

            <div>
              <div className="dns-section-title">DNS Security & Findings</div>
              {findings.length === 0 ? (
                <div style={{ fontSize: '0.85rem', color: 'var(--accent-green)' }}>
                  ✅ SPF, DMARC, and DNS records verified without obvious misconfigurations.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {findings.map((f, i) => (
                    <div key={i} className="vuln-card glass-card info" style={{ padding: '0.75rem 1rem' }}>
                      <div className="vuln-header" style={{ marginBottom: 0 }}>
                        <span className="vuln-title" style={{ fontSize: '0.88rem' }}>{f.title || f.name || 'DNS Finding'}</span>
                        <span className={`severity-badge ${(f.severity || 'info').toLowerCase()}`}>
                          {f.severity || 'Info'}
                        </span>
                      </div>
                      {f.description && <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.4rem' }}>{f.description}</p>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* WHOIS Data */}
      {whois && (
        <div className="glass-card">
          <div className="module-header">
            <span className="module-title">📋 WHOIS Domain Information</span>
          </div>
          <div className="module-body">
            <div className="whois-grid">
              {Object.entries(whois).map(([k, v]) => {
                if (!v || typeof v === 'object') return null;
                return (
                  <div key={k} className="whois-row">
                    <span className="whois-key">{k.replace(/_/g, ' ')}:</span>
                    <span className="whois-val text-mono">{String(v)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

