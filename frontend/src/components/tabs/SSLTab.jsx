import React from 'react';

export default function SSLTab({ data }) {
  if (!data) {
    return (
      <div className="glass-card">
        <div className="empty-state">
          <div className="empty-state-icon">🔒</div>
          <div className="empty-state-title">No SSL/TLS data available</div>
        </div>
      </div>
    );
  }

  const gradeClass = (grade) => {
    if (!grade) return 'info';
    const g = grade.toUpperCase();
    if (g.startsWith('A')) return 'ap';
    if (g.startsWith('B')) return 'b';
    return 'f';
  };

  return (
    <div className="glass-card">
      <div className="module-header">
        <span className="module-title">🔒 SSL/TLS Certificate & Configuration</span>
        {data.grade && (
          <div className={`ssl-grade ${gradeClass(data.grade)}`}>
            Grade: {data.grade}
          </div>
        )}
      </div>
      <div className="module-body">
        <div className="ssl-grid" style={{ marginBottom: '1.5rem' }}>
          <div className="ssl-item">
            <div className="ssl-key">HTTPS Supported</div>
            <div className="ssl-val" style={{ color: data.https_supported ? 'var(--accent-green)' : 'var(--critical)' }}>
              {data.https_supported ? '✅ Yes' : '❌ No'}
            </div>
          </div>
          <div className="ssl-item">
            <div className="ssl-key">TLS Version</div>
            <div className="ssl-val text-mono">{data.tls_version || data.protocol || 'Unknown'}</div>
          </div>
          <div className="ssl-item">
            <div className="ssl-key">Issuer</div>
            <div className="ssl-val">{data.issuer || data.certificate_issuer || 'Unknown'}</div>
          </div>
          <div className="ssl-item">
            <div className="ssl-key">Subject / Common Name</div>
            <div className="ssl-val">{data.subject || data.common_name || 'Unknown'}</div>
          </div>
          <div className="ssl-item">
            <div className="ssl-key">Expiration Date</div>
            <div className="ssl-val">{data.expires_at || data.valid_until || 'Unknown'}</div>
          </div>
          <div className="ssl-item">
            <div className="ssl-key">Days Remaining</div>
            <div className="ssl-val" style={{ color: (data.days_remaining || 0) < 30 ? 'var(--critical)' : 'var(--accent-green)' }}>
              {data.days_remaining !== undefined ? `${data.days_remaining} days` : 'Unknown'}
            </div>
          </div>
        </div>

        {data.findings && data.findings.length > 0 && (
          <div>
            <h4 style={{ fontSize: '0.85rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              SSL Security Findings
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {data.findings.map((f, i) => (
                <div key={i} className="vuln-card glass-card info">
                  <div className="vuln-header">
                    <span className="vuln-title">{f.title || f.name || 'SSL Check'}</span>
                    <span className={`severity-badge ${(f.severity || 'info').toLowerCase()}`}>
                      {f.severity || 'Info'}
                    </span>
                  </div>
                  {f.description && <div className="vuln-description">{f.description}</div>}
                  {f.recommendation && (
                    <div className="vuln-rec">
                      <div className="vuln-rec-label">Recommendation</div>
                      {f.recommendation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

