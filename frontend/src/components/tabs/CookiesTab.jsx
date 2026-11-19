import React from 'react';

export default function CookiesTab({ data }) {
  const cookies = Array.isArray(data) ? data : data?.findings || [];

  return (
    <div className="glass-card">
      <div className="module-header">
        <span className="module-title">🍪 Cookie Security Flags</span>
        <span className="text-muted" style={{ fontSize: '0.82rem' }}>
          {cookies.length} cookie flags analyzed
        </span>
      </div>
      <div className="module-body">
        {cookies.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🍪</div>
            <div className="empty-state-title">No cookies detected or analyzed</div>
          </div>
        ) : (
          <table className="tech-table">
            <thead>
              <tr>
                <th>Finding / Cookie</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {cookies.map((c, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {c.header || c.name || c.title || 'Cookie Flag'}
                  </td>
                  <td>
                    <span className="severity-badge info">
                      {c.status || 'Analyzed'}
                    </span>
                  </td>
                  <td>
                    <span className={`severity-badge ${(c.severity || 'Info').toLowerCase()}`}>
                      {c.severity || 'Info'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    {c.recommendation || c.description || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

