import React from 'react';

export default function HeadersTab({ data }) {
  const findings = data?.findings || [];

  return (
    <div className="glass-card">
      <div className="module-header">
        <span className="module-title">🛡️ HTTP Security Headers</span>
        <span className="text-muted" style={{ fontSize: '0.82rem' }}>
          {findings.length} headers analyzed
        </span>
      </div>
      <div className="module-body">
        {findings.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <div className="empty-state-title">No header data available</div>
          </div>
        ) : (
          <table className="tech-table">
            <thead>
              <tr>
                <th>Header</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td>
                    <span className="text-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                      {f.header || f.name}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`severity-badge ${
                        f.status?.toLowerCase() === 'present'
                          ? 'pass'
                          : f.status?.toLowerCase() === 'missing'
                          ? 'critical'
                          : 'info'
                      }`}
                    >
                      {f.status || 'Analyzed'}
                    </span>
                  </td>
                  <td>
                    <span className={`severity-badge ${(f.severity || 'Info').toLowerCase()}`}>
                      {f.severity || 'Info'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    {f.description}
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

