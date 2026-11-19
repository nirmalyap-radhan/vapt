import React from 'react';

export default function TechTab({ data }) {
  const techs = data?.technologies_detected || (Array.isArray(data) ? data : []);

  return (
    <div className="glass-card">
      <div className="module-header">
        <span className="module-title">⚙️ Detected Technologies & Stack</span>
        <span className="text-muted" style={{ fontSize: '0.82rem' }}>
          {techs.length} technologies identified
        </span>
      </div>
      <div className="module-body">
        {techs.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔍</div>
            <div className="empty-state-title">No explicit technologies detected</div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
              The server headers or HTML fingerprint do not reveal standard signatures.
            </p>
          </div>
        ) : (
          <table className="tech-table">
            <thead>
              <tr>
                <th>Technology</th>
                <th>Version</th>
                <th>Category / Source</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {techs.map((t, i) => (
                <tr key={i}>
                  <td className="tech-name">
                    {t.name || t.technology || 'Unknown'}
                  </td>
                  <td>
                    <span className="tech-version">{t.version || 'Unspecified'}</span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    {t.category || t.source || 'Header/Body Analysis'}
                  </td>
                  <td>
                    <span className="severity-badge info">
                      {t.confidence || 'Medium'}
                    </span>
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

