import React from 'react';

export default function PortsTab({ data }) {
  const ports = data?.open_ports || [];

  return (
    <div className="glass-card">
      <div className="module-header">
        <span className="module-title">🔌 Open Ports & Services</span>
        <span className="text-muted" style={{ fontSize: '0.82rem' }}>
          {ports.length} open port{ports.length !== 1 ? 's' : ''} detected
        </span>
      </div>
      <div className="module-body">
        {ports.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-title">No common open ports detected</div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
              Standard scanned ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443) are filtered or closed.
            </p>
          </div>
        ) : (
          <table className="port-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Risk / Status</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {ports.map((p, i) => (
                <tr key={i}>
                  <td className="port-num">:{p.port}</td>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {p.service || 'Unknown Service'}
                  </td>
                  <td>
                    <span className={`severity-badge ${(p.severity || p.finding?.severity || 'info').toLowerCase()}`}>
                      {p.severity || p.finding?.severity || 'Open'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    {p.description || p.finding?.description || 'Port is accessible from the internet'}
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

