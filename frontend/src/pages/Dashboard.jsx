import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { getHistory, deleteHistoryItem, getStats } from '../api/scanner';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) { navigate('/login'); return; }
    fetchData();
  }, [user]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [h, s] = await Promise.all([getHistory(), getStats()]);
      setHistory(h || []);
      setStats(s || {});
    } catch {
      setHistory([]);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await deleteHistoryItem(id);
      setHistory((prev) => prev.filter((h) => h.id !== id));
    } catch {
      alert('Failed to delete item.');
    }
  };

  const formatDate = (iso) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  };

  return (
    <main className="app-layout">
      <div className="grid-bg" />
      <div className="container dashboard-page">
        {/* Header */}
        <div className="dashboard-header">
          <div>
            <h1 className="dashboard-title">Dashboard</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '0.3rem' }}>
              Welcome back, <span style={{ color: 'var(--accent-cyan)' }}>{user?.username}</span>
            </p>
          </div>
          <Link to="/" className="scan-btn" style={{ textDecoration: 'none' }}>
            🚀 New Scan
          </Link>
        </div>

        {/* Stats Row */}
        {stats && (
          <div className="stats-grid">
            <div className="glass-card stat-card scans">
              <div className="stat-value">{stats.total_scans ?? 0}</div>
              <div className="stat-label">Total Scans</div>
            </div>
            <div className="glass-card stat-card critical">
              <div className="stat-value">{stats.critical ?? 0}</div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="glass-card stat-card high">
              <div className="stat-value">{stats.high ?? 0}</div>
              <div className="stat-label">High</div>
            </div>
            <div className="glass-card stat-card medium">
              <div className="stat-value">{stats.medium ?? 0}</div>
              <div className="stat-label">Medium</div>
            </div>
            <div className="glass-card stat-card low">
              <div className="stat-value">{stats.low ?? 0}</div>
              <div className="stat-label">Low</div>
            </div>
          </div>
        )}

        {/* Scan History */}
        <div className="glass-card">
          <div className="module-header">
            <span className="module-title">📋 Scan History</span>
            <span className="text-muted" style={{ fontSize: '0.82rem' }}>{history.length} scans</span>
          </div>
          <div className="module-body" style={{ padding: '0' }}>
            {loading ? (
              <div style={{ padding: '3rem', textAlign: 'center' }}>
                <div className="spinner-lg" />
                <p style={{ marginTop: '1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>Loading history...</p>
              </div>
            ) : history.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">📭</div>
                <div className="empty-state-title">No scans yet</div>
                <p style={{ fontSize: '0.82rem', marginTop: '0.5rem' }}>Run your first scan to see results here.</p>
              </div>
            ) : (
              <table className="history-table">
                <thead>
                  <tr>
                    <th>Target URL</th>
                    <th>Score</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Date</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <span className="history-url" title={item.target_url}>{item.target_url}</span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 700, color: scoreColor(item.security_score) }}>
                          {item.security_score ?? '—'}
                        </span>
                      </td>
                      <td><span className="severity-badge critical">{item.critical_count ?? 0}</span></td>
                      <td><span className="severity-badge high">{item.high_count ?? 0}</span></td>
                      <td><span className="history-time">{formatDate(item.created_at)}</span></td>
                      <td>
                        <button className="delete-btn" onClick={() => handleDelete(item.id)}>🗑️</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}

function scoreColor(score) {
  if (!score) return 'var(--text-muted)';
  if (score >= 80) return 'var(--accent-green)';
  if (score >= 60) return 'var(--medium)';
  if (score >= 40) return 'var(--high)';
  return 'var(--critical)';
}

