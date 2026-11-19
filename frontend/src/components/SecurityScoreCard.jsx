import React from 'react'

export default function SecurityScoreCard({ score, riskLevel, counts = {} }) {
  const numScore = typeof score === 'object' && score !== null
    ? (score.score ?? 0)
    : (Number(score) || 0)

  const level = riskLevel ||
    (typeof score === 'object' && score?.risk_level) ||
    (numScore >= 80 ? 'Good' : numScore >= 60 ? 'Moderate' : 'Critical')

  const scoreColor = numScore >= 80
    ? '#10b981'
    : numScore >= 60
    ? '#f59e0b'
    : '#ef4444'

  const strokeDash = Math.round((numScore / 100) * 283) // 2 * PI * 45 ≈ 283

  return (
    <div className="glass-card security-posture-card">
      <div className="posture-card-header">
        <span className="posture-subtitle">OVERALL SECURITY POSTURE</span>
        <span className="posture-shield-icon">🛡️</span>
      </div>

      {/* Circular Gauge */}
      <div className="score-gauge-container">
        <div className="score-gauge-wrapper">
          <svg className="score-svg" viewBox="0 0 100 100">
            <circle
              className="score-bg-circle"
              cx="50"
              cy="50"
              r="43"
            />
            <circle
              className="score-val-circle"
              cx="50"
              cy="50"
              r="43"
              stroke={scoreColor}
              strokeDasharray={`${strokeDash} 283`}
            />
          </svg>
          <div className="score-gauge-text">
            <span className="score-number" style={{ color: scoreColor }}>{numScore}</span>
            <span className="score-scale">/100</span>
          </div>
        </div>

        <div className="score-meta">
          <div className="posture-risk-badge" style={{
            background: `${scoreColor}18`,
            color: scoreColor,
            borderColor: `${scoreColor}40`
          }}>
            <span className="risk-dot" style={{ background: scoreColor }}></span>
            {level} RISK
          </div>
          <div className="score-status-desc">
            {numScore >= 80
              ? 'Target maintains robust defense hygiene.'
              : numScore >= 60
              ? 'Moderate exposure — review warnings.'
              : 'Immediate hardening action required.'}
          </div>
        </div>
      </div>

      {/* Severity Breakdown Strip */}
      <div className="score-breakdown">
        <div className="breakdown-title">Vulnerability Breakdown</div>
        <div className="breakdown-items">
          <div className="breakdown-item critical">
            <span className="b-label">Critical</span>
            <span className="b-value">{counts.Critical ?? 0}</span>
          </div>
          <div className="breakdown-item high">
            <span className="b-label">High</span>
            <span className="b-value">{counts.High ?? 0}</span>
          </div>
          <div className="breakdown-item medium">
            <span className="b-label">Medium</span>
            <span className="b-value">{counts.Medium ?? 0}</span>
          </div>
          <div className="breakdown-item low">
            <span className="b-label">Low</span>
            <span className="b-value">{counts.Low ?? 0}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
