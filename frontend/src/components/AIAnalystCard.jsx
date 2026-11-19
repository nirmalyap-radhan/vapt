import React from 'react'

export default function AIAnalystCard({ data, analysis: directAnalysis }) {
  const analysis = directAnalysis || data?.ai_analysis || {}

  const summary = analysis.executive_summary ||
    (typeof analysis === 'string' ? analysis : 'Automated multi-vector AI security correlation completed for the target.')

  const findings = Array.isArray(analysis.key_findings) ? analysis.key_findings : []
  const recommendations = Array.isArray(analysis.priority_recommendations) ? analysis.priority_recommendations : []

  return (
    <div className="glass-card ai-analyst-panel">
      <div className="ai-panel-header">
        <div className="ai-title-group">
          <div className="ai-flame-icon">⚡</div>
          <div>
            <h2 className="ai-panel-title">AI Threat Intelligence & Correlation</h2>
            <div className="ai-panel-sub">Dual-Engine Heuristic Analysis (Groq 120B & Gemini LLM)</div>
          </div>
        </div>
        <span className="ai-badge-live">
          <span className="pulse-dot"></span>
          AI Live Verified
        </span>
      </div>

      <div className="ai-executive-summary">
        <div className="summary-label">EXECUTIVE SUMMARY</div>
        <p className="summary-text">{summary}</p>
      </div>

      {(findings.length > 0 || recommendations.length > 0) && (
        <div className="ai-grid-columns">
          {findings.length > 0 && (
            <div className="ai-column findings-col">
              <div className="ai-col-header critical-head">
                <span>⚠️</span>
                <span>Critical Risk Exposures ({findings.length})</span>
              </div>
              <div className="ai-items-list">
                {findings.map((f, i) => (
                  <div key={i} className="ai-item finding-item">
                    <span className="item-bullet danger">•</span>
                    <span className="item-text">{typeof f === 'string' ? f : JSON.stringify(f)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {recommendations.length > 0 && (
            <div className="ai-column recs-col">
              <div className="ai-col-header rec-head">
                <span>🛡️</span>
                <span>Strategic Hardening Actions ({recommendations.length})</span>
              </div>
              <div className="ai-items-list">
                {recommendations.map((r, i) => (
                  <div key={i} className="ai-item rec-item">
                    <span className="item-bullet success">✓</span>
                    <span className="item-text">{typeof r === 'string' ? r : JSON.stringify(r)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {analysis.business_impact && (
        <div className="ai-business-impact-box">
          <div className="impact-header">
            <span className="impact-tag">BUSINESS IMPACT ASSESSMENT</span>
          </div>
          <div className="impact-text">{analysis.business_impact}</div>
        </div>
      )}
    </div>
  )
}
