import React from 'react'

export default function ScanProgress({ stages, currentStep = 0, target }) {
  const defaultStages = [
    'Connecting to target...',
    'Scanning security headers...',
    'Analyzing SSL/TLS certificate...',
    'Checking cookies...',
    'Running port discovery...',
    'DNS & WHOIS lookup...',
    'Technology detection...',
    'AI analysis & risk scoring...',
  ]

  const stageList = Array.isArray(stages) && stages.length > 0
    ? stages
    : defaultStages.map((name, idx) => ({
        name,
        status: idx < currentStep ? 'completed' : idx === currentStep ? 'running' : 'pending'
      }))

  const completedCount = stageList.filter(s => s.status === 'completed').length
  const pct = Math.min(100, Math.round((completedCount / stageList.length) * 100))

  return (
    <div className="glass-card" style={{ padding: '2rem', textAlign: 'left' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
          <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            🔍 Scanning in progress...
          </span>
          <span style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono, monospace' }}>
            {pct}%
          </span>
        </div>
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${Math.max(10, pct)}%` }} />
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {stageList.map((s, i) => {
          const isDone = s.status === 'completed'
          const isRunning = s.status === 'running'

          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              <div
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  background: isDone
                    ? 'var(--accent-green)'
                    : isRunning
                    ? 'var(--accent-orange)'
                    : 'rgba(255,255,255,0.15)',
                  boxShadow: isRunning ? '0 0 12px var(--accent-orange)' : 'none',
                  animation: isRunning ? 'pulse 1s infinite' : 'none',
                  flexShrink: 0,
                }}
              />
              <span
                style={{
                  fontSize: '0.85rem',
                  fontWeight: isRunning ? 600 : 400,
                  color: isDone
                    ? 'var(--text-primary)'
                    : isRunning
                    ? 'var(--accent-orange)'
                    : 'var(--text-muted)',
                }}
              >
                {s.name || s}
              </span>
              {isDone && (
                <span style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--accent-green)' }}>
                  ✓
                </span>
              )}
              {isRunning && (
                <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--accent-blue)' }}>
                  Scanning...
                </span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
