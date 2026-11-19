import { Link, useLocation } from 'react-router-dom'

export default function Navbar() {
  const location = useLocation()
  const isActive = (path) => location.pathname === path ? 'active' : ''

  return (
    <nav className="navbar">
      <div className="container navbar-inner">
        <Link to="/" className="navbar-brand">
          <div className="brand-icon-wrapper">
            <span className="brand-icon-flame">🛡️</span>
          </div>
          <div className="brand-text-group">
            <span className="brand-main">EYESHIELD</span>
            <span className="brand-sub">VAPT<span className="brand-accent">ProX</span></span>
          </div>
        </Link>

        <div className="navbar-links">
          <Link to="/" className={`nav-link ${isActive('/')}`}>
            <span>🎯</span> Scanner
          </Link>
          <a href="#why-eyeshield" className="nav-link">
            <span>⚡</span> Features
          </a>
          <a href="#capabilities" className="nav-link">
            <span>🛡️</span> Modules
          </a>
          <span className="nav-badge">
            <span className="pulse-dot"></span>
            AI Powered
          </span>
        </div>

        <div className="navbar-actions">
          <Link to="/" className="nav-cta-btn">
            Live Audit ➔
          </Link>
        </div>
      </div>
    </nav>
  )
}
