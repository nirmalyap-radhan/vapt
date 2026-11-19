import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import Home from './pages/Home.jsx'
import Results from './pages/Results.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <div className="grid-bg" />
        <Navbar />
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/results" element={<Results />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <footer style={{
          textAlign: 'center', padding: '1.5rem',
          color: 'var(--text-muted)', fontSize: '0.8rem',
          borderTop: '1px solid var(--border)'
        }}>
          VAPTProX — Professional Web Security Assessment Suite. 🛡
        </footer>
      </div>
    </BrowserRouter>
  )
}
