import { useState } from 'react'

export default function ReportDownload({ url }) {
  const [downloading, setDownloading] = useState(false)

  const handleDownload = async () => {
    if (!url || downloading) return
    setDownloading(true)
    try {
      const response = await fetch('http://localhost:8000/api/v1/scan/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('token')}` },
        body: JSON.stringify({ url }),
      })
      if (!response.ok) throw new Error('Report generation failed')
      const blob = await response.blob()
      const link = document.createElement('a')
      link.href = URL.createObjectURL(blob)
      link.download = `VAPTProX_Audit_${new Date().toISOString().slice(0, 10)}.pdf`
      link.click()
    } catch (err) {
      alert('Could not generate report: ' + err.message)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <button className={`download-btn ${downloading ? 'loading' : ''}`} onClick={handleDownload} disabled={downloading}>
      <span>{downloading ? '⏳' : '📄'}</span>
      <span>{downloading ? 'Compiling PDF...' : 'Download PDF Report'}</span>
    </button>
  )
}
