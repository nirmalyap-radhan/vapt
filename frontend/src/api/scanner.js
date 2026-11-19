import api from './client.js'

export const runFullScan = (url) => api.post('/api/v1/scan/full', { url })
export const runHeaderScan = (url) => api.post('/api/v1/scan/headers', { url })
export const runCookieScan = (url) => api.post('/api/v1/scan/cookies', { url })
export const runSSLScan = (url) => api.post('/api/v1/scan/ssl', { url })
export const runPortScan = (url) => api.post('/api/v1/scan/ports', { url })
export const runDNSScan = (url) => api.post('/api/v1/scan/dns', { url })
export const runTechScan = (url) => api.post('/api/v1/scan/technologies', { url })
export const runLabScan = (url, maxPages = 15) => api.post('/api/v1/scan/lab', { url, max_pages: maxPages })
export const getHistory = () => api.get('/api/v1/history/')
export const getStats = () => api.get('/api/v1/history/stats')
export const deleteHistoryScan = (id) => api.delete(`/api/v1/history/${id}`)
export const deleteHistoryItem = deleteHistoryScan

