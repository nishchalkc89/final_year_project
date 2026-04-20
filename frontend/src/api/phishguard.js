const BASE = '/api'

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem('pg_token')
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  }
  const res = await fetch(`${BASE}${path}`, { ...options, headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Request failed')
  }
  return res.json()
}

function qs(params = {}) {
  const p = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== ''))
  ).toString()
  return p ? '?' + p : ''
}

export const api = {
  // ── Public scan ──────────────────────────────────────────────────────────
  scan: (url) =>
    apiFetch('/scan', { method: 'POST', body: JSON.stringify({ url }) }),

  // ── Auth ─────────────────────────────────────────────────────────────────
  adminLogin: (username, password) =>
    apiFetch('/admin/login', { method: 'POST', body: JSON.stringify({ username, password }) }),

  // ── Scans CRUD ───────────────────────────────────────────────────────────
  adminScans: (params = {}) =>
    apiFetch(`/admin/scans${qs(params)}`),

  adminScanDetail: (id) =>
    apiFetch(`/admin/scans/${id}`),

  adminUpdateScan: (id, payload) =>
    apiFetch(`/admin/scans/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),

  adminDeleteScan: (id) =>
    apiFetch(`/admin/scans/${id}`, { method: 'DELETE' }),

  adminBulkDelete: (ids) =>
    apiFetch('/admin/scans', { method: 'DELETE', body: JSON.stringify({ ids }) }),

  // ── Stats ────────────────────────────────────────────────────────────────
  adminStats: () =>
    apiFetch('/admin/stats'),

  // ── Blacklist ────────────────────────────────────────────────────────────
  getBlacklist: () =>
    apiFetch('/admin/blacklist'),

  addToBlacklist: (url, reason = '') =>
    apiFetch('/admin/blacklist', { method: 'POST', body: JSON.stringify({ url, reason }) }),

  removeFromBlacklist: (id) =>
    apiFetch(`/admin/blacklist/${id}`, { method: 'DELETE' }),
}
