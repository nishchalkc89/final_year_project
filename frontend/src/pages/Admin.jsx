import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, LogOut, RefreshCw, Search, Trash2, ChevronLeft, ChevronRight,
  TrendingUp, AlertTriangle, CheckCircle, ShieldX, BarChart2, Clock,
  X, Loader2, Eye, Pencil, Save, Ban, ListFilter, Calendar,
  ShieldAlert, Plus, Minus, SlidersHorizontal,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, CartesianGrid,
} from 'recharts'
import { api } from '../api/phishguard'

// ── Shared helpers ────────────────────────────────────────────────────────────

const LABEL_CFG = {
  Phishing:  { dot: 'bg-red-500',     text: 'text-red-400',     badge: 'bg-red-900/30 text-red-300 border-red-700/40' },
  Suspicious:{ dot: 'bg-amber-500',   text: 'text-amber-400',   badge: 'bg-amber-900/30 text-amber-300 border-amber-700/40' },
  Legitimate:{ dot: 'bg-emerald-500', text: 'text-emerald-400', badge: 'bg-emerald-900/30 text-emerald-300 border-emerald-700/40' },
}

function LabelBadge({ label }) {
  const c = LABEL_CFG[label] || LABEL_CFG.Suspicious
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${c.badge}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />{label}
    </span>
  )
}

function ScorePill({ score }) {
  const c = score >= 65 ? 'text-red-400 bg-red-900/20 border-red-800/40'
          : score >= 35 ? 'text-amber-400 bg-amber-900/20 border-amber-800/40'
          : 'text-emerald-400 bg-emerald-900/20 border-emerald-800/40'
  return <span className={`px-2.5 py-0.5 rounded-lg text-xs font-bold border ${c}`}>{score?.toFixed(1)}</span>
}

function StatCard({ icon: Icon, label, value, sub, color = 'text-blue-400' }) {
  const bg = color.replace('text-', 'bg-').replace('400', '900/40')
  return (
    <div className="glass rounded-2xl p-5">
      <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${bg} mb-3`}>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className="text-2xl font-black text-white">{value}</div>
      <div className="text-xs font-medium text-gray-400 mt-0.5">{label}</div>
      {sub && <div className="text-[10px] text-gray-600 mt-1">{sub}</div>}
    </div>
  )
}

// ── View Details Modal ────────────────────────────────────────────────────────
function ViewModal({ scan, onClose }) {
  if (!scan) return null
  const c = LABEL_CFG[scan.final_label] || LABEL_CFG.Suspicious
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl max-h-[88vh] overflow-y-auto glass rounded-2xl shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 glass border-b border-white/10 px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <LabelBadge label={scan.final_label} />
            <span className="text-sm font-semibold text-white">Scan #{scan.id}</span>
            {scan.is_manual_override && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-violet-900/40 border border-violet-600/40 text-violet-300 font-medium">
                MANUAL OVERRIDE
              </span>
            )}
          </div>
          <button onClick={onClose} className="p-2 rounded-lg text-gray-400 hover:bg-white/10 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* URL */}
          <div className="glass rounded-xl p-4">
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Scanned URL</div>
            <div className="text-sm text-blue-300 break-all font-mono">{scan.url}</div>
            <div className="text-[10px] text-gray-600 mt-2">
              {new Date(scan.timestamp).toLocaleString()} &middot; Duration: {scan.scan_duration}s
            </div>
          </div>

          {/* Score cards */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: 'Risk Score', val: scan.risk_score, color: 'text-white' },
              { label: 'ML',         val: scan.ml_score,        color: 'text-purple-400' },
              { label: 'Heuristic',  val: scan.heuristic_score, color: 'text-blue-400' },
              { label: 'Behavioral', val: scan.behavioral_score,color: 'text-cyan-400' },
            ].map(({ label, val, color }) => (
              <div key={label} className="glass rounded-xl p-3 text-center">
                <div className={`text-xl font-black ${color}`}>{val?.toFixed(1)}</div>
                <div className="text-[10px] text-gray-500 mt-0.5">{label}</div>
              </div>
            ))}
          </div>

          {/* Score bars */}
          <div className="glass rounded-xl p-4 space-y-3">
            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Score Breakdown (Weights)</div>
            {[
              { label: 'Heuristic Engine (35%)', val: scan.heuristic_score, color: 'bg-blue-500' },
              { label: 'ML Ensemble (45%)',      val: scan.ml_score,        color: 'bg-purple-500' },
              { label: 'Behavioral (20%)',       val: scan.behavioral_score,color: 'bg-cyan-500' },
            ].map(({ label, val, color }) => (
              <div key={label}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-400">{label}</span>
                  <span className="font-bold text-white">{val?.toFixed(1)}</span>
                </div>
                <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${color} transition-all duration-500`}
                    style={{ width: `${Math.min(val || 0, 100)}%` }} />
                </div>
              </div>
            ))}
          </div>

          {/* Explanation */}
          {scan.explanation?.length > 0 && (
            <div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Why It Was Flagged</div>
              <ul className="space-y-1.5">
                {scan.explanation.map((e, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-gray-300">
                    <AlertTriangle className="w-3 h-3 text-amber-400 mt-0.5 shrink-0" />
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Heuristic flags */}
          {scan.heuristic_flags?.length > 0 && (
            <div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Heuristic Flags</div>
              <div className="space-y-1">
                {scan.heuristic_flags.map((f, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-blue-300 bg-blue-900/10 rounded-lg px-3 py-1.5">
                    <Shield className="w-3 h-3 mt-0.5 shrink-0" />{f}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Behavioral anomalies */}
          {scan.behavioral_anomalies?.length > 0 && (
            <div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Behavioral Anomalies</div>
              <div className="space-y-1">
                {scan.behavioral_anomalies.map((a, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-cyan-300 bg-cyan-900/10 rounded-lg px-3 py-1.5">
                    <ShieldAlert className="w-3 h-3 mt-0.5 shrink-0" />{a}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* URL Features grid */}
          {scan.url_features && Object.keys(scan.url_features).length > 0 && (
            <div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">URL Feature Breakdown</div>
              <div className="grid grid-cols-3 gap-1.5">
                {Object.entries(scan.url_features)
                  .filter(([, v]) => typeof v === 'number')
                  .map(([key, val]) => (
                    <div key={key} className="glass rounded-lg px-2.5 py-2">
                      <div className="text-[9px] text-gray-600 truncate">{key.replace(/_/g, ' ')}</div>
                      <div className="text-xs font-bold text-gray-300 mt-0.5">{String(val)}</div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Notes */}
          {scan.notes && (
            <div className="glass rounded-xl p-4">
              <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Admin Notes</div>
              <div className="text-sm text-gray-300 whitespace-pre-wrap">{scan.notes}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Edit Modal ────────────────────────────────────────────────────────────────
function EditModal({ scan, onClose, onSave }) {
  const [label, setLabel]     = useState(scan.final_label)
  const [score, setScore]     = useState(String(scan.risk_score ?? ''))
  const [notes, setNotes]     = useState(scan.notes || '')
  const [override, setOverride] = useState(Boolean(scan.is_manual_override))
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState('')

  async function handleSave() {
    const numScore = parseFloat(score)
    if (score !== '' && (isNaN(numScore) || numScore < 0 || numScore > 100)) {
      setError('Risk score must be 0–100')
      return
    }
    setSaving(true)
    setError('')
    try {
      const payload = {
        final_label: label,
        risk_score: score !== '' ? numScore : undefined,
        notes: notes || null,
        is_manual_override: override,
      }
      const updated = await api.adminUpdateScan(scan.id, payload)
      onSave(updated)
      onClose()
    } catch (e) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md glass rounded-2xl shadow-2xl">
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Pencil className="w-4 h-4 text-blue-400" />
            <span className="font-semibold text-white text-sm">Edit Scan #{scan.id}</span>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-gray-400 hover:bg-white/10"><X className="w-4 h-4" /></button>
        </div>

        <div className="p-6 space-y-4">
          {/* URL preview */}
          <div className="glass rounded-xl px-3 py-2">
            <div className="text-[10px] text-gray-600 mb-0.5">URL</div>
            <div className="text-xs text-blue-300 truncate font-mono">{scan.url}</div>
          </div>

          {/* Label */}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Classification Label</label>
            <select
              value={label}
              onChange={e => setLabel(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white outline-none focus:border-blue-500/60 transition-colors"
            >
              <option value="Legitimate">Legitimate</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Phishing">Phishing</option>
            </select>
          </div>

          {/* Risk score */}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">
              Risk Score (0–100)
              <span className="text-gray-600 font-normal ml-1">— leave blank to keep current</span>
            </label>
            <input
              type="number"
              min="0" max="100" step="0.1"
              value={score}
              onChange={e => setScore(e.target.value)}
              placeholder={String(scan.risk_score)}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white placeholder-gray-600 outline-none focus:border-blue-500/60 transition-colors"
            />
          </div>

          {/* Notes */}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Admin Notes</label>
            <textarea
              value={notes}
              onChange={e => setNotes(e.target.value)}
              rows={3}
              placeholder="Add investigation notes, context, or justification..."
              className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white placeholder-gray-600 outline-none focus:border-blue-500/60 transition-colors resize-none"
            />
          </div>

          {/* Manual override toggle */}
          <div className="flex items-center justify-between glass rounded-xl px-4 py-3">
            <div>
              <div className="text-sm font-medium text-white">Manual Override</div>
              <div className="text-[11px] text-gray-500 mt-0.5">Mark this scan as manually reviewed</div>
            </div>
            <button
              onClick={() => setOverride(o => !o)}
              className={`w-11 h-6 rounded-full transition-all duration-200 ${override ? 'bg-violet-600' : 'bg-white/10'}`}
            >
              <div className={`w-4.5 h-4.5 bg-white rounded-full shadow-md transition-all duration-200 mx-0.5 mt-0.5 ${override ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
          </div>

          {error && (
            <div className="text-xs text-red-300 bg-red-900/20 border border-red-500/20 rounded-xl px-3 py-2.5 flex items-center gap-2">
              <X className="w-3.5 h-3.5 shrink-0" />{error}
            </div>
          )}

          <div className="flex gap-3 pt-1">
            <button onClick={onClose} className="btn-ghost flex-1 justify-center text-xs py-2.5">Cancel</button>
            <button onClick={handleSave} disabled={saving} className="btn-primary flex-1 justify-center text-xs py-2.5">
              {saving ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Saving...</> : <><Save className="w-3.5 h-3.5" />Save Changes</>}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Delete Confirmation Modal ─────────────────────────────────────────────────
function DeleteConfirmModal({ scan, onClose, onConfirm }) {
  const [deleting, setDeleting] = useState(false)
  async function handleDelete() {
    setDeleting(true)
    await onConfirm(scan.id)
    setDeleting(false)
    onClose()
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-sm glass rounded-2xl shadow-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-red-900/40 flex items-center justify-center">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <div className="font-semibold text-white text-sm">Delete Scan?</div>
            <div className="text-xs text-gray-500">This cannot be undone.</div>
          </div>
        </div>
        <div className="glass rounded-xl px-3 py-2 mb-5">
          <div className="text-[10px] text-gray-600 mb-0.5">Scan #{scan.id}</div>
          <div className="text-xs text-gray-400 truncate font-mono">{scan.url}</div>
        </div>
        <div className="flex gap-3">
          <button onClick={onClose} className="btn-ghost flex-1 justify-center text-xs py-2.5">Cancel</button>
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="flex-1 justify-center inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold transition-all disabled:opacity-50"
          >
            {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
            {deleting ? 'Deleting…' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Blacklist Tab ─────────────────────────────────────────────────────────────
function BlacklistTab() {
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [newUrl,  setNewUrl]  = useState('')
  const [reason,  setReason]  = useState('')
  const [adding,  setAdding]  = useState(false)
  const [error,   setError]   = useState('')
  const [search,  setSearch]  = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.getBlacklist()
      setEntries(data.entries)
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleAdd(e) {
    e.preventDefault()
    if (!newUrl.trim()) return
    setAdding(true)
    setError('')
    try {
      await api.addToBlacklist(newUrl.trim(), reason.trim())
      setNewUrl('')
      setReason('')
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setAdding(false)
    }
  }

  async function handleRemove(id) {
    try {
      await api.removeFromBlacklist(id)
      await load()
    } catch (err) {
      alert(err.message)
    }
  }

  const filtered = entries.filter(e =>
    !search || e.domain?.includes(search.toLowerCase()) || e.url?.includes(search.toLowerCase())
  )

  return (
    <div className="space-y-5">
      {/* Add form */}
      <div className="glass rounded-2xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Plus className="w-4 h-4 text-red-400" />
          Add to Blacklist
        </h3>
        <form onSubmit={handleAdd} className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">URL or Domain *</label>
              <input
                type="text"
                value={newUrl}
                onChange={e => setNewUrl(e.target.value)}
                placeholder="e.g. paypal-secure-login.com"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white placeholder-gray-600 outline-none focus:border-red-500/50 transition-colors"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Reason (optional)</label>
              <input
                type="text"
                value={reason}
                onChange={e => setReason(e.target.value)}
                placeholder="e.g. Reported phishing, credential harvesting"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white placeholder-gray-600 outline-none focus:border-red-500/50 transition-colors"
              />
            </div>
          </div>
          {error && (
            <div className="text-xs text-red-300 bg-red-900/20 border border-red-500/20 rounded-xl px-3 py-2 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />{error}
            </div>
          )}
          <button
            type="submit"
            disabled={adding || !newUrl.trim()}
            className="btn-primary text-xs py-2.5 px-5 bg-gradient-to-r from-red-600 to-red-500 shadow-red-900/40 hover:from-red-500 hover:to-red-400"
          >
            {adding ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Adding…</> : <><Ban className="w-3.5 h-3.5" />Add to Blacklist</>}
          </button>
        </form>
      </div>

      {/* List */}
      <div className="glass rounded-2xl overflow-hidden">
        <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Ban className="w-4 h-4 text-red-400" />
            Blacklisted Domains
            <span className="text-xs font-normal text-gray-500">({entries.length})</span>
          </h3>
          <div className="relative w-44">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search..."
              className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-gray-600 outline-none focus:border-red-500/40"
            />
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-10"><Loader2 className="w-6 h-6 animate-spin text-gray-500" /></div>
        ) : filtered.length === 0 ? (
          <div className="text-center text-gray-600 py-10 text-sm">
            {entries.length === 0 ? 'No blacklist entries yet.' : 'No entries match your search.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider border-b border-white/8">
                  <th className="text-left px-5 py-3">#</th>
                  <th className="text-left px-4 py-3">Domain</th>
                  <th className="text-left px-4 py-3 hidden sm:table-cell">URL / Source</th>
                  <th className="text-left px-4 py-3 hidden md:table-cell">Reason</th>
                  <th className="text-left px-4 py-3 hidden lg:table-cell">Added</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map(entry => (
                  <tr key={entry.id} className="hover:bg-white/4 transition-colors">
                    <td className="px-5 py-3 text-gray-600 text-xs font-mono">{entry.id}</td>
                    <td className="px-4 py-3">
                      <span className="text-red-300 text-xs font-mono font-semibold">{entry.domain}</span>
                    </td>
                    <td className="px-4 py-3 hidden sm:table-cell">
                      <span className="text-gray-500 text-xs truncate block max-w-[200px]">{entry.url}</span>
                    </td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      <span className="text-gray-400 text-xs">{entry.reason || '—'}</span>
                    </td>
                    <td className="px-4 py-3 hidden lg:table-cell text-gray-600 text-xs whitespace-nowrap">
                      {new Date(entry.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleRemove(entry.id)}
                        className="p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-900/20 transition-all"
                        title="Remove from blacklist"
                      >
                        <Minus className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Admin Component ──────────────────────────────────────────────────────
export default function Admin() {
  const navigate = useNavigate()

  // Data state
  const [stats,   setStats]   = useState(null)
  const [scans,   setScans]   = useState([])
  const [total,   setTotal]   = useState(0)
  const [pages,   setPages]   = useState(1)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // Tab state
  const [activeTab, setActiveTab] = useState('scans') // 'scans' | 'blacklist'

  // Filter state
  const [page,        setPage]       = useState(1)
  const [search,      setSearch]     = useState('')
  const [labelFilter, setLabelFilter]= useState('')
  const [riskMin,     setRiskMin]    = useState('')
  const [riskMax,     setRiskMax]    = useState('')
  const [dateFrom,    setDateFrom]   = useState('')
  const [dateTo,      setDateTo]     = useState('')
  const [showFilters, setShowFilters]= useState(false)
  const [autoRefresh, setAutoRefresh]= useState(true)

  // Selection for bulk delete
  const [selected, setSelected] = useState(new Set())

  // Modal state
  const [viewScan,   setViewScan]  = useState(null)
  const [editScan,   setEditScan]  = useState(null)
  const [deleteScan, setDeleteScan]= useState(null)
  const [bulkConfirm,setBulkConfirm]=useState(false)

  const token    = localStorage.getItem('pg_token')
  const username = localStorage.getItem('pg_user') || 'Admin'

  useEffect(() => { if (!token) navigate('/admin/login') }, [token, navigate])

  // ── Data fetching ──────────────────────────────────────────────────────────
  const fetchAll = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    try {
      const params = {
        page, per_page: 15,
        search: search || undefined,
        label: labelFilter || undefined,
        risk_min: riskMin || undefined,
        risk_max: riskMax || undefined,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
      }
      const [statsData, scansData] = await Promise.all([
        api.adminStats(),
        api.adminScans(params),
      ])
      setStats(statsData)
      setScans(scansData.results)
      setTotal(scansData.total)
      setPages(scansData.pages)
    } catch (err) {
      const msg = err.message?.toLowerCase() || ''
      if (msg.includes('401') || msg.includes('unauthorized')) {
        localStorage.removeItem('pg_token')
        navigate('/admin/login')
      }
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [page, search, labelFilter, riskMin, riskMax, dateFrom, dateTo, navigate])

  useEffect(() => { fetchAll(true) }, [fetchAll])

  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => fetchAll(false), 5000)
    return () => clearInterval(id)
  }, [autoRefresh, fetchAll])

  // ── CRUD handlers ──────────────────────────────────────────────────────────
  function handleLogout() {
    localStorage.removeItem('pg_token')
    localStorage.removeItem('pg_user')
    navigate('/admin/login')
  }

  function handleScanUpdated(updated) {
    setScans(prev => prev.map(s => s.id === updated.id ? updated : s))
  }

  async function handleDeleteConfirm(id) {
    await api.adminDeleteScan(id)
    setScans(prev => prev.filter(s => s.id !== id))
    setTotal(t => t - 1)
    setSelected(prev => { const n = new Set(prev); n.delete(id); return n })
  }

  async function handleBulkDelete() {
    if (selected.size === 0) return
    await api.adminBulkDelete([...selected])
    setSelected(new Set())
    setBulkConfirm(false)
    fetchAll(false)
  }

  function toggleSelect(id) {
    setSelected(prev => {
      const n = new Set(prev)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
  }

  function toggleSelectAll() {
    if (selected.size === scans.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(scans.map(s => s.id)))
    }
  }

  function clearFilters() {
    setSearch(''); setLabelFilter(''); setRiskMin(''); setRiskMax('')
    setDateFrom(''); setDateTo(''); setPage(1)
  }

  const hasActiveFilters = search || labelFilter || riskMin || riskMax || dateFrom || dateTo

  // Chart data
  const pieData = stats ? [
    { name: 'Phishing',   value: stats.label_distribution.phishing   || 0, color: '#ef4444' },
    { name: 'Suspicious', value: stats.label_distribution.suspicious || 0, color: '#f59e0b' },
    { name: 'Legitimate', value: stats.label_distribution.legitimate || 0, color: '#10b981' },
  ] : []

  if (loading) return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
      <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
    </div>
  )

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">

      {/* ── Topbar ────────────────────────────────────────────────────────── */}
      <header className="glass-dark border-b border-white/10 sticky top-0 z-40">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center shadow-lg">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-bold text-white text-sm">PhishGuard <span className="text-gray-600 font-normal">Admin</span></span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoRefresh(r => !r)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                autoRefresh ? 'bg-blue-900/30 text-blue-300 border-blue-700/40' : 'text-gray-500 border-white/10 hover:bg-white/10'
              }`}
            >
              <RefreshCw className={`w-3 h-3 ${autoRefresh ? 'animate-spin' : ''}`} />
              {autoRefresh ? 'Live' : 'Paused'}
            </button>
            <span className="text-xs text-gray-500 hidden sm:block">{username}</span>
            <button onClick={handleLogout} className="btn-ghost text-xs px-3 py-1.5">
              <LogOut className="w-3.5 h-3.5" />Logout
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-[1400px] mx-auto px-4 sm:px-6 py-8 space-y-8">

        {/* ── Stats Cards ─────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon={BarChart2}    label="Total Scans"    value={stats?.total_scans ?? 0}               color="text-blue-400" />
          <StatCard icon={ShieldX}      label="Phishing"       value={stats?.label_distribution.phishing ?? 0}
            sub={`${stats?.total_scans ? ((stats.label_distribution.phishing / stats.total_scans) * 100).toFixed(1) : 0}% of total`}
            color="text-red-400" />
          <StatCard icon={AlertTriangle}label="Suspicious"     value={stats?.label_distribution.suspicious ?? 0} color="text-amber-400" />
          <StatCard icon={TrendingUp}   label="Avg Risk Score" value={stats?.average_risk_score?.toFixed(1) ?? '—'}
            sub={`${stats?.manual_overrides ?? 0} manual overrides`} color="text-purple-400" />
        </div>

        {/* ── Charts ──────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="lg:col-span-2 glass rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />Daily Scans — Last 7 Days
            </h3>
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={stats?.daily_scans || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#6b7280' }} tickFormatter={d => d.slice(5)} />
                <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={{ fill: '#3b82f6', r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="glass rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-purple-400" />Label Distribution
            </h3>
            {stats?.total_scans ? (
              <>
                <ResponsiveContainer width="100%" height={140}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="value" paddingAngle={3}>
                      {pieData.map(e => <Cell key={e.name} fill={e.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-col gap-1.5 mt-2">
                  {pieData.map(({ name, value, color }) => (
                    <div key={name} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full" style={{ background: color }} />
                        <span className="text-gray-400">{name}</span>
                      </div>
                      <span className="font-bold text-white">{value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-40 text-gray-600 text-sm">No data yet</div>
            )}
          </div>
        </div>

        {/* ── Tabs ────────────────────────────────────────────────────────── */}
        <div className="flex items-center gap-1 glass rounded-xl p-1 w-fit">
          {[
            { key: 'scans',     label: 'Scans',     icon: Shield },
            { key: 'blacklist', label: 'Blacklist',  icon: Ban },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === key
                  ? 'bg-white/10 text-white shadow-sm'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />{label}
            </button>
          ))}
        </div>

        {/* ── Scans Tab ───────────────────────────────────────────────────── */}
        {activeTab === 'scans' && (
          <div className="glass rounded-2xl overflow-hidden">
            {/* Table toolbar */}
            <div className="px-5 py-4 border-b border-white/10 space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                <h3 className="text-sm font-semibold text-white flex-1">
                  All Scans <span className="text-xs font-normal text-gray-500">({total})</span>
                  {hasActiveFilters && (
                    <button onClick={clearFilters} className="ml-2 text-[10px] text-blue-400 hover:text-blue-300 underline">clear filters</button>
                  )}
                </h3>

                <div className="flex items-center gap-2 w-full sm:w-auto flex-wrap">
                  {/* Bulk delete */}
                  {selected.size > 0 && (
                    <button
                      onClick={() => setBulkConfirm(true)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-900/30 text-red-300 border border-red-700/40 text-xs font-medium hover:bg-red-900/50 transition-all"
                    >
                      <Trash2 className="w-3 h-3" />Delete {selected.size}
                    </button>
                  )}

                  {/* Search */}
                  <div className="relative flex-1 sm:w-52 min-w-[140px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                    <input
                      type="text"
                      placeholder="Search URLs..."
                      value={search}
                      onChange={e => { setSearch(e.target.value); setPage(1) }}
                      className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-gray-600 outline-none focus:border-blue-500/50"
                    />
                  </div>

                  {/* Label filter */}
                  <select
                    value={labelFilter}
                    onChange={e => { setLabelFilter(e.target.value); setPage(1) }}
                    className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-gray-300 outline-none focus:border-blue-500/50"
                  >
                    <option value="">All Labels</option>
                    <option value="Phishing">Phishing</option>
                    <option value="Suspicious">Suspicious</option>
                    <option value="Legitimate">Legitimate</option>
                  </select>

                  {/* Advanced filters toggle */}
                  <button
                    onClick={() => setShowFilters(f => !f)}
                    className={`p-2 rounded-lg text-xs transition-all ${showFilters ? 'bg-blue-900/30 text-blue-300 border border-blue-700/40' : 'text-gray-400 hover:bg-white/10 border border-white/10'}`}
                    title="Advanced filters"
                  >
                    <SlidersHorizontal className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => { setRefreshing(true); fetchAll(false) }}
                    className="p-2 rounded-lg text-gray-400 hover:bg-white/10 hover:text-white border border-white/10 transition-all"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                  </button>
                </div>
              </div>

              {/* Advanced filters panel */}
              {showFilters && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-white/8">
                  <div>
                    <label className="block text-[10px] text-gray-500 mb-1">Risk Score Min</label>
                    <input type="number" min="0" max="100" value={riskMin}
                      onChange={e => { setRiskMin(e.target.value); setPage(1) }}
                      placeholder="0"
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-600 outline-none focus:border-blue-500/50" />
                  </div>
                  <div>
                    <label className="block text-[10px] text-gray-500 mb-1">Risk Score Max</label>
                    <input type="number" min="0" max="100" value={riskMax}
                      onChange={e => { setRiskMax(e.target.value); setPage(1) }}
                      placeholder="100"
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder-gray-600 outline-none focus:border-blue-500/50" />
                  </div>
                  <div>
                    <label className="block text-[10px] text-gray-500 mb-1 flex items-center gap-1"><Calendar className="w-3 h-3" />Date From</label>
                    <input type="date" value={dateFrom}
                      onChange={e => { setDateFrom(e.target.value); setPage(1) }}
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-blue-500/50 [color-scheme:dark]" />
                  </div>
                  <div>
                    <label className="block text-[10px] text-gray-500 mb-1 flex items-center gap-1"><Calendar className="w-3 h-3" />Date To</label>
                    <input type="date" value={dateTo}
                      onChange={e => { setDateTo(e.target.value); setPage(1) }}
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-blue-500/50 [color-scheme:dark]" />
                  </div>
                </div>
              )}
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/8 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
                    <th className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={scans.length > 0 && selected.size === scans.length}
                        onChange={toggleSelectAll}
                        className="w-3.5 h-3.5 rounded accent-blue-500 cursor-pointer"
                      />
                    </th>
                    <th className="text-left px-3 py-3">#</th>
                    <th className="text-left px-4 py-3">URL</th>
                    <th className="text-left px-4 py-3">Label</th>
                    <th className="text-left px-4 py-3">Risk</th>
                    <th className="text-left px-4 py-3 hidden sm:table-cell">ML</th>
                    <th className="text-left px-4 py-3 hidden md:table-cell">Heuristic</th>
                    <th className="text-left px-4 py-3 hidden lg:table-cell">Behavioral</th>
                    <th className="text-left px-4 py-3 hidden sm:table-cell">Time</th>
                    <th className="px-4 py-3 text-center">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {scans.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="text-center text-gray-600 py-12 text-sm">
                        {hasActiveFilters ? 'No scans match your filters.' : 'No scan records yet.'}
                      </td>
                    </tr>
                  ) : scans.map(scan => (
                    <tr
                      key={scan.id}
                      className={`hover:bg-white/4 transition-colors ${selected.has(scan.id) ? 'bg-blue-900/10' : ''}`}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selected.has(scan.id)}
                          onChange={() => toggleSelect(scan.id)}
                          onClick={e => e.stopPropagation()}
                          className="w-3.5 h-3.5 rounded accent-blue-500 cursor-pointer"
                        />
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1.5">
                          <span className="text-gray-600 text-xs font-mono">{scan.id}</span>
                          {scan.is_manual_override && (
                            <span className="w-1.5 h-1.5 rounded-full bg-violet-400" title="Manual override" />
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 max-w-[180px]">
                        <span className="text-blue-300 text-xs font-mono truncate block" title={scan.url}>
                          {scan.url.replace(/^https?:\/\//, '').slice(0, 35)}{scan.url.length > 45 ? '…' : ''}
                        </span>
                        {scan.notes && (
                          <span className="text-[10px] text-violet-400 truncate block mt-0.5">{scan.notes.slice(0, 40)}…</span>
                        )}
                      </td>
                      <td className="px-4 py-3"><LabelBadge label={scan.final_label} /></td>
                      <td className="px-4 py-3"><ScorePill score={scan.risk_score} /></td>
                      <td className="px-4 py-3 hidden sm:table-cell text-purple-400 text-xs font-bold">{scan.ml_score?.toFixed(0)}</td>
                      <td className="px-4 py-3 hidden md:table-cell text-blue-400 text-xs font-bold">{scan.heuristic_score?.toFixed(0)}</td>
                      <td className="px-4 py-3 hidden lg:table-cell text-cyan-400 text-xs font-bold">{scan.behavioral_score?.toFixed(0)}</td>
                      <td className="px-4 py-3 hidden sm:table-cell text-gray-600 text-xs whitespace-nowrap">
                        {new Date(scan.timestamp).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 justify-center">
                          <button
                            onClick={() => setViewScan(scan)}
                            className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-white/10 transition-all"
                            title="View details"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setEditScan(scan)}
                            className="p-1.5 rounded-lg text-gray-500 hover:text-blue-400 hover:bg-blue-900/20 transition-all"
                            title="Edit scan"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setDeleteScan(scan)}
                            className="p-1.5 rounded-lg text-gray-500 hover:text-red-400 hover:bg-red-900/20 transition-all"
                            title="Delete scan"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pages > 1 && (
              <div className="px-5 py-3 border-t border-white/8 flex items-center justify-between">
                <span className="text-xs text-gray-600">Page {page} of {pages} &middot; {total} total</span>
                <div className="flex items-center gap-1.5">
                  <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
                    className="p-1.5 rounded-lg text-gray-400 hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  {Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1).map(p => (
                    <button key={p} onClick={() => setPage(p)}
                      className={`w-7 h-7 rounded-lg text-xs font-medium transition-all ${p === page ? 'bg-blue-600 text-white' : 'text-gray-400 hover:bg-white/10'}`}>
                      {p}
                    </button>
                  ))}
                  <button disabled={page === pages} onClick={() => setPage(p => p + 1)}
                    className="p-1.5 rounded-lg text-gray-400 hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Blacklist Tab ────────────────────────────────────────────────── */}
        {activeTab === 'blacklist' && <BlacklistTab />}

      </main>

      {/* ── Modals ────────────────────────────────────────────────────────── */}
      {viewScan   && <ViewModal   scan={viewScan}   onClose={() => setViewScan(null)} />}
      {editScan   && <EditModal   scan={editScan}   onClose={() => setEditScan(null)} onSave={handleScanUpdated} />}
      {deleteScan && <DeleteConfirmModal scan={deleteScan} onClose={() => setDeleteScan(null)} onConfirm={handleDeleteConfirm} />}

      {/* Bulk delete confirmation */}
      {bulkConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setBulkConfirm(false)} />
          <div className="relative w-full max-w-sm glass rounded-2xl p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-900/40 flex items-center justify-center">
                <Trash2 className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <div className="font-semibold text-white text-sm">Delete {selected.size} Scans?</div>
                <div className="text-xs text-gray-500">This cannot be undone.</div>
              </div>
            </div>
            <div className="flex gap-3">
              <button onClick={() => setBulkConfirm(false)} className="btn-ghost flex-1 justify-center text-xs py-2.5">Cancel</button>
              <button
                onClick={handleBulkDelete}
                className="flex-1 justify-center inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold transition-all"
              >
                <Trash2 className="w-3.5 h-3.5" />Delete All
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
