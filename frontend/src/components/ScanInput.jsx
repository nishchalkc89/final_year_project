import { useState } from 'react'
import { Search, Shield, AlertCircle, Loader2 } from 'lucide-react'
import { api } from '../api/phishguard'
import ResultCard from './ResultCard'

export default function ScanInput() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  async function handleScan(e) {
    e.preventDefault()
    const trimmed = url.trim()
    if (!trimmed) return

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const data = await api.scan(trimmed)
      setResult(data)
    } catch (err) {
      setError(err.message || 'Scan failed. Make sure the backend is running.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section id="scan" className="py-20 px-4">
      <div className="max-w-3xl mx-auto">
        {/* Heading */}
        <div className="text-center mb-10">
          <h2 className="section-heading mb-3">Analyze Any URL</h2>
          <p className="text-gray-400 text-base">
            Paste any suspicious link below and get an instant threat assessment.
          </p>
        </div>

        {/* Input form */}
        <form onSubmit={handleScan}>
          <div className="relative flex items-center glass rounded-2xl p-1.5 shadow-xl shadow-black/30 focus-within:border-blue-500/50 transition-colors">
            <div className="pl-4 text-gray-500">
              <Search className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com/suspicious-page"
              className="flex-1 bg-transparent px-4 py-3.5 text-white placeholder-gray-500 text-sm outline-none min-w-0"
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="btn-primary px-6 py-3 rounded-xl shrink-0"
            >
              {loading ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</>
              ) : (
                <><Shield className="w-4 h-4" /> Scan</>
              )}
            </button>
          </div>
        </form>

        {/* Error */}
        {error && (
          <div className="mt-4 flex items-center gap-3 px-4 py-3 rounded-xl bg-red-900/30 border border-red-500/30 text-red-300 text-sm">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        {/* Loading skeleton */}
        {loading && (
          <div className="mt-8 glass rounded-2xl p-6 animate-pulse space-y-4">
            <div className="flex items-center gap-4">
              <div className="w-20 h-20 rounded-full bg-white/10" />
              <div className="space-y-2 flex-1">
                <div className="h-5 bg-white/10 rounded w-1/3" />
                <div className="h-3 bg-white/10 rounded w-1/2" />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              {[1, 2, 3].map(i => <div key={i} className="h-16 bg-white/10 rounded-xl" />)}
            </div>
          </div>
        )}

        {/* Result */}
        {result && !loading && <ResultCard result={result} />}
      </div>
    </section>
  )
}
