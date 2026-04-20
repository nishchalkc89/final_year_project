import { Shield, ShieldAlert, ShieldX, CheckCircle, AlertTriangle, XCircle, ChevronDown, ChevronUp } from 'lucide-react'
import { useState } from 'react'

const LABEL_CONFIG = {
  Phishing: {
    color: 'text-red-400',
    bg: 'bg-red-900/20',
    border: 'border-red-500/30',
    ringColor: 'border-red-500',
    textRing: 'text-red-400',
    Icon: ShieldX,
    badge: 'bg-red-500/20 text-red-300 border-red-500/30',
    dot: 'bg-red-500',
  },
  Suspicious: {
    color: 'text-amber-400',
    bg: 'bg-amber-900/20',
    border: 'border-amber-500/30',
    ringColor: 'border-amber-500',
    textRing: 'text-amber-400',
    Icon: ShieldAlert,
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    dot: 'bg-amber-500',
  },
  Legitimate: {
    color: 'text-emerald-400',
    bg: 'bg-emerald-900/20',
    border: 'border-emerald-500/30',
    ringColor: 'border-emerald-500',
    textRing: 'text-emerald-400',
    Icon: Shield,
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    dot: 'bg-emerald-500',
  },
}

function ScoreBar({ label, score, color }) {
  return (
    <div>
      <div className="flex justify-between items-center mb-1.5">
        <span className="text-xs font-medium text-gray-400">{label}</span>
        <span className={`text-xs font-bold ${color}`}>{score.toFixed(1)}</span>
      </div>
      <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color.replace('text-', 'bg-')}`}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
      </div>
    </div>
  )
}

export default function ResultCard({ result }) {
  const [showDetails, setShowDetails] = useState(false)
  const cfg = LABEL_CONFIG[result.final_label] || LABEL_CONFIG.Suspicious
  const { Icon } = cfg

  return (
    <div className={`mt-8 rounded-2xl border ${cfg.border} ${cfg.bg} overflow-hidden animate-slide-up`}>
      {/* Header */}
      <div className="p-6 border-b border-white/8">
        <div className="flex items-start gap-5">
          {/* Score ring */}
          <div className={`w-20 h-20 rounded-full border-4 ${cfg.ringColor} flex items-center justify-center shrink-0 shadow-lg`}>
            <div className="text-center">
              <div className={`text-xl font-black ${cfg.textRing}`}>{Math.round(result.risk_score)}</div>
              <div className="text-[9px] text-gray-500 font-medium -mt-0.5">/ 100</div>
            </div>
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Icon className={`w-5 h-5 ${cfg.color}`} />
              <span className={`text-xl font-bold ${cfg.color}`}>{result.final_label}</span>
              <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${cfg.badge}`}>
                {result.confidence} Confidence
              </span>
            </div>
            <p className="text-gray-400 text-sm truncate">{result.url}</p>
            <p className="text-gray-500 text-xs mt-1">
              Scanned in {result.scan_duration}s &middot; {new Date(result.timestamp).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Score breakdown */}
      <div className="p-6 border-b border-white/8">
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Score Breakdown</h3>
        <div className="grid grid-cols-3 gap-4 mb-4">
          {[
            { label: 'Heuristic', score: result.breakdown.heuristic.score, color: 'text-blue-400' },
            { label: 'ML Engine', score: result.breakdown.ml.score, color: 'text-purple-400' },
            { label: 'Behavioral', score: result.breakdown.behavioral.score, color: 'text-cyan-400' },
          ].map(({ label, score, color }) => (
            <div key={label} className="glass rounded-xl p-3 text-center">
              <div className={`text-xl font-black ${color}`}>{score.toFixed(0)}</div>
              <div className="text-[10px] text-gray-500 font-medium mt-0.5">{label}</div>
            </div>
          ))}
        </div>
        <div className="space-y-3">
          <ScoreBar label="Heuristic (35%)" score={result.breakdown.heuristic.score} color="text-blue-400" />
          <ScoreBar label="ML Probability (45%)" score={result.breakdown.ml.score} color="text-purple-400" />
          <ScoreBar label="Behavioral (20%)" score={result.breakdown.behavioral.score} color="text-cyan-400" />
        </div>
      </div>

      {/* Explanation */}
      {result.explanation && result.explanation.length > 0 && (
        <div className="p-6 border-b border-white/8">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Why This Was Flagged</h3>
          <ul className="space-y-2">
            {result.explanation.slice(0, 6).map((item, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm text-gray-300">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Behavioral anomalies */}
      {result.breakdown.behavioral.anomalies?.length > 0 && (
        <div className="p-6 border-b border-white/8">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Behavioral Anomalies</h3>
          <ul className="space-y-2">
            {result.breakdown.behavioral.anomalies.map((a, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm text-gray-300">
                <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                {a}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Toggle details */}
      <button
        className="w-full flex items-center justify-center gap-2 py-3 text-sm text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-all"
        onClick={() => setShowDetails(d => !d)}
      >
        {showDetails ? <><ChevronUp className="w-4 h-4" /> Hide Details</> : <><ChevronDown className="w-4 h-4" /> Show URL Feature Details</>}
      </button>

      {showDetails && (
        <div className="p-6 pt-0 grid grid-cols-2 sm:grid-cols-3 gap-2">
          {result.url_features && Object.entries(result.url_features)
            .filter(([, v]) => typeof v === 'number')
            .slice(0, 18)
            .map(([key, val]) => (
              <div key={key} className="glass rounded-lg px-3 py-2">
                <div className="text-[10px] text-gray-500 truncate">{key.replace(/_/g, ' ')}</div>
                <div className="text-sm font-semibold text-gray-300 mt-0.5">{String(val)}</div>
              </div>
            ))}
        </div>
      )}
    </div>
  )
}
