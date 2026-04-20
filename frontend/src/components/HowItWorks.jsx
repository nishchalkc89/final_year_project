import { Globe, Cpu, Brain, GitMerge, CheckCircle } from 'lucide-react'

const steps = [
  {
    num: '01',
    icon: Globe,
    title: 'URL Input',
    desc: 'User submits a URL. The system normalizes and validates it before processing.',
    color: 'from-blue-600 to-blue-500',
    glow: 'shadow-blue-900/40',
  },
  {
    num: '02',
    icon: Cpu,
    title: 'Feature Extraction',
    desc: 'Extracts 37+ features from URL structure, domain metadata, SSL certificate, and page content.',
    color: 'from-violet-600 to-purple-500',
    glow: 'shadow-purple-900/40',
  },
  {
    num: '03',
    icon: Brain,
    title: 'Parallel Detection',
    desc: 'Three engines run simultaneously: Heuristic rule-check, ML ensemble (RF + XGBoost), and Behavioral analysis.',
    color: 'from-cyan-600 to-cyan-500',
    glow: 'shadow-cyan-900/40',
  },
  {
    num: '04',
    icon: GitMerge,
    title: 'Decision Fusion',
    desc: 'Weighted scoring (Heuristic 35% · ML 45% · Behavioral 20%) produces a final composite risk score.',
    color: 'from-amber-600 to-orange-500',
    glow: 'shadow-orange-900/40',
  },
  {
    num: '05',
    icon: CheckCircle,
    title: 'Verdict',
    desc: 'URL classified as Legitimate, Suspicious, or Phishing with a risk score, explanation, and breakdown.',
    color: 'from-emerald-600 to-green-500',
    glow: 'shadow-emerald-900/40',
  },
]

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="py-24 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-14">
          <h2 className="section-heading mb-3">How PhishGuard Works</h2>
          <p className="text-gray-400 max-w-xl mx-auto">
            A five-stage pipeline that analyzes every URL through three independent detection layers
            before fusing results into a final verdict.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {steps.map(({ num, icon: Icon, title, desc, color, glow }, idx) => (
            <div key={num} className="relative glass rounded-2xl p-5 flex flex-col gap-4 hover:border-white/20 transition-colors">
              {/* Arrow connector */}
              {idx < steps.length - 1 && (
                <div className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-gray-600 text-lg font-bold">
                  →
                </div>
              )}

              <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${color} shadow-lg ${glow} flex items-center justify-center`}>
                <Icon className="w-5 h-5 text-white" />
              </div>

              <div>
                <div className="text-[10px] font-bold text-gray-600 tracking-widest mb-1">STEP {num}</div>
                <h3 className="font-semibold text-white text-sm mb-1.5">{title}</h3>
                <p className="text-gray-500 text-xs leading-relaxed">{desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Architecture diagram legend */}
        <div className="mt-12 glass rounded-2xl p-6">
          <h3 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">Detection Layer Weights</h3>
          <div className="grid grid-cols-3 gap-4 text-center">
            {[
              { label: 'Heuristic Engine', weight: '35%', desc: 'Blacklist + Rule-based', color: 'text-blue-400 bg-blue-900/30 border-blue-800' },
              { label: 'ML Engine', weight: '45%', desc: 'Random Forest + XGBoost', color: 'text-purple-400 bg-purple-900/30 border-purple-800' },
              { label: 'Behavioral Engine', weight: '20%', desc: 'Anomaly Simulation', color: 'text-cyan-400 bg-cyan-900/30 border-cyan-800' },
            ].map(({ label, weight, desc, color }) => (
              <div key={label} className={`rounded-xl p-4 border ${color}`}>
                <div className={`text-2xl font-black ${color.split(' ')[0]}`}>{weight}</div>
                <div className="text-sm font-semibold text-white mt-1">{label}</div>
                <div className="text-xs text-gray-500 mt-0.5">{desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
