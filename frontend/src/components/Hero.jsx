import { Shield, Zap, Brain, Eye } from 'lucide-react'

const pillars = [
  { icon: Shield, label: 'Heuristic Engine', color: 'text-blue-400' },
  { icon: Brain, label: 'ML Detection', color: 'text-purple-400' },
  { icon: Eye, label: 'Behavioral Analysis', color: 'text-cyan-400' },
]

export default function Hero() {
  return (
    <section id="home" className="relative min-h-screen flex items-center justify-center overflow-hidden pt-16">
      {/* Background gradients */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-600/15 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-purple-600/10 rounded-full blur-3xl" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_rgba(59,130,246,0.04)_0%,_transparent_70%)]" />
        {/* Grid pattern */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: 'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
          }}
        />
      </div>

      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 text-center">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass border border-blue-500/30 text-blue-400 text-xs font-semibold tracking-widest uppercase mb-8">
          <Zap className="w-3.5 h-3.5" />
          AI-Powered Hybrid Detection System
        </div>

        {/* Heading */}
        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold text-white leading-tight tracking-tight mb-6">
          Stay Safe From{' '}
          <span className="bg-gradient-to-r from-blue-400 via-blue-300 to-cyan-400 bg-clip-text text-transparent">
            Phishing
          </span>{' '}
          Attacks
        </h1>

        <p className="text-lg sm:text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed mb-10">
          PhishGuard uses a three-layer hybrid framework — combining rule-based heuristics,
          machine learning, and behavioral analysis — to detect phishing URLs with high accuracy.
        </p>

        {/* CTA */}
        <a
          href="#scan"
          className="btn-primary text-base px-8 py-4 rounded-2xl shadow-xl shadow-blue-900/40"
        >
          <Shield className="w-5 h-5" />
          Scan a URL Now
        </a>

        {/* Pillars */}
        <div className="mt-16 grid grid-cols-3 gap-4 max-w-lg mx-auto">
          {pillars.map(({ icon: Icon, label, color }) => (
            <div key={label} className="glass rounded-2xl p-4 flex flex-col items-center gap-2">
              <Icon className={`w-6 h-6 ${color}`} />
              <span className="text-xs font-medium text-gray-400 text-center leading-tight">{label}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
