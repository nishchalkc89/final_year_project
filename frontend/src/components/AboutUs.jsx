import { ShieldCheck, GraduationCap, Code2, Lightbulb } from 'lucide-react'

const cards = [
  {
    icon: ShieldCheck,
    title: 'Mission',
    desc: 'To protect everyday users from phishing attacks using state-of-the-art hybrid AI — combining explainable rules with machine learning precision.',
    color: 'text-blue-400',
    bg: 'bg-blue-900/20 border-blue-800/40',
  },
  {
    icon: GraduationCap,
    title: 'Research Foundation',
    desc: 'Built on the research paper "PhishGuard: A Hybrid Framework for Detecting Phishing Attacks" — a three-layer detection architecture validated on real-world datasets.',
    color: 'text-purple-400',
    bg: 'bg-purple-900/20 border-purple-800/40',
  },
  {
    icon: Code2,
    title: 'Technology',
    desc: 'FastAPI backend · SQLite persistence · React + Tailwind frontend · Scikit-learn Random Forest · XGBoost ensemble · Behavioral simulation engine.',
    color: 'text-cyan-400',
    bg: 'bg-cyan-900/20 border-cyan-800/40',
  },
  {
    icon: Lightbulb,
    title: 'Why Hybrid?',
    desc: 'No single method is perfect. Rules catch known patterns fast; ML generalizes to novel attacks; behavioral analysis detects evasive techniques — together they cover all bases.',
    color: 'text-amber-400',
    bg: 'bg-amber-900/20 border-amber-800/40',
  },
]

export default function AboutUs() {
  return (
    <section id="about" className="py-24 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-14">
          <h2 className="section-heading mb-3">About PhishGuard</h2>
          <p className="text-gray-400 max-w-xl mx-auto">
            A final-year research project demonstrating how a hybrid AI system
            outperforms single-method phishing detection approaches.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          {cards.map(({ icon: Icon, title, desc, color, bg }) => (
            <div key={title} className={`rounded-2xl border p-6 ${bg}`}>
              <div className="flex items-center gap-3 mb-3">
                <Icon className={`w-5 h-5 ${color}`} />
                <h3 className="font-semibold text-white">{title}</h3>
              </div>
              <p className="text-gray-400 text-sm leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>

        {/* Stats */}
        <div className="mt-10 grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { value: '37+', label: 'Features Extracted' },
            { value: '3', label: 'Detection Layers' },
            { value: '1000+', label: 'Training Samples' },
            { value: '~95%', label: 'Detection Accuracy' },
          ].map(({ value, label }) => (
            <div key={label} className="glass rounded-2xl p-5 text-center">
              <div className="text-3xl font-black text-white">{value}</div>
              <div className="text-xs text-gray-500 mt-1 font-medium">{label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
