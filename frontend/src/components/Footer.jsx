import { Shield, Github, Lock } from 'lucide-react'
import { Link } from 'react-router-dom'

export default function Footer() {
  return (
    <footer className="border-t border-white/10 py-10 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
          {/* Brand */}
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-white" />
            </div>
            <span className="font-bold text-white tracking-tight">
              Phish<span className="text-blue-400">Guard</span>
            </span>
          </div>

          {/* Links */}
          <nav className="flex items-center gap-5 text-sm text-gray-500">
            <a href="#home" className="hover:text-gray-300 transition-colors">Home</a>
            <a href="#scan" className="hover:text-gray-300 transition-colors">Scan</a>
            <a href="#how-it-works" className="hover:text-gray-300 transition-colors">How It Works</a>
            <a href="#about" className="hover:text-gray-300 transition-colors">About</a>
            <Link
              to="/admin/login"
              className="flex items-center gap-1.5 hover:text-gray-300 transition-colors"
            >
              <Lock className="w-3 h-3" />
              Admin
            </Link>
          </nav>

          {/* Copyright */}
          <p className="text-xs text-gray-600">
            © {new Date().getFullYear()} PhishGuard — Final Year Project
          </p>
        </div>
      </div>
    </footer>
  )
}
