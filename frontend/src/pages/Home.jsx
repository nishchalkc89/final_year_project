import Navbar from '../components/Navbar'
import Hero from '../components/Hero'
import ScanInput from '../components/ScanInput'
import HowItWorks from '../components/HowItWorks'
import AboutUs from '../components/AboutUs'
import Footer from '../components/Footer'

export default function Home() {
  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />
      <Hero />
      <ScanInput />
      <HowItWorks />
      <AboutUs />
      <Footer />
    </div>
  )
}
