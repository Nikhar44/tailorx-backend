import Header from './components/Header.jsx'
import Hero from './components/Hero.jsx'
import About from './components/About.jsx'
import Features from './components/Features.jsx'
import Download from './components/Download.jsx'
import Pricing from './components/Pricing.jsx'
import Reviews from './components/Reviews.jsx'
import Contact from './components/Contact.jsx'
import Footer from './components/Footer.jsx'
import useReveal from './hooks/useReveal.js'

export default function App() {
  useReveal()

  return (
    <>
      <div className="grain" />
      <Header />
      <Hero />
      <About />
      <Features />
      <Download />
      <Pricing />
      <Reviews />
      <Contact />
      <Footer />
    </>
  )
}
