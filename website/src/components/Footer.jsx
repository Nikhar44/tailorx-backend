import { useRef } from 'react'
import { useWaterRipple } from '../hooks/useWaterRipple'

export default function Footer() {
  const year = new Date().getFullYear()
  const footerRef = useRef(null)
  const canvasRef = useWaterRipple(footerRef)

  return (
    <footer className="site-footer" ref={footerRef}>
      <canvas className="hero-ripple-canvas" ref={canvasRef} aria-hidden="true"></canvas>
      <div className="container footer-cta reveal">
        <h2 className="display-md">Ready to run your boutique <em>the easy way?</em></h2>
        <p>Join boutiques and tailoring studios across India already managing their business with TailorX.</p>
        <div className="footer-cta-actions">
          <a href="#download" className="btn btn-primary">Download the App</a>
          <a href="https://wa.me/918469696966" target="_blank" rel="noopener noreferrer" className="btn btn-ghost">WhatsApp Us</a>
        </div>
      </div>

      <div className="container footer-inner">
        <div className="footer-brand">
          <a href="#top" className="logo">Tailor<span>X</span></a>
          <p>The all-in-one management app for fashion boutiques and tailoring studios.</p>
        </div>
        <div className="footer-links">
          <div>
            <h4>Product</h4>
            <a href="#features">Features</a>
            <a href="#pricing">Pricing</a>
            <a href="#download">Download</a>
          </div>
          <div>
            <h4>Company</h4>
            <a href="#about">About</a>
            <a href="#reviews">Reviews</a>
            <a href="#contact">Contact</a>
          </div>
          <div>
            <h4>Get in touch</h4>
            <a href="https://wa.me/918469696966" target="_blank" rel="noopener noreferrer">WhatsApp: +91 84696 96966</a>
            <a href="mailto:tailorxapp@gmail.com">tailorxapp@gmail.com</a>
          </div>
        </div>
      </div>
      <div className="container footer-bottom">
        <span>© {year} TailorX. All rights reserved.</span>
        <span>Made for boutiques across India 🇮🇳</span>
      </div>
    </footer>
  )
}
