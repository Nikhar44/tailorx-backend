import { useRef } from 'react'
import { useWaterRipple } from '../hooks/useWaterRipple'

const TAPE_ITEMS = [
  'MEASUREMENTS', 'ORDERS', 'INVOICES', 'GST', 'INVENTORY', 'STAFF', 'EXPENSES', 'REVENUE',
]

export default function Hero() {
  const tape = [...TAPE_ITEMS, ...TAPE_ITEMS]
  const heroRef = useRef(null)
  const canvasRef = useWaterRipple(heroRef)

  return (
    <section className="hero" id="home" ref={heroRef}>
      <div className="hero-bg">
        <svg className="hero-pattern" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="stitch" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M0 20 L10 20" stroke="currentColor" strokeWidth="1" strokeDasharray="4 4" />
              <path d="M20 20 L40 20" stroke="currentColor" strokeWidth="1" strokeDasharray="4 4" />
            </pattern>
          </defs>
          <g className="hero-waves" stroke="currentColor" fill="none" strokeWidth="1.4">
            <path d="M-50,120 C150,40 350,200 600,120 C850,40 1050,200 1250,120" />
            <path d="M-50,260 C150,180 350,340 600,260 C850,180 1050,340 1250,260" />
            <path d="M-50,400 C150,320 350,480 600,400 C850,320 1050,480 1250,400" />
            <path d="M-50,540 C150,460 350,620 600,540 C850,460 1050,620 1250,540" />
            <path d="M-50,680 C150,600 350,760 600,680 C850,600 1050,760 1250,680" />
          </g>
        </svg>
      </div>

      <canvas className="hero-ripple-canvas" ref={canvasRef} aria-hidden="true"></canvas>

      <div className="container hero-inner">
        <p className="eyebrow fade-up" data-delay="0">Web · Android · iOS</p>
        <h1 className="hero-title">
          <span className="fade-up" data-delay="1">Run your boutique</span>
          <span className="fade-up hero-script" data-delay="2">like the brand it deserves to be.</span>
        </h1>
        <p className="hero-sub fade-up" data-delay="3">
          TailorX brings customer measurements, orders, billing with GST, inventory,
          staff and revenue into one elegant workspace — built for fashion designers
          and tailoring boutiques across India.
        </p>
        <div className="hero-actions fade-up" data-delay="4">
          <a href="#download" className="btn btn-primary">Download the App</a>
          <a href="https://wa.me/918469696966" target="_blank" rel="noopener noreferrer" className="btn btn-ghost">
            <svg className="ico" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12.04 2c-5.46 0-9.91 4.45-9.91 9.91 0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38c1.45.79 3.08 1.21 4.74 1.21h.01c5.46 0 9.91-4.45 9.91-9.91 0-2.65-1.03-5.14-2.9-7.01A9.82 9.82 0 0 0 12.04 2zm0 1.67c2.21 0 4.29.86 5.85 2.42a8.23 8.23 0 0 1 2.43 5.85c0 4.56-3.71 8.27-8.28 8.27a8.3 8.3 0 0 1-4.22-1.15l-.3-.18-3.12.82.83-3.04-.2-.31a8.26 8.26 0 0 1-1.27-4.41c0-4.57 3.71-8.27 8.28-8.27zm-4.5 4.73c-.15 0-.4.06-.57.27-.18.21-.7.68-.7 1.66s.72 1.93.82 2.06c.1.13 1.39 2.27 3.51 3.1 1.76.68 2.1.54 2.49.5.39-.03 1.27-.52 1.45-1.02.18-.5.18-.93.12-1.02-.05-.1-.23-.15-.49-.28-.26-.13-1.55-.77-1.79-.85-.24-.09-.42-.13-.6.13-.18.26-.68.85-.83 1.02-.15.18-.31.2-.57.07-.26-.13-1.09-.4-2.07-1.27-.77-.68-1.28-1.52-1.43-1.78-.15-.26-.02-.4.13-.55.13-.13.3-.34.45-.51.15-.18.2-.3.3-.5.1-.2.05-.37-.02-.51-.07-.15-.62-1.52-.86-2.07-.18-.43-.37-.43-.54-.44-.14 0-.3-.01-.46-.01z" />
            </svg>
            WhatsApp Us
          </a>
        </div>

        <div className="hero-stats fade-up" data-delay="5">
          <div className="stat">
            <span className="stat-num">7</span>
            <span className="stat-label">Core modules<br />in one app</span>
          </div>
          <div className="stat">
            <span className="stat-num">₹</span>
            <span className="stat-label">GST-ready<br />invoicing</span>
          </div>
          <div className="stat">
            <span className="stat-num">3</span>
            <span className="stat-label">Platforms —<br />Web, Android, iOS</span>
          </div>
        </div>
      </div>

      <div className="hero-tape" aria-hidden="true">
        <div className="tape-track">
          {tape.map((item, i) => (
            <span key={i}>{item}{i < tape.length - 1 ? ' ·' : ''}</span>
          ))}
        </div>
      </div>
    </section>
  )
}
