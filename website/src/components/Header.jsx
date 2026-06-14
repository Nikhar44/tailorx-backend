import { useEffect, useState } from 'react'

const NAV_LINKS = [
  { href: '#about', label: 'About' },
  { href: '#features', label: 'Features' },
  { href: '#pricing', label: 'Pricing' },
  { href: '#reviews', label: 'Reviews' },
  { href: '#download', label: 'Download' },
  { href: '#contact', label: 'Contact' },
]

export default function Header() {
  const [open, setOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <header className={`site-header ${scrolled ? 'site-header--scrolled' : ''}`} id="top">
      <div className="container header-inner">
        <a href="#top" className="logo">Tailor<span>X</span></a>

        <nav className={`nav-links ${open ? 'nav-links--open' : ''}`}>
          {NAV_LINKS.map((link) => (
            <a key={link.href} href={link.href} onClick={() => setOpen(false)}>
              {link.label}
            </a>
          ))}
        </nav>

        <a href="#contact" className="btn btn-small btn-outline header-cta">Get Started</a>

        <button
          className={`nav-toggle ${open ? 'nav-toggle--open' : ''}`}
          aria-label="Toggle navigation"
          onClick={() => setOpen((o) => !o)}
        >
          <span></span><span></span><span></span>
        </button>
      </div>
    </header>
  )
}
