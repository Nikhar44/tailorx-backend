import { useState } from 'react'

export default function Contact() {
  const [note, setNote] = useState('')
  const [form, setForm] = useState({ name: '', boutique: '', email: '', phone: '', message: '' })

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!form.name || !form.email || !form.message) {
      setNote('Please fill in your name, email and message.')
      return
    }
    setNote("Thanks! We've received your message and will get back to you shortly.")
    setForm({ name: '', boutique: '', email: '', phone: '', message: '' })
  }

  return (
    <section className="contact" id="contact">
      <div className="container">
        <div className="section-head section-head--center reveal">
          <div className="about-index about-index--center">
            <span className="section-num">06</span>
            <span className="section-line"></span>
            <span className="section-label">Contact</span>
          </div>
          <h2 className="display-md">Let's get your boutique <em>set up.</em></h2>
          <p className="lead">Have questions about plans, features or onboarding? Reach us however suits you best — we're happy to help.</p>
        </div>

        <div className="contact-channels reveal">
          <a href="https://wa.me/918469696966" target="_blank" rel="noopener noreferrer" className="channel-card">
            <span className="channel-icon channel-icon--whatsapp">
              <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12.04 2c-5.46 0-9.91 4.45-9.91 9.91 0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38c1.45.79 3.08 1.21 4.74 1.21h.01c5.46 0 9.91-4.45 9.91-9.91 0-2.65-1.03-5.14-2.9-7.01A9.82 9.82 0 0 0 12.04 2zm0 1.67c2.21 0 4.29.86 5.85 2.42a8.23 8.23 0 0 1 2.43 5.85c0 4.56-3.71 8.27-8.28 8.27a8.3 8.3 0 0 1-4.22-1.15l-.3-.18-3.12.82.83-3.04-.2-.31a8.26 8.26 0 0 1-1.27-4.41c0-4.57 3.71-8.27 8.28-8.27zm-4.5 4.73c-.15 0-.4.06-.57.27-.18.21-.7.68-.7 1.66s.72 1.93.82 2.06c.1.13 1.39 2.27 3.51 3.1 1.76.68 2.1.54 2.49.5.39-.03 1.27-.52 1.45-1.02.18-.5.18-.93.12-1.02-.05-.1-.23-.15-.49-.28-.26-.13-1.55-.77-1.79-.85-.24-.09-.42-.13-.6.13-.18.26-.68.85-.83 1.02-.15.18-.31.2-.57.07-.26-.13-1.09-.4-2.07-1.27-.77-.68-1.28-1.52-1.43-1.78-.15-.26-.02-.4.13-.55.13-.13.3-.34.45-.51.15-.18.2-.3.3-.5.1-.2.05-.37-.02-.51-.07-.15-.62-1.52-.86-2.07-.18-.43-.37-.43-.54-.44-.14 0-.3-.01-.46-.01z" />
              </svg>
            </span>
            <span className="channel-body">
              <span className="channel-label">WhatsApp</span>
              <strong>+91 84696 96966</strong>
              <span className="channel-meta">Fastest response</span>
            </span>
            <svg className="channel-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M5 12h14M13 6l6 6-6 6" />
            </svg>
          </a>

          <a href="tel:+918469696966" className="channel-card">
            <span className="channel-icon channel-icon--call">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.362 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.338 1.85.573 2.81.7A2 2 0 0 1 22 16.92z" />
              </svg>
            </span>
            <span className="channel-body">
              <span className="channel-label">Call us</span>
              <strong>+91 84696 96966</strong>
              <span className="channel-meta">Mon–Sat, 10am–7pm</span>
            </span>
            <svg className="channel-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M5 12h14M13 6l6 6-6 6" />
            </svg>
          </a>

          <a href="mailto:tailorxapp@gmail.com" className="channel-card">
            <span className="channel-icon channel-icon--mail">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M4 4h16v16H4V4z" />
                <path d="M22 6 12 13 2 6" />
              </svg>
            </span>
            <span className="channel-body">
              <span className="channel-label">Email</span>
              <strong>tailorxapp@gmail.com</strong>
              <span className="channel-meta">We reply within a day</span>
            </span>
            <svg className="channel-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M5 12h14M13 6l6 6-6 6" />
            </svg>
          </a>
        </div>

        <div className="contact-form-wrap reveal">
          <div className="contact-form-head">
            <h3>Or send us a message</h3>
            <p>Tell us a little about your boutique and we'll get back to you on whichever channel you prefer.</p>
          </div>
          <form className="contact-form" onSubmit={handleSubmit}>
            <div className="form-grid">
              <div className="form-row">
                <label htmlFor="name">Name</label>
                <input type="text" id="name" name="name" placeholder="Your name" value={form.name} onChange={handleChange} required />
              </div>
              <div className="form-row">
                <label htmlFor="boutique">Boutique / Studio name</label>
                <input type="text" id="boutique" name="boutique" placeholder="e.g. Stitch & Style" value={form.boutique} onChange={handleChange} />
              </div>
              <div className="form-row">
                <label htmlFor="email">Email</label>
                <input type="email" id="email" name="email" placeholder="you@example.com" value={form.email} onChange={handleChange} required />
              </div>
              <div className="form-row">
                <label htmlFor="phone">Phone</label>
                <input type="tel" id="phone" name="phone" placeholder="+91 00000 00000" value={form.phone} onChange={handleChange} />
              </div>
            </div>
            <div className="form-row">
              <label htmlFor="message">Message</label>
              <textarea id="message" name="message" rows="4" placeholder="Tell us about your boutique and what you're looking for..." value={form.message} onChange={handleChange} required></textarea>
            </div>
            <button type="submit" className="btn btn-primary btn-block">Send Message</button>
            <p className="form-note">{note}</p>
          </form>
        </div>
      </div>
    </section>
  )
}
