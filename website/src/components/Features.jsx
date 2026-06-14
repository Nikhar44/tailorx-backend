const FEATURES = [
  {
    title: 'Customer & Measurement Management',
    desc: "Every customer's measurements, preferences and order history live in one place — so the next visit feels personal, not like starting from scratch.",
    large: true,
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="18" cy="16" r="7" stroke="currentColor" strokeWidth="2" />
        <path d="M6 40c0-7 5-12 12-12s12 5 12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        <path d="M28 12h12M28 18h8M28 24h12M28 30h6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    title: 'Order Tracking',
    desc: 'Follow every order from cutting to stitching to ready to delivered — you and your team always know what stage it\'s at and what\'s due next.',
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="8" y="6" width="32" height="36" rx="2" stroke="currentColor" strokeWidth="2" />
        <path d="M15 16h18M15 24h18M15 32h10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        <circle cx="34" cy="32" r="2" fill="currentColor" />
      </svg>
    ),
  },
  {
    title: 'Billing & GST Invoicing',
    desc: 'Send polished, GST-ready bills in a few taps — look professional with every customer and stay on top of your taxes without extra effort.',
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M10 8h28v32l-5-3-5 3-5-3-5 3-5-3-3 3V8z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M16 18h16M16 24h16M16 30h8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    title: 'Revenue Dashboard',
    desc: 'See how your boutique is really doing at a glance — what\'s coming in, what\'s pending, and how this month compares to the last.',
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M8 38V22M18 38V14M28 38V26M38 38V8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        <path d="M6 38h36" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    title: 'Employee Management',
    desc: 'Bring your tailors and staff onto the app, hand out work, and keep everyone on the same page — no more juggling notebooks and phone calls.',
    large: true,
    upcoming: true,
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="16" cy="12" r="5" stroke="currentColor" strokeWidth="2" />
        <circle cx="32" cy="12" r="5" stroke="currentColor" strokeWidth="2" />
        <path d="M6 38c0-6 4.5-10 10-10s10 4 10 10M22 38c0-6 4.5-10 10-10s10 4 10 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    title: 'Inventory Management',
    desc: "Always know what fabric and supplies you have on hand — never get caught short before a big order.",
    upcoming: true,
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M24 4 6 12v10c0 11 7.5 18.5 18 22 10.5-3.5 18-11 18-22V12L24 4z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M16 22l8 8 12-14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
  },
  {
    title: 'Daily Expense Tracking',
    desc: 'Note down everyday costs as they happen, so you always know what you\'re really keeping — not just what\'s coming in.',
    upcoming: true,
    icon: (
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="24" cy="24" r="18" stroke="currentColor" strokeWidth="2" />
        <path d="M24 14v10l7 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
  },
]

export default function Features() {
  return (
    <section className="features" id="features">
      <div className="container">
        <div className="section-head reveal">
          <div className="about-index">
            <span className="section-num">02</span>
            <span className="section-line"></span>
            <span className="section-label">Features</span>
          </div>
          <h2 className="display-md">Everything your boutique runs on — <em>in one place.</em></h2>
        </div>

        <div className="feature-grid">
          {FEATURES.map((f) => (
            <article className={`feature-card reveal ${f.large ? 'feature-card--large' : ''}`} key={f.title}>
              <div className="feature-icon">{f.icon}</div>
              <h3>{f.title}{f.upcoming && <span className="feature-badge">Coming Soon</span>}</h3>
              <p>{f.desc}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
