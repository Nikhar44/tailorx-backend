const PLANS = [
  {
    name: 'Basic Monthly',
    desc: 'Everything you need to run your boutique, day to day.',
    price: '199',
    period: '/month',
    features: [
      'Customer management',
      'Measurements',
      'Order tracking',
      'Job cards',
      'GST-enabled invoicing',
      'Trial & delivery tracking',
    ],
    cta: 'Start Free Trial',
    featured: false,
  },
  {
    name: 'Basic Yearly',
    desc: 'The full Basic plan — pay yearly and save.',
    price: '1,999',
    period: '/year',
    badge: 'Save ₹389',
    features: [
      'Customer management',
      'Measurements',
      'Order tracking',
      'Job cards',
      'GST-enabled invoicing',
      'Trial & delivery tracking',
    ],
    cta: 'Start Free Trial',
    featured: false,
  },
  {
    name: 'Pro Monthly',
    desc: 'Basic, plus a head start on every measurement.',
    price: '399',
    period: '/month',
    features: [
      'Everything in Basic',
      'AI Measurement Suggestions (20–30/month)',
    ],
    cta: 'Start Free Trial',
    featured: false,
  },
  {
    name: 'Pro Yearly',
    desc: 'Best value for boutiques that lean on AI every day.',
    price: '3,999',
    period: '/year',
    features: [
      'Everything in Basic',
      'AI Measurement Suggestions — Unlimited',
    ],
    highlightLast: true,
    badge: 'Best Value',
    tagline: 'Unlimited AI Measurements, only on yearly Pro.',
    cta: 'Start Free Trial',
    featured: true,
  },
]

export default function Pricing() {
  return (
    <section className="pricing" id="pricing">
      <div className="container">
        <div className="section-head section-head--center reveal">
          <div className="about-index about-index--center">
            <span className="section-num">04</span>
            <span className="section-line"></span>
            <span className="section-label">Pricing</span>
          </div>
          <h2 className="display-md">Simple plans, priced for <em>Indian boutiques.</em></h2>
          <p className="lead">All plans include the full TailorX experience across Web, Android and iOS. Activation is handled personally — just reach out and we'll set you up.</p>
        </div>

        <div className="pricing-grid pricing-grid--4">
          {PLANS.map((plan) => (
            <div className={`price-card reveal ${plan.featured ? 'price-card--featured' : ''}`} key={plan.name}>
              {plan.badge && <span className={`price-badge ${plan.featured ? '' : 'price-badge--subtle'}`}>{plan.badge}</span>}
              <h3>{plan.name}</h3>
              <p className="price-desc">{plan.desc}</p>
              <div className="price-amount">
                <span className="currency">₹</span>{plan.price}<span className="period">{plan.period}</span>
              </div>
              <ul className="price-features">
                {plan.features.map((f, i) => (
                  <li
                    key={f}
                    className={plan.highlightLast && i === plan.features.length - 1 ? 'price-feature--highlight' : ''}
                  >
                    {f}
                  </li>
                ))}
              </ul>
              {plan.tagline && <p className="price-tagline">{plan.tagline}</p>}
              <a
                href="#contact"
                className={`btn btn-block ${plan.featured ? 'btn-primary' : 'btn-outline'}`}
              >
                {plan.cta}
              </a>
            </div>
          ))}
        </div>
        <p className="price-note">No card required to get started. Subscriptions and upgrades are activated manually by our team — just contact us and we'll set you up, typically within a few hours.</p>
      </div>
    </section>
  )
}
