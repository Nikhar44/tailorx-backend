const REVIEWS = [
  {
    text: '"TailorX took our measurement books out of the drawer and into the cloud. Our tailors now know exactly what\'s pending every morning."',
    name: 'Ritu Malhotra',
    studio: 'Stitch & Style, Jaipur',
    initials: 'RM',
  },
  {
    text: '"GST billing used to take my accountant hours every month. Now invoices are generated the moment an order is delivered."',
    name: 'Arvind Kapoor',
    studio: 'Kapoor Couture, Lucknow',
    initials: 'AK',
  },
  {
    text: '"The revenue dashboard alone is worth it. I can finally see which months are actually profitable, not just busy."',
    name: 'Sneha Nair',
    studio: 'Threadline Studio, Kochi',
    initials: 'SN',
  },
  {
    text: '"Switching from three different notebooks to one app sounded daunting, but the team set everything up for us over WhatsApp."',
    name: 'Vikram Patel',
    studio: 'Drape House, Ahmedabad',
    initials: 'VP',
  },
]

export default function Reviews() {
  return (
    <section className="reviews" id="reviews">
      <div className="container">
        <div className="section-head reveal">
          <div className="about-index">
            <span className="section-num">05</span>
            <span className="section-line"></span>
            <span className="section-label">Reviews</span>
          </div>
          <h2 className="display-md">Loved by boutiques <em>across India.</em></h2>
        </div>

        <div className="reviews-track">
          {REVIEWS.map((r) => (
            <div className="review-card reveal" key={r.name}>
              <div className="stars">★★★★★</div>
              <p>{r.text}</p>
              <div className="review-author">
                <span className="avatar">{r.initials}</span>
                <div><strong>{r.name}</strong><span>{r.studio}</span></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
