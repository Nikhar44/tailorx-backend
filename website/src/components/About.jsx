export default function About() {
  return (
    <section className="about" id="about">
      <div className="container about-grid">
        <div className="about-index reveal">
          <span className="section-num">01</span>
          <span className="section-line"></span>
          <span className="section-label">About TailorX</span>
        </div>
        <div className="about-content reveal">
          <h2 className="display-md">
            Built in the back office of real boutiques —{' '}
            <em>not a generic spreadsheet.</em>
          </h2>
          <p className="lead">
            TailorX was designed alongside fashion designers and tailoring studios
            who were drowning in WhatsApp measurement notes, paper order books and
            manual GST bills. We replaced the chaos with one calm, connected system —
            available on the web, and as native apps for Android and iOS.
          </p>
          <div className="about-points">
            <div className="point reveal">
              <h3>For boutique owners</h3>
              <p>See your revenue, outstanding orders and expenses at a glance — from your phone or desktop.</p>
            </div>
            <div className="point reveal">
              <h3>For your tailors &amp; staff</h3>
              <p>Give your team structured access to orders and measurements without losing control.</p>
            </div>
            <div className="point reveal">
              <h3>For your customers</h3>
              <p>Faster turnarounds, accurate fits and professional GST invoices every time.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
