export default function Download() {
  return (
    <section className="download" id="download">
      <div className="container download-grid">
        <div className="download-content reveal">
          <div className="about-index">
            <span className="section-num">03</span>
            <span className="section-line"></span>
            <span className="section-label">Download</span>
          </div>
          <h2 className="display-md">Take TailorX with you — <em>wherever your boutique takes you.</em></h2>
          <p className="lead">Manage your business from the cutting table, the shop floor, or on the move. TailorX is available as a web app and native apps for Android and iOS.</p>

          <div className="download-buttons">
            <a href="#" className="store-btn">
              <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M3 20.5V3.5c0-.59.34-1.11.84-1.36L13.69 12l-9.85 9.86c-.5-.25-.84-.77-.84-1.36zM16.81 15.12L6.05 21.34l8.49-8.49 2.27 2.27zM20.16 10.81c.5.34.84.91.84 1.19 0 .28-.34.85-.84 1.19l-2.7 1.55-2.51-2.51v-.46l2.51-2.51 2.7 1.55zM6.05 2.66l10.76 6.22-2.27 2.27-8.49-8.49z" /></svg>
              <span>
                <small>Get it on</small>
                Google Play
              </span>
            </a>
            <a href="#" className="store-btn">
              <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M17.05 12.04c-.02-2.13 1.74-3.15 1.82-3.2-1-1.46-2.55-1.66-3.1-1.69-1.4-.14-2.74.82-3.45.82-.72 0-1.84-.8-3.02-.78-1.55.02-3 .9-3.79 2.29-1.62 2.81-.42 7.18 1.16 9.53.77 1.15 1.69 2.43 2.9 2.39 1.16-.05 1.6-.75 3.01-.75 1.4 0 1.81.75 3.04.73 1.26-.02 2.06-1.14 2.83-2.3.89-1.32 1.26-2.6 1.28-2.66-.03-.01-2.45-.94-2.68-3.38zM14.91 4.21c.65-.79 1.09-1.88.97-2.97-.94.04-2.08.63-2.76 1.41-.6.69-1.13 1.79-.99 2.84 1.04.08 2.1-.53 2.78-1.28z" /></svg>
              <span>
                <small>Download on the</small>
                App Store
              </span>
            </a>
            <a href="#" className="store-btn store-btn--web">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></svg>
              <span>
                <small>Launch the</small>
                Web App
              </span>
            </a>
          </div>
        </div>

        <div className="download-visual reveal">
          <div className="phone-mock">
            <div className="phone-notch"></div>
            <div className="phone-screen">
              <div className="mock-topbar">
                <span className="mock-dot"></span>
                <span className="mock-title">Today's Overview</span>
              </div>
              <div className="mock-card mock-card--big">
                <span className="mock-label">Revenue (Today)</span>
                <span className="mock-value">₹18,450</span>
                <span className="mock-trend">▲ 12% vs yesterday</span>
              </div>
              <div className="mock-row">
                <div className="mock-card">
                  <span className="mock-label">New Orders</span>
                  <span className="mock-value mock-value--sm">6</span>
                </div>
                <div className="mock-card">
                  <span className="mock-label">Pending</span>
                  <span className="mock-value mock-value--sm">14</span>
                </div>
              </div>
              <div className="mock-card mock-card--list">
                <span className="mock-label">Recent Orders</span>
                <div className="mock-list-item"><span>Anika Sharma — Lehenga</span><span className="tag tag--progress">Stitching</span></div>
                <div className="mock-list-item"><span>R. Verma — Blazer Set</span><span className="tag tag--done">Ready</span></div>
                <div className="mock-list-item"><span>Priya Nair — Saree Blouse</span><span className="tag tag--new">New</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
