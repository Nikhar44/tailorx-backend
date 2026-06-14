/* Current dashboard — recreated faithfully from the Flutter source */
const CurrentDashboard = () => {
  return (
    <div className="screen current">
      <div className="appbar">
        <div className="appbar-left">
          <div className="logo-chip">TX</div>
          <div className="boutique">Anjali Boutique</div>
        </div>
        <div className="appbar-actions">
          <span className="ic">⌕</span>
          <span className="ic dot">◔</span>
        </div>
      </div>

      <div className="body">
        <div className="overview">
          <div className="overview-title">Overview</div>
          <div className="overview-date">Friday, 24 April</div>
        </div>

        <div className="grid">
          {[
            { l: "Total Customers", v: "248", c: "info" },
            { l: "Total Orders", v: "1,432", c: "purple" },
            { l: "Revenue", v: "₹4,82,500", c: "success" },
            { l: "Pending", v: "₹38,200", c: "warning" },
          ].map((s, i) => (
            <div key={i} className="stat">
              <div className={`stat-ic ${s.c}`}>■</div>
              <div className="stat-v">{s.v}</div>
              <div className="stat-l">{s.l.toUpperCase()}</div>
            </div>
          ))}
        </div>

        <div className="alert">
          <div className="alert-ic">!</div>
          <div>
            <div className="alert-t">12 pending orders</div>
            <div className="alert-s">Require attention</div>
          </div>
        </div>

        <div className="section-h">RECENT ORDERS</div>

        {[
          { n: "Priya Sharma", d: "Lehenga (Silk) x1, Blouse", a: "₹18,500", s: "stitching" },
          { n: "Meera Patel", d: "Anarkali Suit (Georgette)", a: "₹12,000", s: "trial" },
          { n: "Riya Kapoor", d: "Saree Blouse (Cotton) x2", a: "₹3,200", s: "ready" },
          { n: "Anita Reddy", d: "Kurta Set (Linen)", a: "₹5,800", s: "cutting" },
        ].map((o, i) => (
          <div key={i} className="order-row">
            <div className={`bar ${o.s}`}></div>
            <div className="order-mid">
              <div className="order-n">{o.n}</div>
              <div className="order-d">{o.d}</div>
            </div>
            <div className="order-right">
              <div className="order-a">{o.a}</div>
              <div className={`badge ${o.s}`}>
                <span className="dot" /> {o.s.toUpperCase()}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="tabbar">
        {[
          ["▦", "Dashboard", true],
          ["♟", "Customers"],
          ["▤", "Orders"],
          ["₹", "Invoices"],
          ["⚙", "Settings"],
        ].map(([ic, l, a], i) => (
          <div key={i} className={`tab ${a ? "active" : ""}`}>
            <span>{ic}</span>
            <small>{l}</small>
          </div>
        ))}
      </div>
    </div>
  );
};

window.CurrentDashboard = CurrentDashboard;
