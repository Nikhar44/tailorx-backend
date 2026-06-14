/* Improved dashboard — concrete upgrades with rich animation */
const { useState, useEffect, useRef } = React;

/* Animated counter that eases up to its target */
const Counter = ({ to, prefix = "", duration = 1200, decimals = 0 }) => {
  const [v, setV] = useState(0);
  const startedRef = useRef(false);
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    const start = performance.now();
    let raf;
    const tick = (t) => {
      const p = Math.min(1, (t - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setV(to * eased);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [to, duration]);
  const formatted = decimals === 0
    ? Math.round(v).toLocaleString("en-IN")
    : v.toFixed(decimals);
  return <span>{prefix}{formatted}</span>;
};

/* Sparkline that draws itself in */
const Sparkline = ({ data, color = "#D4A574", height = 28, width = 80, delay = 0 }) => {
  const pathRef = useRef(null);
  const [len, setLen] = useState(0);
  useEffect(() => {
    if (pathRef.current) setLen(pathRef.current.getTotalLength());
  }, []);
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const step = width / (data.length - 1);
  const pts = data.map((d, i) => [i * step, height - ((d - min) / range) * (height - 4) - 2]);
  const dPath = pts.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(" ");
  const fillPath = `${dPath} L${width},${height} L0,${height} Z`;
  return (
    <svg width={width} height={height} className="spark" style={{ animationDelay: `${delay}ms` }}>
      <defs>
        <linearGradient id={`g-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={fillPath} fill={`url(#g-${color.replace("#","")})`} className="spark-fill" style={{ animationDelay: `${delay+200}ms` }} />
      <path
        ref={pathRef}
        d={dPath}
        fill="none"
        stroke={color}
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray={len}
        strokeDashoffset={len}
        className="spark-line"
        style={{ animationDelay: `${delay}ms` }}
      />
    </svg>
  );
};

/* Animated radial — capacity / workload meter */
const Radial = ({ value = 0.62, color = "#D4A574", size = 64 }) => {
  const r = (size - 8) / 2;
  const c = 2 * Math.PI * r;
  return (
    <svg width={size} height={size} className="radial">
      <circle cx={size/2} cy={size/2} r={r} stroke="#E8E5DF" strokeWidth="4" fill="none" />
      <circle
        cx={size/2} cy={size/2} r={r}
        stroke={color} strokeWidth="4" fill="none"
        strokeLinecap="round"
        strokeDasharray={c}
        strokeDashoffset={c}
        style={{ "--target": c * (1 - value) }}
        className="radial-fill"
        transform={`rotate(-90 ${size/2} ${size/2})`}
      />
      <text x="50%" y="50%" textAnchor="middle" dy="0.35em" className="radial-t">
        {Math.round(value * 100)}%
      </text>
    </svg>
  );
};

/* Stitched progress bar — a literal needle stitches across to fill the bar.
   This is the "proper animation" — bespoke to the tailoring metaphor. */
const StitchProgress = ({ value = 0.55, color = "#D4A574" }) => {
  return (
    <div className="stitch-wrap">
      <div className="stitch-track">
        <div className="stitch-fill" style={{ width: `${value*100}%`, background: color }} />
        <div className="stitch-dashes" style={{ width: `${value*100}%` }}>
          {Array.from({ length: 24 }).map((_, i) => (
            <span key={i} style={{ animationDelay: `${i * 60}ms` }} />
          ))}
        </div>
        <div className="needle" style={{ left: `${value*100}%` }}>
          <svg width="22" height="22" viewBox="0 0 22 22">
            <line x1="3" y1="19" x2="18" y2="4" stroke="#1A1A2E" strokeWidth="1.4" strokeLinecap="round" />
            <circle cx="18" cy="4" r="1.5" fill="#D4A574" />
            <circle cx="3" cy="19" r="0.8" fill="#1A1A2E" />
          </svg>
          <div className="thread" />
        </div>
      </div>
    </div>
  );
};

const ImprovedDashboard = () => {
  const [tick, setTick] = useState(0);
  // re-trigger animations on remount via key
  return (
    <div className="screen improved" key={tick}>
      <div className="appbar gradient">
        <div className="appbar-left">
          <div className="logo-chip premium">
            <span>TX</span>
            <i className="shimmer" />
          </div>
          <div>
            <div className="boutique">Anjali Boutique</div>
            <div className="greeting">Good evening, Anjali</div>
          </div>
        </div>
        <div className="appbar-actions">
          <button className="ic-btn" onClick={() => setTick(t => t+1)} title="replay">↻</button>
          <button className="ic-btn">⌕</button>
          <button className="ic-btn"><span className="ic">◔</span><i className="badge-dot" /></button>
        </div>
      </div>

      <div className="body">
        {/* Hero KPI — focal "Today" card with sparkline */}
        <div className="hero-card stagger" style={{ "--i": 0 }}>
          <div className="hero-top">
            <div>
              <div className="hero-label">REVENUE · TODAY</div>
              <div className="hero-v">
                ₹<Counter to={48250} />
              </div>
              <div className="hero-delta up">▲ 12.4% vs yesterday</div>
            </div>
            <Sparkline
              data={[12, 18, 14, 22, 19, 28, 24, 32, 30, 38, 35, 48]}
              width={110} height={42} color="#D4A574" delay={400}
            />
          </div>
          <div className="hero-row">
            <div className="hero-mini">
              <div className="hm-l">Orders</div>
              <div className="hm-v"><Counter to={14} /></div>
            </div>
            <div className="hero-mini">
              <div className="hm-l">New customers</div>
              <div className="hm-v"><Counter to={3} /></div>
            </div>
            <div className="hero-mini">
              <div className="hm-l">Avg ticket</div>
              <div className="hm-v">₹<Counter to={3446} /></div>
            </div>
          </div>
        </div>

        {/* Workshop capacity — NEW. Tailors don't track this anywhere today. */}
        <div className="capacity-card stagger" style={{ "--i": 1 }}>
          <div className="cc-left">
            <div className="cc-label">WORKSHOP LOAD</div>
            <div className="cc-h">This week</div>
            <div className="cc-sub">23 of 32 slots booked</div>
            <div className="cc-chip">3 trial slots open Sat</div>
          </div>
          <Radial value={0.72} color="#D4A574" size={72} />
        </div>

        {/* Priority queue — replaces "Recent orders" with what actually needs action */}
        <div className="section-row stagger" style={{ "--i": 2 }}>
          <div className="section-h">PRIORITY QUEUE</div>
          <div className="section-link">View all →</div>
        </div>

        {[
          { n: "Priya Sharma", d: "Lehenga (Silk) · Blouse", due: "Tomorrow", urgency: "today", progress: 0.85, stage: "Trial fit", color: "#2BA5A5" },
          { n: "Meera Patel", d: "Anarkali Suit (Georgette)", due: "in 2 days", urgency: "soon", progress: 0.55, stage: "Stitching", color: "#7C5CBF" },
          { n: "Riya Kapoor", d: "Saree Blouse (Cotton) ×2", due: "in 4 days", urgency: "ok", progress: 0.95, stage: "Ready", color: "#2D8F6F" },
        ].map((o, i) => (
          <div key={i} className={`pri-card stagger urg-${o.urgency}`} style={{ "--i": 3 + i }}>
            <div className="pri-top">
              <div className="avatar" style={{ background: `linear-gradient(135deg, ${o.color}, ${o.color}aa)` }}>
                {o.n.split(" ").map(s => s[0]).join("")}
              </div>
              <div className="pri-mid">
                <div className="pri-n">{o.n}</div>
                <div className="pri-d">{o.d}</div>
              </div>
              <div className="pri-due">
                <div className={`due-pill urg-${o.urgency}`}>{o.due}</div>
                <div className="stage">{o.stage}</div>
              </div>
            </div>
            <StitchProgress value={o.progress} color={o.color} />
          </div>
        ))}

        {/* Quick actions */}
        <div className="quick-row stagger" style={{ "--i": 7 }}>
          {[
            ["＋", "New order", "primary"],
            ["♟", "Add customer", ""],
            ["₹", "Invoice", ""],
            ["✂", "Measurements", ""],
          ].map(([ic, l, c], i) => (
            <button key={i} className={`quick ${c}`}>
              <span className="quick-ic">{ic}</span>
              <span>{l}</span>
            </button>
          ))}
        </div>

        <div className="footer-pad" />
      </div>

      <div className="tabbar">
        {[
          ["▦", "Home", true],
          ["♟", "Customers"],
          ["▤", "Orders"],
          ["₹", "Invoices"],
          ["⚙", "More"],
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

window.ImprovedDashboard = ImprovedDashboard;
window.StitchProgress = StitchProgress;
window.Counter = Counter;
window.Sparkline = Sparkline;
window.Radial = Radial;
