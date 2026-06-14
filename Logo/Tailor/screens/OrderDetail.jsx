/* Animated order detail — showcases the proper status pipeline animation,
   plus payment flip, swipe-to-action, and the stitched progress hero. */
const { useState: useStateOD, useEffect: useEffectOD } = React;

const STAGES = [
  { k: "received", l: "Received", c: "#E09F3E", ic: "📥" },
  { k: "cutting",  l: "Cutting",  c: "#4A7FC1", ic: "✂" },
  { k: "stitching",l: "Stitching",c: "#7C5CBF", ic: "🧵" },
  { k: "trial",    l: "Trial",    c: "#2BA5A5", ic: "👗" },
  { k: "ready",    l: "Ready",    c: "#2D8F6F", ic: "✓" },
  { k: "delivered",l: "Delivered",c: "#1A1A2E", ic: "🚚" },
];

const Pipeline = ({ index }) => {
  return (
    <div className="pipeline">
      {/* track + animated fill */}
      <div className="pipe-track">
        <div
          className="pipe-fill"
          style={{
            width: `${(index / (STAGES.length - 1)) * 100}%`,
            background: `linear-gradient(90deg, ${STAGES[0].c}, ${STAGES[Math.max(0, index)].c})`,
          }}
        />
        {/* Moving thread sparkle */}
        <div
          className="pipe-thread"
          style={{ left: `${(index / (STAGES.length - 1)) * 100}%` }}
        />
      </div>
      <div className="pipe-stages">
        {STAGES.map((s, i) => {
          const done = i < index;
          const active = i === index;
          return (
            <div
              key={s.k}
              className={`pipe-stage ${done ? "done" : ""} ${active ? "active" : ""}`}
              style={{ "--c": s.c, "--i": i }}
            >
              <div className="pipe-node">
                {done ? (
                  <svg width="14" height="14" viewBox="0 0 14 14">
                    <path d="M3 7.5 L6 10 L11 4" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : active ? (
                  <span className="pulse-dot" />
                ) : (
                  <span className="empty-dot" />
                )}
                {active && <span className="ring-ping" />}
              </div>
              <div className="pipe-l">{s.l}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const OrderDetail = () => {
  const [stage, setStage] = useStateOD(2);
  const [paid, setPaid] = useStateOD(false);
  const [autoplay, setAutoplay] = useStateOD(false);

  useEffectOD(() => {
    if (!autoplay) return;
    const id = setInterval(() => {
      setStage(s => (s + 1) % STAGES.length);
    }, 1600);
    return () => clearInterval(id);
  }, [autoplay]);

  const progress = (stage + 1) / STAGES.length;
  const color = STAGES[stage].c;

  return (
    <div className="screen orderdetail">
      <div className="appbar gradient">
        <div className="appbar-left">
          <button className="ic-btn">←</button>
          <div>
            <div className="boutique">Order #1284</div>
            <div className="greeting">Created 22 Apr · Due 28 Apr</div>
          </div>
        </div>
        <div className="appbar-actions">
          <button className="ic-btn">⋯</button>
        </div>
      </div>

      <div className="body">
        {/* Customer header */}
        <div className="cust-card stagger" style={{ "--i": 0 }}>
          <div className="avatar lg" style={{ background: "linear-gradient(135deg, #D4A574, #B8895A)" }}>PS</div>
          <div className="cust-mid">
            <div className="cust-n">Priya Sharma</div>
            <div className="cust-d">+91 98765 43210 · Mumbai</div>
          </div>
          <div className="cust-actions">
            <button className="round-btn">📞</button>
            <button className="round-btn">💬</button>
          </div>
        </div>

        {/* Animated pipeline */}
        <div className="card pad stagger" style={{ "--i": 1 }}>
          <div className="card-h-row">
            <div className="card-h">ORDER PROGRESS</div>
            <button className="play-btn" onClick={() => setAutoplay(a => !a)}>
              {autoplay ? "⏸ Pause" : "▶ Auto-advance"}
            </button>
          </div>
          <Pipeline index={stage} />
          <div className="stage-controls">
            <button onClick={() => setStage(Math.max(0, stage-1))} disabled={stage === 0}>← Back</button>
            <div className="stage-current" style={{ color }}>{STAGES[stage].l}</div>
            <button onClick={() => setStage(Math.min(STAGES.length-1, stage+1))} disabled={stage === STAGES.length-1}>Advance →</button>
          </div>

          <div className="stitch-block">
            <div className="stitch-label-row">
              <span>Garment progress</span>
              <span className="stitch-pct"><Counter to={Math.round(progress*100)} />%</span>
            </div>
            <StitchProgress value={progress} color={color} />
          </div>
        </div>

        {/* Items */}
        <div className="card pad stagger" style={{ "--i": 2 }}>
          <div className="card-h">ITEMS · 2</div>
          {[
            { g: "Lehenga", f: "Raw Silk · Maroon", q: 1, p: 14500 },
            { g: "Blouse",  f: "Silk · Maroon",     q: 1, p: 4000  },
          ].map((it, i) => (
            <div key={i} className="item-row">
              <div className="item-thumb" style={{ background: `linear-gradient(135deg, ${["#D4A574","#7C5CBF"][i]}33, ${["#D4A574","#7C5CBF"][i]}11)` }}>
                <span>{it.g[0]}</span>
              </div>
              <div className="item-mid">
                <div className="item-g">{it.g} <span className="qty">×{it.q}</span></div>
                <div className="item-f">{it.f}</div>
              </div>
              <div className="item-p">₹{it.p.toLocaleString("en-IN")}</div>
            </div>
          ))}
        </div>

        {/* Payment flip card */}
        <div className={`pay-card stagger ${paid ? "paid" : ""}`} style={{ "--i": 3 }} onClick={() => setPaid(p => !p)}>
          <div className="pay-inner">
            <div className="pay-face front">
              <div>
                <div className="pay-l">BALANCE DUE</div>
                <div className="pay-v">₹<Counter to={9500} /></div>
                <div className="pay-sub">Total ₹18,500 · Advance ₹9,000</div>
              </div>
              <button className="pay-cta">Mark paid →</button>
            </div>
            <div className="pay-face back">
              <div>
                <div className="pay-l ok">PAID IN FULL</div>
                <div className="pay-v">₹18,500</div>
                <div className="pay-sub">Tap to undo</div>
              </div>
              <div className="check-circle">
                <svg width="36" height="36" viewBox="0 0 36 36">
                  <circle cx="18" cy="18" r="16" fill="none" stroke="#2D8F6F" strokeWidth="2" className="ring-draw" />
                  <path d="M11 18 L16 23 L25 13" fill="none" stroke="#2D8F6F" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" className="check-draw" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        <div className="footer-pad" />
      </div>
    </div>
  );
};

window.OrderDetail = OrderDetail;
