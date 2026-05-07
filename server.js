// TailorX Backend — server.js
// Express + PostgreSQL REST API

require('dotenv').config();
const express  = require('express');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const crypto   = require('crypto');

// Resend email client (only if API key is set)
let resendClient = null;
try {
  if (process.env.RESEND_API_KEY) {
    const { Resend } = require('resend');
    resendClient = new Resend(process.env.RESEND_API_KEY);
    console.log('✅ Resend email client ready');
  } else {
    console.log('⚠️  No RESEND_API_KEY — forgot password emails disabled');
  }
} catch(e) {
  console.log('⚠️  Resend not installed:', e.message);
}

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
//  DATABASE
// ─────────────────────────────────────────────
const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }
    : {
        host:     process.env.DB_HOST     || 'localhost',
        port:     parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME     || 'tailorx_db',
        user:     process.env.DB_USER     || 'postgres',
        password: process.env.DB_PASSWORD || '',
      }
);

pool.connect()
  .then(() => console.log('✅ PostgreSQL connected'))
  .catch(e => console.error('❌ DB error:', e.message));

const db = { query: (text, params) => pool.query(text, params) };

// ─────────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());

// Auth middleware — verify JWT and attach boutique_id
function auth(req, res, next) {
  const header = req.headers['authorization'];
  const token  = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    req.boutiqueId = payload.boutiqueId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// SHA-256 helper (backward compat for old desktop-created accounts)
function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// ─────────────────────────────────────────────
//  HEALTH
// ─────────────────────────────────────────────
app.get('/health',     (req, res) => res.json({ status: 'ok', time: new Date() }));
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// ─────────────────────────────────────────────
//  LICENSE VERIFY
//  Used by both Electron desktop and Flutter app
// ─────────────────────────────────────────────
app.post('/api/license/verify', async (req, res) => {
  try {
    const { license_key } = req.body;
    if (!license_key) return res.json({ status: 'invalid' });

    const r = await db.query(
      "SELECT * FROM licenses WHERE license_key = $1 AND status = 'active'",
      [license_key]
    );
    if (!r.rows.length) return res.json({ status: 'invalid' });

    const l = r.rows[0];
    if (l.expires_at && new Date(l.expires_at) < new Date()) {
      return res.json({ status: 'expired' });
    }

    res.json({
      status:       'active',
      boutique_name: l.boutique_name,
      plan:          l.plan,
      expires_at:    l.expires_at,
    });
  } catch (e) {
    console.error('License verify error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  AUTH ROUTES
// ─────────────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, ownerName, email, password, phone, city, address } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email and password required' });

    const exists = await db.query('SELECT id FROM boutiques WHERE email = $1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const result = await db.query(
      `INSERT INTO boutiques (name, owner_name, email, password, phone, city, address)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, name, owner_name, email, phone, city, address, plan`,
      [name, ownerName || '', email, hash, phone || '', city || 'Surat', address || '']
    );
    const boutique = result.rows[0];
    const token = jwt.sign(
      { boutiqueId: boutique.id },
      process.env.JWT_SECRET || 'dev_secret',
      { expiresIn: '30d' }
    );
    res.status(201).json({ token, boutique });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login — supports both bcrypt (new) and SHA-256 (old desktop) passwords
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const result = await db.query('SELECT * FROM boutiques WHERE email = $1', [email]);
    if (!result.rows.length)
      return res.status(401).json({ error: 'Invalid email or password' });

    const boutique = result.rows[0];

    // Try bcrypt first; fall back to SHA-256 for accounts created on old desktop server
    let valid = false;
    const isBcrypt = boutique.password && boutique.password.startsWith('$2');

    if (isBcrypt) {
      valid = await bcrypt.compare(password, boutique.password);
    } else {
      // SHA-256 hash — auto-upgrade to bcrypt on success
      valid = sha256(password) === boutique.password;
      if (valid) {
        const newHash = await bcrypt.hash(password, 12);
        await db.query('UPDATE boutiques SET password=$1, updated_at=NOW() WHERE id=$2', [newHash, boutique.id]);
      }
    }

    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    // Account hold check
    if (boutique.is_active === false) {
      return res.status(403).json({
        error: 'Your account has been put on hold. Please contact support to resolve this.'
      });
    }

    const token = jwt.sign(
      { boutiqueId: boutique.id },
      process.env.JWT_SECRET || 'dev_secret',
      { expiresIn: '30d' }
    );
    delete boutique.password;
    res.json({ token, boutique });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current boutique profile
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, name, owner_name, email, phone, city, address, gstin, plan, created_at FROM boutiques WHERE id = $1',
      [req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update boutique settings
app.put('/api/auth/me', auth, async (req, res) => {
  try {
    const { name, ownerName, phone, city, address, gstin } = req.body;
    const result = await db.query(
      `UPDATE boutiques SET name=$1, owner_name=$2, phone=$3, city=$4, address=$5, gstin=$6, updated_at=NOW()
       WHERE id=$7 RETURNING id, name, owner_name, email, phone, city, address, gstin, plan`,
      [name, ownerName, phone, city, address, gstin, req.boutiqueId]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const result = await db.query('SELECT id, name FROM boutiques WHERE email = $1', [email]);
    if (!result.rows.length)
      return res.json({ message: 'If this email is registered, a reset link has been sent.' });

    const boutique    = result.rows[0];
    const resetToken  = crypto.randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000);

    await db.query(
      'UPDATE boutiques SET reset_token=$1, reset_token_expiry=$2 WHERE id=$3',
      [resetToken, resetExpiry, boutique.id]
    );

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const resetLink   = `${frontendUrl}?reset_token=${resetToken}`;

    if (resendClient) {
      await resendClient.emails.send({
        from:    'TailorX <noreply@tailorx.in>',
        to:      email,
        subject: 'Reset Your TailorX Password',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
            <h2 style="color:#1A1A2E;font-family:Georgia,serif;font-weight:400;letter-spacing:2px;">TAILOR<span style="color:#D4A574;">X</span></h2>
            <hr style="border:1px solid #E8E5DF;margin:20px 0;">
            <p>Hello ${boutique.name},</p>
            <p>Click the button below to reset your password. This link expires in <strong>1 hour</strong>.</p>
            <div style="text-align:center;margin:30px 0;">
              <a href="${resetLink}" style="background:#1A1A2E;color:#fff;padding:14px 32px;text-decoration:none;font-size:13px;letter-spacing:2px;text-transform:uppercase;">Reset Password →</a>
            </div>
            <p style="color:#6B6B7B;font-size:12px;">If you did not request this, ignore this email.</p>
          </div>
        `,
      });
    } else {
      console.log(`🔑 Password reset link for ${email}: ${resetLink}`);
    }

    res.json({ message: 'If this email is registered, a reset link has been sent.' });
  } catch (e) {
    console.error('Forgot password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)
      return res.status(400).json({ error: 'Token and new password required' });
    if (newPassword.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const result = await db.query(
      'SELECT id FROM boutiques WHERE reset_token=$1 AND reset_token_expiry > NOW()',
      [token]
    );
    if (!result.rows.length)
      return res.status(400).json({ error: 'Reset link is invalid or has expired.' });

    const hash = await bcrypt.hash(newPassword, 12);
    await db.query(
      'UPDATE boutiques SET password=$1, reset_token=NULL, reset_token_expiry=NULL, updated_at=NOW() WHERE id=$2',
      [hash, result.rows[0].id]
    );

    res.json({ message: 'Password reset successfully! You can now login.' });
  } catch (e) {
    console.error('Reset password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  ADMIN — boutique account management
//  Protected by ADMIN_SECRET env var (set in Render dashboard)
// ─────────────────────────────────────────────

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'tailorx_admin_2025';

const adminAuth = (req, res, next) => {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

// ── Admin Web Dashboard (browser UI) ─────────────────────────────
app.get('/admin', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TailorX Admin</title>
<style>
  :root {
    --dark: #1a1a2e; --mid: #16213e; --accent: #d4a574;
    --bg: #f8f7f4; --card: #ffffff; --border: #e8e5df;
    --text: #1a1a2e; --text2: #6b6b7b; --text3: #9e9ea8;
    --success: #2d8f6f; --danger: #cf4747; --warning: #e09f3e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }

  /* ── Header ── */
  header {
    background: linear-gradient(135deg, var(--dark), var(--mid));
    padding: 16px 24px; display: flex; align-items: center; gap: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.2);
  }
  .logo { width: 40px; height: 40px; background: var(--accent); border-radius: 10px;
    display: grid; place-items: center; font-weight: 900; font-size: 14px; color: var(--dark); letter-spacing: 1px; }
  header h1 { color: #fff; font-size: 20px; font-weight: 700; }
  header span { color: var(--accent); font-size: 12px; font-weight: 600; letter-spacing: 1px; margin-left: auto; }

  /* ── Login ── */
  #login-screen { display: flex; align-items: center; justify-content: center; min-height: calc(100vh - 72px); padding: 24px; }
  .login-box { background: var(--card); border-radius: 20px; padding: 36px; width: 100%; max-width: 400px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.08); }
  .login-box h2 { font-size: 22px; margin-bottom: 6px; }
  .login-box p { color: var(--text2); font-size: 14px; margin-bottom: 24px; }
  input[type=password], input[type=text] {
    width: 100%; padding: 12px 16px; border: 1.5px solid var(--border);
    border-radius: 10px; font-size: 15px; background: var(--bg); color: var(--text);
    outline: none; transition: border-color .2s;
  }
  input:focus { border-color: var(--accent); }
  .btn { display: block; width: 100%; padding: 13px; margin-top: 14px;
    background: var(--dark); color: #fff; border: none; border-radius: 10px;
    font-size: 14px; font-weight: 700; letter-spacing: 0.8px; cursor: pointer; transition: opacity .2s; }
  .btn:hover { opacity: 0.85; }
  .btn.danger { background: var(--danger); }
  .btn.success { background: var(--success); }
  .error-msg { color: var(--danger); font-size: 13px; margin-top: 10px; display: none; }

  /* ── Dashboard ── */
  #dashboard { display: none; padding: 24px; max-width: 960px; margin: 0 auto; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: linear-gradient(135deg, var(--dark), var(--mid)); border-radius: 16px;
    padding: 20px; text-align: center; color: #fff; }
  .stat-card .val { font-size: 36px; font-weight: 800; }
  .stat-card .lbl { font-size: 11px; color: rgba(255,255,255,0.5); letter-spacing: 1px; margin-top: 2px; }
  .stat-card.active .val { color: #5dcea8; }
  .stat-card.hold .val { color: #e87070; }

  .search-bar { margin-bottom: 16px; }
  .search-bar input { width: 100%; padding: 11px 16px; border: 1.5px solid var(--border);
    border-radius: 10px; font-size: 14px; background: var(--card); }

  /* ── Boutique Cards ── */
  .boutique-list { display: flex; flex-direction: column; gap: 12px; }
  .boutique-card {
    background: var(--card); border-radius: 16px; padding: 16px 18px;
    border: 1.5px solid var(--border);
    display: flex; align-items: center; gap: 14px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.04);
    transition: border-color .2s;
  }
  .boutique-card.on-hold { border-color: rgba(207,71,71,0.4); background: #fff9f9; }
  .avatar { width: 48px; height: 48px; border-radius: 12px; display: grid; place-items: center;
    font-size: 18px; font-weight: 800; color: var(--dark); flex-shrink: 0; }
  .avatar.active { background: linear-gradient(135deg, #d4a574, #e8c49a); }
  .avatar.hold { background: linear-gradient(135deg, #e87070, #cf4747); color: #fff; }
  .info { flex: 1; min-width: 0; }
  .info .name { font-size: 16px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .info .meta { font-size: 12px; color: var(--text2); margin-top: 3px; }
  .info .tags { display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap; }
  .tag { padding: 2px 8px; border-radius: 5px; font-size: 10px; font-weight: 700; letter-spacing: 0.5px; }
  .tag.active { background: rgba(45,143,111,0.1); color: var(--success); border: 1px solid rgba(45,143,111,0.25); }
  .tag.hold   { background: rgba(207,71,71,0.1);  color: var(--danger);  border: 1px solid rgba(207,71,71,0.25); }
  .tag.plan   { background: rgba(212,165,116,0.1); color: #b8895a; border: 1px solid rgba(212,165,116,0.25); }
  .tag.city   { background: rgba(107,107,123,0.08); color: var(--text2); border: 1px solid var(--border); }

  .hold-btn {
    flex-shrink: 0; padding: 8px 14px; border: none; border-radius: 10px;
    font-size: 11px; font-weight: 800; letter-spacing: 0.5px; cursor: pointer;
    transition: opacity .2s; display: flex; flex-direction: column; align-items: center; gap: 2px;
  }
  .hold-btn.do-hold   { background: rgba(207,71,71,0.1); color: var(--danger); border: 1px solid rgba(207,71,71,0.25); }
  .hold-btn.do-lift   { background: rgba(45,143,111,0.1); color: var(--success); border: 1px solid rgba(45,143,111,0.25); }
  .hold-btn:hover { opacity: 0.75; }
  .hold-btn svg { width: 20px; height: 20px; }

  .empty { text-align: center; padding: 48px; color: var(--text3); font-size: 15px; }
  .spinner { width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--accent);
    border-radius: 50%; animation: spin .7s linear infinite; margin: 48px auto; }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 600px) {
    .stats { grid-template-columns: repeat(3, 1fr); }
    .stat-card { padding: 14px 10px; }
    .stat-card .val { font-size: 26px; }
    header h1 { font-size: 17px; }
  }
</style>
</head>
<body>
<header>
  <div class="logo">TX</div>
  <h1>TailorX Admin</h1>
  <span id="header-count" style="display:none"></span>
</header>

<!-- Login -->
<div id="login-screen">
  <div class="login-box">
    <h2>🔐 Admin Access</h2>
    <p>Enter your admin secret key to manage boutique accounts.</p>
    <input type="password" id="secret-input" placeholder="Admin secret key" autocomplete="off" />
    <button class="btn" onclick="doLogin()">ENTER DASHBOARD</button>
    <div class="error-msg" id="login-error">Invalid secret. Try again.</div>
  </div>
</div>

<!-- Dashboard -->
<div id="dashboard">
  <div class="stats">
    <div class="stat-card"><div class="val" id="stat-total">—</div><div class="lbl">TOTAL</div></div>
    <div class="stat-card active"><div class="val" id="stat-active">—</div><div class="lbl">ACTIVE</div></div>
    <div class="stat-card hold"><div class="val" id="stat-hold">—</div><div class="lbl">ON HOLD</div></div>
  </div>
  <div class="search-bar">
    <input type="text" id="search-input" placeholder="🔍  Search by name, email or city…" oninput="renderList()" />
  </div>
  <div class="boutique-list" id="boutique-list">
    <div class="spinner"></div>
  </div>
</div>

<script>
let secret = '';
let boutiques = [];

function doLogin() {
  const val = document.getElementById('secret-input').value.trim();
  if (!val) return;
  secret = val;
  fetchBoutiques();
}
document.getElementById('secret-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

async function fetchBoutiques() {
  document.getElementById('login-error').style.display = 'none';
  document.getElementById('boutique-list').innerHTML = '<div class="spinner"></div>';
  try {
    const res = await fetch('/api/admin/boutiques', { headers: { 'x-admin-secret': secret } });
    if (res.status === 403) {
      document.getElementById('login-error').style.display = 'block';
      secret = '';
      return;
    }
    boutiques = await res.json();
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('header-count').style.display = 'inline';
    updateStats();
    renderList();
  } catch (e) {
    document.getElementById('login-error').textContent = 'Connection error. Is the server running?';
    document.getElementById('login-error').style.display = 'block';
  }
}

function updateStats() {
  const active = boutiques.filter(b => b.is_active !== false).length;
  const hold   = boutiques.filter(b => b.is_active === false).length;
  document.getElementById('stat-total').textContent  = boutiques.length;
  document.getElementById('stat-active').textContent = active;
  document.getElementById('stat-hold').textContent   = hold;
  document.getElementById('header-count').textContent = boutiques.length + ' boutiques';
}

function renderList() {
  const q = (document.getElementById('search-input').value || '').toLowerCase();
  const filtered = boutiques.filter(b =>
    (b.name || '').toLowerCase().includes(q) ||
    (b.email || '').toLowerCase().includes(q) ||
    (b.city || '').toLowerCase().includes(q)
  );
  const list = document.getElementById('boutique-list');
  if (!filtered.length) { list.innerHTML = '<div class="empty">No boutiques match your search.</div>'; return; }

  list.innerHTML = filtered.map(b => {
    const isActive = b.is_active !== false;
    const initials = (b.name || '?').trim().split(' ').filter(Boolean).slice(0,2).map(w => w[0].toUpperCase()).join('');
    const joined = b.created_at ? new Date(b.created_at).toLocaleDateString('en-IN', {day:'2-digit',month:'short',year:'numeric'}) : '';
    return \`
      <div class="boutique-card \${isActive ? '' : 'on-hold'}" id="card-\${b.id}">
        <div class="avatar \${isActive ? 'active' : 'hold'}">\${initials}</div>
        <div class="info">
          <div class="name">\${b.name || 'Unknown'}</div>
          <div class="meta">\${b.email || ''}  \${b.phone ? '· ' + b.phone : ''}</div>
          <div class="tags">
            <span class="tag \${isActive ? 'active' : 'hold'}">\${isActive ? '● ACTIVE' : '⏸ ON HOLD'}</span>
            <span class="tag plan">\${(b.plan || 'free').toUpperCase()}</span>
            \${b.city ? '<span class="tag city">📍 ' + b.city + '</span>' : ''}
            \${joined ? '<span class="tag city">Since ' + joined + '</span>' : ''}
          </div>
        </div>
        <button class="hold-btn \${isActive ? 'do-hold' : 'do-lift'}" onclick="toggleHold(\${b.id}, \${isActive})">
          \${isActive
            ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>HOLD'
            : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>LIFT'}
        </button>
      </div>
    \`;
  }).join('');
}

async function toggleHold(id, currentlyActive) {
  const newState = !currentlyActive;
  const b = boutiques.find(x => x.id === id);
  const name = b ? b.name : 'this boutique';
  const msg = newState
    ? 'Reactivate "' + name + '"?\\nThey will be able to login again.'
    : 'Put "' + name + '" on hold?\\nThey won\\'t be able to login until you lift the hold.';
  if (!confirm(msg)) return;

  try {
    const res = await fetch('/api/admin/boutiques/' + id + '/hold', {
      method: 'PATCH',
      headers: { 'x-admin-secret': secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) { alert('Failed to update. Try again.'); return; }
    // Update local data and re-render
    const idx = boutiques.findIndex(x => x.id === id);
    if (idx !== -1) boutiques[idx].is_active = newState;
    updateStats();
    renderList();
  } catch (e) {
    alert('Connection error.');
  }
}
</script>
</body>
</html>`);
});

// List all boutiques (admin)
app.get('/api/admin/boutiques', adminAuth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, name, owner_name, email, phone, city, plan, is_active, created_at
       FROM boutiques ORDER BY id ASC`
    );
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Toggle account hold (admin)
app.patch('/api/admin/boutiques/:id/hold', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_active } = req.body; // true = active, false = on hold
    if (typeof is_active !== 'boolean')
      return res.status(400).json({ error: 'is_active (boolean) required' });

    const result = await db.query(
      'UPDATE boutiques SET is_active=$1, updated_at=NOW() WHERE id=$2 RETURNING id, name, is_active',
      [is_active, id]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: 'Boutique not found' });

    res.json({
      message: is_active ? 'Account reactivated' : 'Account put on hold',
      boutique: result.rows[0],
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  DASHBOARD
//  Returns stats + recentOrders (Flutter & desktop compatible)
// ─────────────────────────────────────────────
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const bid = req.boutiqueId;
    const [ordersRes, invoicesRes, customersRes, notifRes, recentRes] = await Promise.all([
      db.query(
        `SELECT COUNT(*)::int as total,
                COUNT(*) FILTER (WHERE stage NOT IN ('delivered','dispensed'))::int as active
         FROM orders WHERE boutique_id=$1`, [bid]
      ),
      db.query(
        `SELECT COALESCE(SUM(total_amount),0)::float  as total_revenue,
                COALESCE(SUM(due_amount),0)::float    as pending_payments,
                COUNT(*) FILTER (WHERE status != 'paid')::int as pending_orders
         FROM invoices WHERE boutique_id=$1`, [bid]
      ),
      db.query('SELECT COUNT(*)::int as count FROM customers     WHERE boutique_id=$1', [bid]),
      db.query('SELECT COUNT(*)::int as count FROM notifications WHERE boutique_id=$1 AND is_read=FALSE', [bid]),
      db.query('SELECT * FROM orders WHERE boutique_id=$1 ORDER BY created_at DESC LIMIT 5', [bid]),
    ]);

    res.json({
      stats: {
        totalCustomers:   customersRes.rows[0].count,
        totalOrders:      ordersRes.rows[0].total,
        pendingOrders:    ordersRes.rows[0].active,
        totalRevenue:     invoicesRes.rows[0].total_revenue,
        pendingPayments:  invoicesRes.rows[0].pending_payments,
      },
      recentOrders:        recentRes.rows,
      unreadNotifications: notifRes.rows[0].count,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  CUSTOMERS
// ─────────────────────────────────────────────

app.get('/api/customers', auth, async (req, res) => {
  try {
    const { search, gender } = req.query;
    let query  = 'SELECT * FROM customers WHERE boutique_id = $1';
    const params = [req.boutiqueId];
    if (search) {
      params.push(`%${search}%`);
      query += ` AND (name ILIKE $${params.length} OR phone ILIKE $${params.length})`;
    }
    if (gender) {
      params.push(gender);
      query += ` AND gender = $${params.length}`;
    }
    query += ' ORDER BY created_at DESC';
    res.json((await db.query(query, params)).rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/customers/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM customers WHERE id = $1 AND boutique_id = $2',
      [req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/customers', auth, async (req, res) => {
  try {
    const { name, phone, email, city, gender, dob, notify, notes, measurements,
            measurements_top, measurements_bottom } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const result = await db.query(
      `INSERT INTO customers
         (boutique_id, name, phone, email, city, gender, dob, notify, notes,
          measurements, measurements_top, measurements_bottom)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.boutiqueId, name, phone||'', email||'', city||'Surat',
       gender||'', dob||null, notify||'WhatsApp', notes||'', measurements||'',
       JSON.stringify(measurements_top||{}), JSON.stringify(measurements_bottom||{})]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/customers/:id', auth, async (req, res) => {
  try {
    const { name, phone, email, city, gender, dob, notify, notes, measurements,
            measurements_top, measurements_bottom } = req.body;
    const result = await db.query(
      `UPDATE customers SET
         name=$1, phone=$2, email=$3, city=$4, gender=$5, dob=$6, notify=$7,
         notes=$8, measurements=$9, measurements_top=$10, measurements_bottom=$11,
         updated_at=NOW()
       WHERE id=$12 AND boutique_id=$13 RETURNING *`,
      [name, phone||'', email||'', city||'Surat', gender||'', dob||null, notify||'WhatsApp',
       notes||'', measurements||'',
       JSON.stringify(measurements_top||{}), JSON.stringify(measurements_bottom||{}),
       req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/customers/:id', auth, async (req, res) => {
  try {
    await db.query(
      'DELETE FROM customers WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  ORDERS
// ─────────────────────────────────────────────

app.get('/api/orders', auth, async (req, res) => {
  try {
    const { stage, search } = req.query;
    let query  = 'SELECT * FROM orders WHERE boutique_id = $1';
    const params = [req.boutiqueId];
    if (stage && stage !== 'all') {
      params.push(stage);
      query += ` AND stage = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      query += ` AND (customer_name ILIKE $${params.length} OR garment ILIKE $${params.length})`;
    }
    query += ' ORDER BY created_at DESC';
    res.json((await db.query(query, params)).rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM orders WHERE id = $1 AND boutique_id = $2',
      [req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    const { customer_id, customer_name, customer_phone,
            garment, fabric, due_date, amount, advance,
            stage, notify, notes } = req.body;
    if (!garment) return res.status(400).json({ error: 'Garment required' });
    const bal = Math.max(0, (amount||0) - (advance||0));
    const result = await db.query(
      `INSERT INTO orders
         (boutique_id, customer_id, customer_name, customer_phone,
          garment, fabric, due_date, amount, advance, balance, stage, notify, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [req.boutiqueId, customer_id||null, customer_name||'', customer_phone||'',
       garment, fabric||'', due_date||null,
       amount||0, advance||0, bal,
       stage||'received', notify !== false, notes||'']
    );
    const order = result.rows[0];
    if ((stage||'').toLowerCase() === 'ready' && notify !== false) {
      await autoNotify(req.boutiqueId, order.customer_id, customer_name, garment);
    }
    res.status(201).json(order);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/orders/:id', auth, async (req, res) => {
  try {
    const { customer_id, customer_name, customer_phone,
            garment, fabric, due_date, amount, advance,
            stage, notify, notes } = req.body;
    const bal = Math.max(0, (amount||0) - (advance||0));

    const old = await db.query(
      'SELECT stage, customer_id, customer_name, garment, notify FROM orders WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    if (!old.rows.length) return res.status(404).json({ error: 'Not found' });

    const result = await db.query(
      `UPDATE orders SET
         customer_id=$1, customer_name=$2, customer_phone=$3,
         garment=$4, fabric=$5, due_date=$6,
         amount=$7, advance=$8, balance=$9,
         stage=$10, notify=$11, notes=$12, updated_at=NOW()
       WHERE id=$13 AND boutique_id=$14 RETURNING *`,
      [customer_id||null, customer_name||'', customer_phone||'',
       garment, fabric||'', due_date||null,
       amount||0, advance||0, bal,
       stage||'received', notify !== false, notes||'',
       req.params.id, req.boutiqueId]
    );

    const order = result.rows[0];
    if (old.rows[0].stage !== 'ready' && (stage||'').toLowerCase() === 'ready' && old.rows[0].notify) {
      await autoNotify(req.boutiqueId, old.rows[0].customer_id, old.rows[0].customer_name, old.rows[0].garment);
    }
    res.json(order);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update only the stage (PATCH)
app.patch('/api/orders/:id/stage', auth, async (req, res) => {
  try {
    const { stage } = req.body;
    const old = await db.query(
      'SELECT * FROM orders WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    if (!old.rows.length) return res.status(404).json({ error: 'Not found' });
    const order = old.rows[0];

    await db.query(
      'UPDATE orders SET stage=$1, updated_at=NOW() WHERE id=$2',
      [stage, req.params.id]
    );

    if (order.stage !== 'ready' && (stage||'').toLowerCase() === 'ready' && order.notify) {
      await autoNotify(req.boutiqueId, order.customer_id, order.customer_name, order.garment);
    }
    res.json({ ...order, stage });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/orders/:id', auth, async (req, res) => {
  try {
    await db.query(
      'DELETE FROM orders WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  INVOICES
// ─────────────────────────────────────────────

app.get('/api/invoices', auth, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query  = 'SELECT * FROM invoices WHERE boutique_id = $1';
    const params = [req.boutiqueId];
    if (status && status !== 'all') {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      query += ` AND (customer_name ILIKE $${params.length} OR garment ILIKE $${params.length})`;
    }
    query += ' ORDER BY created_at DESC';
    res.json((await db.query(query, params)).rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/invoices/:id', auth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM invoices WHERE id = $1 AND boutique_id = $2',
      [req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoices', auth, async (req, res) => {
  try {
    const { customer_id, customer_name, customer_phone, order_id, garment,
            bill_date, items, subtotal, discount_pct, discount_amt,
            total_amount, advance, due_amount, remarks } = req.body;
    if (!customer_name || !garment)
      return res.status(400).json({ error: 'Customer name and garment required' });
    const status = (due_amount <= 0) ? 'paid' : 'pending';
    const result = await db.query(
      `INSERT INTO invoices
         (boutique_id, customer_id, customer_name, customer_phone, order_id, garment,
          bill_date, items, subtotal, discount_pct, discount_amt,
          total_amount, advance, due_amount, remarks, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [req.boutiqueId, customer_id||null, customer_name, customer_phone||'',
       order_id||null, garment, bill_date||new Date(),
       JSON.stringify(items||[]),
       subtotal||0, discount_pct||0, discount_amt||0,
       total_amount||0, advance||0, due_amount||0, remarks||'', status]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Full update (desktop uses PUT)
app.put('/api/invoices/:id', auth, async (req, res) => {
  try {
    const { status, advance, due_amount, subtotal, discount_pct,
            discount_amt, total_amount, remarks } = req.body;
    const result = await db.query(
      `UPDATE invoices SET
         status       = COALESCE($1, status),
         advance      = COALESCE($2, advance),
         due_amount   = COALESCE($3, due_amount),
         subtotal     = COALESCE($4, subtotal),
         discount_pct = COALESCE($5, discount_pct),
         discount_amt = COALESCE($6, discount_amt),
         total_amount = COALESCE($7, total_amount),
         remarks      = COALESCE($8, remarks),
         updated_at   = NOW()
       WHERE id=$9 AND boutique_id=$10 RETURNING *`,
      [status, advance, due_amount, subtotal, discount_pct,
       discount_amt, total_amount, remarks,
       req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark as paid (Flutter uses PATCH)
app.patch('/api/invoices/:id/pay', auth, async (req, res) => {
  try {
    const result = await db.query(
      `UPDATE invoices SET status='paid', due_amount=0, updated_at=NOW()
       WHERE id=$1 AND boutique_id=$2 RETURNING *`,
      [req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/invoices/:id', auth, async (req, res) => {
  try {
    await db.query(
      'DELETE FROM invoices WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  NOTIFICATIONS
// ─────────────────────────────────────────────

app.get('/api/notifications', auth, async (req, res) => {
  try {
    const { type } = req.query;
    let query  = 'SELECT * FROM notifications WHERE boutique_id = $1';
    const params = [req.boutiqueId];
    if (type && type !== 'all') {
      params.push(type);
      query += ` AND type = $${params.length}`;
    }
    query += ' ORDER BY created_at DESC LIMIT 100';
    res.json((await db.query(query, params)).rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/notifications', auth, async (req, res) => {
  try {
    const { type, title, msg } = req.body;
    const result = await db.query(
      'INSERT INTO notifications (boutique_id, type, title, msg) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.boutiqueId, type||'whatsapp', title||'', msg||'']
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await db.query(
      'UPDATE notifications SET is_read=TRUE WHERE boutique_id=$1',
      [req.boutiqueId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark single notification read — supports both PATCH (Flutter) and PUT (desktop)
async function markNotifRead(req, res) {
  try {
    await db.query(
      'UPDATE notifications SET is_read=TRUE WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
}
app.patch('/api/notifications/:id/read', auth, markNotifRead);
app.put('/api/notifications/:id/read',   auth, markNotifRead);

// ─────────────────────────────────────────────
//  AUTO NOTIFY HELPER
// ─────────────────────────────────────────────
async function autoNotify(boutiqueId, customerId, customerName, garment) {
  try {
    let notifyChannel = 'whatsapp';
    if (customerId) {
      const cRes = await db.query('SELECT notify FROM customers WHERE id=$1', [customerId]);
      if (cRes.rows.length) notifyChannel = (cRes.rows[0].notify || 'WhatsApp').toLowerCase();
    }
    await db.query(
      'INSERT INTO notifications (boutique_id, type, title, msg) VALUES ($1,$2,$3,$4)',
      [boutiqueId, notifyChannel,
       `Order Ready — ${customerName}`,
       `Your ${garment} is ready for pickup. Please collect at your convenience.`]
    );
  } catch (e) {
    console.error('Auto notify failed:', e.message);
  }
}

// ─────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 TailorX API running on port ${PORT}`));
