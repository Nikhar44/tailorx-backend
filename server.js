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
      `INSERT INTO boutiques (name, owner_name, email, password, phone, city, address, plan, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'trial', NOW() + INTERVAL '15 days')
       RETURNING id, name, owner_name, email, phone, city, address, plan, expires_at`,
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

    // Track last login time
    await db.query('UPDATE boutiques SET last_login_at=NOW() WHERE id=$1', [boutique.id]);

    // Account hold check
    if (boutique.is_active === false) {
      return res.status(403).json({
        error: 'Your account has been put on hold. Please contact support to resolve this.'
      });
    }

    // Subscription / trial expiry check
    if (boutique.expires_at && new Date(boutique.expires_at) < new Date()) {
      const isTrial = boutique.plan === 'trial';
      return res.status(403).json({
        error: isTrial
          ? 'Your 15-day free trial has ended. Please subscribe to continue using TailorX.'
          : 'Your subscription has expired. Please renew to continue using TailorX.',
        expired: true,
        plan: boutique.plan,
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
      'SELECT id, name, owner_name, email, phone, city, address, gstin, logo_url, plan, is_free, created_at FROM boutiques WHERE id = $1',
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
    const { name, ownerName, phone, city, address, gstin, logo_url } = req.body;
    const result = await db.query(
      `UPDATE boutiques SET name=$1, owner_name=$2, phone=$3, city=$4, address=$5, gstin=$6, logo_url=$7, updated_at=NOW()
       WHERE id=$8 RETURNING id, name, owner_name, email, phone, city, address, gstin, logo_url, plan`,
      [name, ownerName, phone, city, address, gstin, logo_url ?? null, req.boutiqueId]
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

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'Admin@123';

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
    box-shadow: 0 4px 20px rgba(0,0,0,0.2); position: sticky; top: 0; z-index: 10;
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
  input[type=password], input[type=text], input[type=number] {
    width: 100%; padding: 12px 16px; border: 1.5px solid var(--border);
    border-radius: 10px; font-size: 15px; background: var(--bg); color: var(--text);
    outline: none; transition: border-color .2s;
  }
  input:focus { border-color: var(--accent); }
  .btn { display: block; width: 100%; padding: 13px; margin-top: 14px;
    background: var(--dark); color: #fff; border: none; border-radius: 10px;
    font-size: 14px; font-weight: 700; letter-spacing: 0.8px; cursor: pointer; transition: opacity .2s; }
  .btn:hover { opacity: 0.85; }
  .error-msg { color: var(--danger); font-size: 13px; margin-top: 10px; display: none; }

  /* ── Dashboard ── */
  #dashboard { display: none; padding: 24px; max-width: 960px; margin: 0 auto; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: linear-gradient(135deg, var(--dark), var(--mid)); border-radius: 16px;
    padding: 20px; text-align: center; color: #fff; }
  .stat-card .val { font-size: 36px; font-weight: 800; }
  .stat-card .lbl { font-size: 11px; color: rgba(255,255,255,0.5); letter-spacing: 1px; margin-top: 2px; }
  .stat-card.s-active .val { color: #5dcea8; }
  .stat-card.s-hold .val { color: #e87070; }
  .stat-card.s-expired .val { color: #e09f3e; }

  .search-bar { margin-bottom: 16px; }
  .search-bar input { width: 100%; padding: 11px 16px; border: 1.5px solid var(--border);
    border-radius: 10px; font-size: 14px; background: var(--card); }

  /* ── Boutique Cards ── */
  .boutique-list { display: flex; flex-direction: column; gap: 10px; }
  .boutique-card {
    background: var(--card); border-radius: 14px; padding: 14px 16px;
    border: 1.5px solid var(--border);
    display: flex; align-items: center; gap: 14px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    cursor: pointer; transition: all .18s;
  }
  .boutique-card:hover { border-color: var(--accent); box-shadow: 0 4px 20px rgba(212,165,116,0.15); transform: translateY(-1px); }
  .boutique-card.on-hold { border-color: rgba(207,71,71,0.35); background: #fff9f9; }
  .boutique-card.on-hold:hover { border-color: var(--danger); }
  .avatar { width: 46px; height: 46px; border-radius: 12px; display: grid; place-items: center;
    font-size: 17px; font-weight: 800; color: var(--dark); flex-shrink: 0; }
  .avatar.av-active { background: linear-gradient(135deg, #d4a574, #e8c49a); }
  .avatar.av-hold   { background: linear-gradient(135deg, #e87070, #cf4747); color: #fff; }
  .info { flex: 1; min-width: 0; }
  .info .name { font-size: 15px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .info .meta { font-size: 12px; color: var(--text2); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .info .tags { display: flex; gap: 5px; margin-top: 6px; flex-wrap: wrap; }
  .tag { padding: 2px 7px; border-radius: 5px; font-size: 10px; font-weight: 700; letter-spacing: 0.4px; }
  .tag.t-active    { background: rgba(45,143,111,0.1);  color: var(--success); border: 1px solid rgba(45,143,111,0.25); }
  .tag.t-hold      { background: rgba(207,71,71,0.1);   color: var(--danger);  border: 1px solid rgba(207,71,71,0.25); }
  .tag.t-expired   { background: rgba(207,71,71,0.1);   color: var(--danger);  border: 1px solid rgba(207,71,71,0.25); }
  .tag.t-expiring  { background: rgba(224,159,62,0.1);  color: var(--warning); border: 1px solid rgba(224,159,62,0.25); }
  .tag.t-expiry-ok { background: rgba(45,143,111,0.08); color: var(--success); border: 1px solid rgba(45,143,111,0.2); }
  .tag.t-plan      { background: rgba(212,165,116,0.1); color: #b8895a; border: 1px solid rgba(212,165,116,0.25); }
  .tag.t-city      { background: rgba(107,107,123,0.08); color: var(--text2); border: 1px solid var(--border); }
  .tag.t-trial     { background: rgba(167,139,250,0.1); color: #7c5cbf; border: 1px solid rgba(167,139,250,0.3); }
  .chevron { color: var(--text3); font-size: 18px; flex-shrink: 0; }

  /* ── Modal ── */
  .modal-backdrop {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.45);
    z-index: 100; align-items: flex-end; justify-content: center;
  }
  .modal-backdrop.open { display: flex; }
  .modal {
    background: var(--card); border-radius: 24px 24px 0 0; width: 100%; max-width: 520px;
    padding: 0 0 32px; max-height: 92vh; overflow-y: auto;
    animation: slideUp .25s ease;
  }
  @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
  .modal-handle { width: 36px; height: 4px; background: var(--border); border-radius: 2px; margin: 12px auto 0; }
  .modal-header {
    display: flex; align-items: center; gap: 14px;
    padding: 20px 20px 16px; border-bottom: 1px solid var(--border);
  }
  .modal-avatar { width: 56px; height: 56px; border-radius: 14px; display: grid; place-items: center;
    font-size: 20px; font-weight: 800; flex-shrink: 0; }
  .modal-info { flex: 1; min-width: 0; }
  .modal-info h2 { font-size: 18px; font-weight: 700; }
  .modal-info p  { font-size: 13px; color: var(--text2); margin-top: 2px; }
  .modal-close { width: 32px; height: 32px; border-radius: 50%; background: var(--bg); border: none;
    cursor: pointer; font-size: 18px; display: grid; place-items: center; color: var(--text2); flex-shrink: 0; }
  .modal-close:hover { background: var(--border); }

  .modal-details { padding: 16px 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; border-bottom: 1px solid var(--border); }
  .detail-item { background: var(--bg); border-radius: 10px; padding: 10px 12px; }
  .detail-item .dl { font-size: 10px; font-weight: 700; letter-spacing: 0.6px; color: var(--text3); margin-bottom: 3px; }
  .detail-item .dv { font-size: 13px; font-weight: 600; color: var(--text); }

  .modal-actions { padding: 16px 20px; display: flex; flex-direction: column; gap: 10px; }
  .modal-actions h3 { font-size: 11px; font-weight: 700; letter-spacing: 1px; color: var(--text3); margin-bottom: 4px; }
  .action-btn {
    display: flex; align-items: center; gap: 12px; padding: 14px 16px;
    border-radius: 12px; border: 1.5px solid; cursor: pointer;
    font-size: 14px; font-weight: 700; width: 100%; text-align: left; transition: opacity .15s;
  }
  .action-btn:hover { opacity: 0.75; }
  .action-btn svg { width: 20px; height: 20px; flex-shrink: 0; }
  .action-btn .ab-text { flex: 1; }
  .action-btn .ab-text span { display: block; font-size: 11px; font-weight: 400; opacity: 0.7; margin-top: 1px; }
  .ab-hold   { background: rgba(207,71,71,0.06);  color: var(--danger);  border-color: rgba(207,71,71,0.25); }
  .ab-lift   { background: rgba(45,143,111,0.06); color: var(--success); border-color: rgba(45,143,111,0.25); }
  .ab-renew  { background: rgba(74,127,193,0.06); color: #4a7fc1;        border-color: rgba(74,127,193,0.25); }
  .ab-pw     { background: rgba(167,139,250,0.06);color: #7c5cbf;        border-color: rgba(167,139,250,0.3); }
  .ab-free   { background: rgba(212,165,116,0.06);color: #d4a574;        border-color: rgba(212,165,116,0.3); }
  .ab-plan   { background: rgba(99,179,237,0.06); color: #3b82f6;        border-color: rgba(99,179,237,0.3); }
  .ab-unfree { background: rgba(100,100,120,0.06);color: var(--text3);   border-color: rgba(100,100,120,0.25); }

  .renew-input-row { display: none; flex-direction: column; gap: 8px; padding: 0 0 4px; }
  .renew-input-row .renew-fields { display: flex; gap: 8px; }
  .renew-input-row input { flex: 1; padding: 10px 12px; font-size: 14px; }
  .renew-input-row button { padding: 10px 18px; background: #4a7fc1; color: #fff; border: none;
    border-radius: 10px; font-weight: 700; cursor: pointer; white-space: nowrap; }

  /* Activity & Revenue */
  .modal-section { padding: 14px 20px; border-bottom: 1px solid var(--border); }
  .modal-section h3 { font-size: 11px; font-weight: 700; letter-spacing: 1px; color: var(--text3); margin-bottom: 10px; }
  .activity-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
  .act-item { background: var(--bg); border-radius: 10px; padding: 10px; text-align: center; }
  .act-item .av { font-size: 20px; font-weight: 800; color: var(--text); }
  .act-item .al { font-size: 10px; font-weight: 600; color: var(--text3); letter-spacing: 0.5px; margin-top: 2px; }
  .last-login { font-size: 12px; color: var(--text2); margin-top: 8px; }
  .pay-total { display: flex; justify-content: space-between; align-items: center; background: var(--bg); border-radius: 10px; padding: 12px 14px; margin-bottom: 8px; }
  .pay-total .pt-lbl { font-size: 12px; color: var(--text2); }
  .pay-total .pt-val { font-size: 20px; font-weight: 800; color: var(--success); }
  .pay-list { display: flex; flex-direction: column; gap: 6px; max-height: 160px; overflow-y: auto; }
  .pay-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: var(--bg); border-radius: 8px; font-size: 13px; }
  .pay-item .pi-amt { font-weight: 700; color: var(--success); }
  .pay-item .pi-meta { font-size: 11px; color: var(--text3); }
  .no-payments { text-align: center; color: var(--text3); font-size: 13px; padding: 16px; }

  .empty { text-align: center; padding: 48px; color: var(--text3); font-size: 15px; }
  .spinner { width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--accent);
    border-radius: 50%; animation: spin .7s linear infinite; margin: 48px auto; }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 600px) {
    .stats { grid-template-columns: repeat(3, 1fr); }
    .stat-card { padding: 14px 10px; }
    .stat-card .val { font-size: 26px; }
    header h1 { font-size: 17px; }
    .modal { border-radius: 20px 20px 0 0; }
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
    <button class="btn" id="login-btn">ENTER DASHBOARD</button>
    <div class="error-msg" id="login-error">Invalid secret. Try again.</div>
  </div>
</div>

<!-- Dashboard -->
<div id="dashboard">
  <div class="stats">
    <div class="stat-card"><div class="val" id="stat-total">—</div><div class="lbl">TOTAL</div></div>
    <div class="stat-card s-active"><div class="val" id="stat-active">—</div><div class="lbl">ACTIVE</div></div>
    <div class="stat-card" style="--c:#a78bfa"><div class="val" id="stat-trial" style="color:#a78bfa">—</div><div class="lbl">ON TRIAL</div></div>
    <div class="stat-card s-hold"><div class="val" id="stat-hold">—</div><div class="lbl">ON HOLD</div></div>
    <div class="stat-card s-expired"><div class="val" id="stat-expired">—</div><div class="lbl">EXPIRED</div></div>
  </div>
  <div class="search-bar">
    <input type="text" id="search-input" placeholder="🔍  Search by name, email or city…" oninput="renderList()" />
  </div>
  <div class="boutique-list" id="boutique-list">
    <div class="spinner"></div>
  </div>
</div>

<!-- Boutique Detail Modal -->
<div class="modal-backdrop" id="modal-backdrop" onclick="closeModal(event)">
  <div class="modal" id="modal">
    <div class="modal-handle"></div>
    <div class="modal-header">
      <div class="modal-avatar" id="m-avatar"></div>
      <div class="modal-info">
        <h2 id="m-name"></h2>
        <p id="m-meta"></p>
      </div>
      <button class="modal-close" onclick="closeModalNow()">✕</button>
    </div>
    <div class="modal-details" id="m-details"></div>
    <!-- Activity Section -->
    <div class="modal-section">
      <h3>ACCOUNT ACTIVITY</h3>
      <div class="activity-grid" id="m-activity">
        <div class="act-item"><div class="av">—</div><div class="al">CUSTOMERS</div></div>
        <div class="act-item"><div class="av">—</div><div class="al">ORDERS</div></div>
        <div class="act-item"><div class="av">—</div><div class="al">INVOICES</div></div>
        <div class="act-item"><div class="av">—</div><div class="al">APP REVENUE</div></div>
      </div>
      <div class="last-login" id="m-last-login">Last login: loading...</div>
    </div>
    <!-- Revenue Section -->
    <div class="modal-section">
      <h3>SUBSCRIPTION REVENUE</h3>
      <div class="pay-total">
        <div class="pt-lbl">Total collected from this boutique</div>
        <div class="pt-val" id="m-total-paid">₹0</div>
      </div>
      <div class="pay-list" id="m-pay-list"><div class="no-payments">Loading...</div></div>
    </div>
    <div class="modal-actions">
      <h3>ACTIONS</h3>
      <button class="action-btn" id="btn-hold" onclick="doHold()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="hold-icon"></svg>
        <div class="ab-text"><span id="hold-label"></span><span id="hold-sub"></span></div>
      </button>
      <button class="action-btn ab-renew" onclick="toggleRenewInput()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        <div class="ab-text">Renew Subscription<span>Extend access by months</span></div>
      </button>
      <div class="renew-input-row" id="renew-row">
        <div class="renew-fields">
          <input type="number" id="renew-months" placeholder="Months (e.g. 3)" min="1" max="24" />
          <input type="number" id="renew-amount" placeholder="Amount paid (₹)" min="0" />
          <button onclick="doRenew()">RENEW</button>
        </div>
      </div>
      <button class="action-btn ab-plan" onclick="togglePlanRow()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        <div class="ab-text">Change Plan<span>Switch between Free / Monthly / Yearly / Pro</span></div>
      </button>
      <div id="plan-row" style="display:none;margin-top:-4px;background:#f0f7ff;border-radius:10px;padding:14px;border:1px solid #bfdbfe;">
        <div style="font-size:11px;font-weight:700;letter-spacing:1px;color:#3b82f6;margin-bottom:8px;">SELECT NEW PLAN</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
          <button onclick="doChangePlan('free')"    style="padding:8px 14px;border-radius:7px;border:1.5px solid #94a3b8;background:#fff;color:#64748b;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.5px;">FREE</button>
          <button onclick="doChangePlan('monthly')" style="padding:8px 14px;border-radius:7px;border:1.5px solid #3b82f6;background:#fff;color:#3b82f6;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.5px;">MONTHLY</button>
          <button onclick="doChangePlan('yearly')"  style="padding:8px 14px;border-radius:7px;border:1.5px solid #7c3aed;background:#fff;color:#7c3aed;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.5px;">YEARLY</button>
          <button onclick="doChangePlan('pro')"     style="padding:8px 14px;border-radius:7px;border:1.5px solid #d4a574;background:#1a1a2e;color:#d4a574;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:0.5px;">PRO</button>
        </div>
        <div style="font-size:11px;color:#64748b;">Current plan shown in details above. Takes effect immediately.</div>
      </div>
      <button class="action-btn ab-pw" onclick="toggleResetRow()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        <div class="ab-text">Reset Password<span>Set a new password for this boutique</span></div>
      </button>
      <button class="action-btn" id="btn-free" onclick="doToggleFree()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="free-icon"></svg>
        <div class="ab-text"><span id="free-label"></span><span id="free-sub"></span></div>
      </button>
      <div id="reset-row" style="display:none;margin-top:12px;background:#f9f7f4;border-radius:10px;padding:14px;border:1px solid #e0d9d0;">
        <div style="font-size:11px;font-weight:700;letter-spacing:1px;color:#888;margin-bottom:8px;">NEW PASSWORD</div>
        <div style="display:flex;gap:8px;align-items:center;">
          <input id="reset-pass-input" type="text" placeholder="Min 8 characters" autocomplete="off"
            style="flex:1;padding:9px 12px;border:1px solid #ddd;border-radius:7px;font-size:14px;font-family:monospace;background:#fff;" />
          <button onclick="doResetPassword()" style="padding:9px 16px;background:#1a1a2e;color:#d4a574;border:none;border-radius:7px;font-size:12px;font-weight:700;letter-spacing:1px;cursor:pointer;">SET</button>
        </div>
        <div style="font-size:11px;color:#999;margin-top:6px;">The boutique owner will use this password to login.</div>
      </div>
    </div>
  </div>
</div>

<script>
let secret = '';
let boutiques = [];
let selectedId = null;

function doLogin() {
  var val = document.getElementById('secret-input').value.trim();
  if (!val) return;
  secret = val;
  fetchBoutiques();
}

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('login-btn').addEventListener('click', doLogin);
  document.getElementById('secret-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') doLogin();
  });
});

async function fetchBoutiques() {
  var btn = document.getElementById('login-btn');
  var errEl = document.getElementById('login-error');
  errEl.style.display = 'none';
  document.getElementById('boutique-list').innerHTML = '<div class="spinner"></div>';

  if (btn) { btn.textContent = 'CONNECTING...'; btn.disabled = true; btn.style.opacity = '0.7'; }

  var wakeHint = setTimeout(function() {
    errEl.style.display = 'block';
    errEl.style.color = '#d4a574';
    errEl.textContent = 'Server is waking up, please wait...';
  }, 4000);

  try {
    const res = await fetch('/api/admin/boutiques', { headers: { 'x-admin-secret': secret } });
    clearTimeout(wakeHint);
    errEl.style.display = 'none';
    errEl.style.color = '';

    if (res.status === 403) {
      errEl.textContent = 'Invalid secret. Try again.';
      errEl.style.display = 'block';
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
    clearTimeout(wakeHint);
    errEl.style.color = '';
    errEl.textContent = 'Connection error - server may be down. Try again in a moment.';
    errEl.style.display = 'block';
  } finally {
    if (btn) { btn.textContent = 'ENTER DASHBOARD'; btn.disabled = false; btn.style.opacity = '1'; }
  }
}

function isExpired(b) {
  return b.expires_at && new Date(b.expires_at) < new Date();
}
function expiryLabel(b) {
  if (!b.expires_at) return null;
  const d = new Date(b.expires_at);
  const now = new Date();
  const diff = Math.ceil((d - now) / (1000 * 60 * 60 * 24));
  const dateStr = d.toLocaleDateString('en-IN', {day:'2-digit', month:'short', year:'numeric'});
  const isTrial = b.plan === 'trial';
  if (diff < 0) return { text: (isTrial ? 'Trial ended ' : 'Expired ') + dateStr, cls: 't-expired' };
  if (diff <= 3) return { text: (isTrial ? 'Trial ends in ' : 'Expires in ') + diff + 'd!', cls: 't-expiring' };
  if (diff <= 7) return { text: (isTrial ? 'Trial: ' : '') + diff + ' days left (' + dateStr + ')', cls: 't-expiring' };
  return { text: (isTrial ? 'Trial until ' : 'Expires ') + dateStr, cls: 't-expiry-ok' };
}

function updateStats() {
  const active  = boutiques.filter(b => b.is_active !== false && !isExpired(b) && b.plan !== 'trial').length;
  const trial   = boutiques.filter(b => b.is_active !== false && !isExpired(b) && b.plan === 'trial').length;
  const hold    = boutiques.filter(b => b.is_active === false).length;
  const expired = boutiques.filter(b => isExpired(b)).length;
  document.getElementById('stat-total').textContent   = boutiques.length;
  document.getElementById('stat-active').textContent  = active;
  document.getElementById('stat-trial').textContent   = trial;
  document.getElementById('stat-hold').textContent    = hold;
  document.getElementById('stat-expired').textContent = expired;
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
    const expired  = isExpired(b);
    const expLbl   = expiryLabel(b);
    const initials = (b.name || '?').trim().split(' ').filter(Boolean).slice(0,2).map(w => w[0].toUpperCase()).join('');
    const cardCls  = (!isActive || expired) ? 'on-hold' : '';
    const avatarCls= (!isActive || expired) ? 'av-hold' : 'av-active';
    const isTrial  = b.plan === 'trial';
    const statusTag = !isActive
      ? '<span class="tag t-hold">ON HOLD</span>'
      : expired
        ? ('<span class="tag t-expired">' + (isTrial ? 'TRIAL ENDED' : 'EXPIRED') + '</span>')
        : isTrial
          ? '<span class="tag t-trial">FREE TRIAL</span>'
          : '<span class="tag t-active">ACTIVE</span>';
    const expiryTag = expLbl ? ('<span class="tag ' + expLbl.cls + '">' + expLbl.text + '</span>') : '';
    return (
      '<div class="boutique-card ' + cardCls + '" onclick="openModal(' + b.id + ')">' +
        '<div class="avatar ' + avatarCls + '">' + initials + '</div>' +
        '<div class="info">' +
          '<div class="name">' + (b.name || 'Unknown') + '</div>' +
          '<div class="meta">' + (b.email || '') + (b.phone ? ' - ' + b.phone : '') + '</div>' +
          '<div class="tags">' + statusTag + '<span class="tag t-plan">' + (b.plan || 'free').toUpperCase() + '</span>' + (b.city ? '<span class="tag t-city">' + b.city + '</span>' : '') + expiryTag + '</div>' +
        '</div>' +
        '<div class="chevron">&#8250;</div>' +
      '</div>'
    );
  }).join('');
}

function openModal(id) {
  selectedId = id;
  const b = boutiques.find(x => x.id === id);
  if (!b) return;
  const isActive = b.is_active !== false;
  const expired  = isExpired(b);
  const initials = (b.name || '?').trim().split(' ').filter(Boolean).slice(0,2).map(w => w[0].toUpperCase()).join('');
  const joined   = b.created_at ? new Date(b.created_at).toLocaleDateString('en-IN', {day:'2-digit',month:'short',year:'numeric'}) : 'Unknown';
  const expiry   = b.expires_at ? new Date(b.expires_at).toLocaleDateString('en-IN', {day:'2-digit',month:'short',year:'numeric'}) : 'Not set';

  // Avatar
  const av = document.getElementById('m-avatar');
  av.textContent = initials;
  av.className = 'modal-avatar ' + ((!isActive || expired) ? 'av-hold' : 'av-active');

  // Header info
  document.getElementById('m-name').textContent = b.name || 'Unknown';
  document.getElementById('m-meta').textContent = (b.email || '') + (b.phone ? ' - ' + b.phone : '');

  // Details grid
  document.getElementById('m-details').innerHTML =
    '<div class="detail-item"><div class="dl">STATUS</div><div class="dv">' + (!isActive ? 'On Hold' : expired ? 'Expired' : 'Active') + '</div></div>' +
    '<div class="detail-item"><div class="dl">PLAN</div><div class="dv">' + (b.plan || 'free').toUpperCase() + '</div></div>' +
    '<div class="detail-item"><div class="dl">CITY</div><div class="dv">' + (b.city || '-') + '</div></div>' +
    '<div class="detail-item"><div class="dl">JOINED</div><div class="dv">' + joined + '</div></div>' +
    '<div class="detail-item" style="grid-column:1/-1"><div class="dl">EXPIRY DATE</div><div class="dv">' + expiry + '</div></div>' +
    '<div class="detail-item" style="grid-column:1/-1"><div class="dl">EMAIL ID</div><div class="dv" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">' +
      '<span style="font-family:monospace;font-size:13px;word-break:break-all">' + (b.email || '-') + '</span>' +
      (b.email ? '<button data-v="' + b.email + '" onclick="copyText(this.dataset.v,this)" style="padding:3px 10px;font-size:11px;background:#1a1a2e;color:#d4a574;border:none;border-radius:4px;cursor:pointer;letter-spacing:0.5px">COPY</button>' : '') +
    '</div></div>' +
    '<div class="detail-item" style="grid-column:1/-1"><div class="dl">PHONE</div><div class="dv" style="display:flex;align-items:center;gap:8px">' +
      '<span style="font-family:monospace;font-size:13px">' + (b.phone || '-') + '</span>' +
      (b.phone ? '<button data-v="' + b.phone + '" onclick="copyText(this.dataset.v,this)" style="padding:3px 10px;font-size:11px;background:#1a1a2e;color:#d4a574;border:none;border-radius:4px;cursor:pointer;letter-spacing:0.5px">COPY</button>' : '') +
    '</div></div>';

  // Free Account button
  const btnFree = document.getElementById('btn-free');
  if (b.is_free) {
    btnFree.className = 'action-btn ab-unfree';
    document.getElementById('free-icon').innerHTML = '<path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>';
    document.getElementById('free-label').textContent = 'Remove Free Access';
    document.getElementById('free-sub').textContent   = 'Switch to paid plan required';
  } else {
    btnFree.className = 'action-btn ab-free';
    document.getElementById('free-icon').innerHTML = '<path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>';
    document.getElementById('free-label').textContent = 'Grant Free Access';
    document.getElementById('free-sub').textContent   = 'No payment required - permanent free account';
  }

  // Hold/Lift button
  const btnHold = document.getElementById('btn-hold');
  if (isActive && !expired) {
    btnHold.className = 'action-btn ab-hold';
    document.getElementById('hold-icon').innerHTML = '<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>';
    document.getElementById('hold-label').textContent = 'Put on Hold';
    document.getElementById('hold-sub').textContent = 'Boutique will not be able to login';
  } else {
    btnHold.className = 'action-btn ab-lift';
    document.getElementById('hold-icon').innerHTML = '<polygon points="5 3 19 12 5 21 5 3"/>';
    document.getElementById('hold-label').textContent = 'Lift Hold / Reactivate';
    document.getElementById('hold-sub').textContent = 'Boutique will be able to login again';
  }

  // Reset renew input
  document.getElementById('renew-row').style.display = 'none';
  document.getElementById('renew-months').value = '';
  document.getElementById('renew-amount').value = '';

  document.getElementById('modal-backdrop').classList.add('open');
  document.body.style.overflow = 'hidden';

  // Load activity + payments async
  loadActivity(id);
  loadPayments(id);
}

async function loadActivity(id) {
  try {
    const res = await fetch('/api/admin/boutiques/' + id + '/stats', { headers: { 'x-admin-secret': secret } });
    const d = await res.json();
    const fmt = n => n >= 1000 ? (n/1000).toFixed(1) + 'k' : String(n);
    const fmtRev = n => n >= 100000 ? (n/100000).toFixed(1) + 'L' : n >= 1000 ? (n/1000).toFixed(1) + 'k' : String(Math.round(n));
    document.getElementById('m-activity').innerHTML =
      '<div class="act-item"><div class="av">' + fmt(d.customers) + '</div><div class="al">CUSTOMERS</div></div>' +
      '<div class="act-item"><div class="av">' + fmt(d.orders) + '</div><div class="al">ORDERS</div></div>' +
      '<div class="act-item"><div class="av">' + fmt(d.invoices) + '</div><div class="al">INVOICES</div></div>' +
      '<div class="act-item"><div class="av">\\u20B9' + fmtRev(d.app_revenue) + '</div><div class="al">APP REV</div></div>';
    const ll = d.last_login_at
      ? 'Last login: ' + new Date(d.last_login_at).toLocaleString('en-IN', {day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'})
      : 'Last login: Never recorded';
    document.getElementById('m-last-login').textContent = ll;
  } catch(e) {
    document.getElementById('m-last-login').textContent = 'Could not load activity.';
  }
}

async function loadPayments(id) {
  try {
    const res = await fetch('/api/admin/boutiques/' + id + '/payments', { headers: { 'x-admin-secret': secret } });
    const payments = await res.json();
    const total = payments.reduce((s, p) => s + parseFloat(p.amount), 0);
    document.getElementById('m-total-paid').textContent = '\\u20B9' + total.toLocaleString('en-IN');
    if (!payments.length) {
      document.getElementById('m-pay-list').innerHTML = '<div class="no-payments">No payments recorded yet</div>';
      return;
    }
    document.getElementById('m-pay-list').innerHTML = payments.map(p => {
      const date = new Date(p.paid_at).toLocaleDateString('en-IN', {day:'2-digit',month:'short',year:'numeric'});
      return '<div class="pay-item">' +
        '<div><div class="pi-amt">\\u20B9' + parseFloat(p.amount).toLocaleString('en-IN') + '</div>' +
        '<div class="pi-meta">' + p.months + ' month(s) - ' + (p.plan || 'monthly').toUpperCase() + (p.notes ? ' - ' + p.notes : '') + '</div></div>' +
        '<div class="pi-meta">' + date + '</div>' +
      '</div>';
    }).join('');
  } catch(e) {
    document.getElementById('m-pay-list').innerHTML = '<div class="no-payments">Could not load payments.</div>';
  }
}

function closeModal(e) {
  if (e.target === document.getElementById('modal-backdrop')) closeModalNow();
}
function closeModalNow() {
  document.getElementById('modal-backdrop').classList.remove('open');
  document.body.style.overflow = '';
  selectedId = null;
}

function toggleRenewInput() {
  const row = document.getElementById('renew-row');
  row.style.display = row.style.display === 'flex' ? 'none' : 'flex';
}

async function doToggleFree() {
  const b = boutiques.find(x => x.id === selectedId);
  if (!b) return;
  const newFree = !b.is_free;
  const msg = newFree
    ? 'Grant FREE access to ' + b.name + '? They will never be charged.'
    : 'Remove free access from ' + b.name + '? They will need to pay after trial ends.';
  if (!confirm(msg)) return;
  try {
    const res = await fetch('/api/admin/boutiques/' + selectedId + '/free', {
      method: 'PATCH',
      headers: { 'x-admin-secret': secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_free: newFree })
    });
    if (!res.ok) { alert('Failed. Try again.'); return; }
    const idx = boutiques.findIndex(x => x.id === selectedId);
    if (idx !== -1) boutiques[idx].is_free = newFree;
    openModal(selectedId);
    alert(newFree ? 'Free access granted to ' + b.name : 'Free access removed from ' + b.name);
  } catch (e) { alert('Error: ' + e.message); }
}

async function doHold() {
  const b = boutiques.find(x => x.id === selectedId);
  if (!b) return;
  const isActive = b.is_active !== false;
  const expired  = isExpired(b);
  const newState = !(isActive && !expired);
  const msg = newState ? 'Reactivate ' + b.name + '?' : 'Put ' + b.name + ' on hold?';
  if (!confirm(msg)) return;
  try {
    const res = await fetch('/api/admin/boutiques/' + selectedId + '/hold', {
      method: 'PATCH',
      headers: { 'x-admin-secret': secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: newState })
    });
    if (!res.ok) { alert('Failed. Try again.'); return; }
    const idx = boutiques.findIndex(x => x.id === selectedId);
    if (idx !== -1) boutiques[idx].is_active = newState;
    updateStats(); renderList(); closeModalNow();
    alert(newState ? b.name + ' has been reactivated!' : b.name + ' has been put on hold.');
  } catch(e) { alert('Connection error.'); }
}

async function doRenew() {
  const m = parseInt(document.getElementById('renew-months').value);
  const amount = parseFloat(document.getElementById('renew-amount').value) || 0;
  if (!m || m < 1) { alert('Enter a valid number of months.'); return; }
  const b = boutiques.find(x => x.id === selectedId);
  try {
    const res = await fetch('/api/admin/boutiques/' + selectedId + '/renew', {
      method: 'PATCH',
      headers: { 'x-admin-secret': secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ months: m, amount: amount })
    });
    if (!res.ok) { alert('Failed. Try again.'); return; }
    const data = await res.json();
    const idx = boutiques.findIndex(x => x.id === selectedId);
    if (idx !== -1) { boutiques[idx].expires_at = data.boutique.expires_at; boutiques[idx].is_active = true; }
    updateStats(); renderList(); closeModalNow();
    alert((b ? b.name : 'Boutique') + ' renewed for ' + m + ' month(s)!' + (amount > 0 ? ' Payment of \\u20B9' + amount.toLocaleString('en-IN') + ' recorded.' : ''));
  } catch(e) { alert('Connection error.'); }
}

function togglePlanRow() {
  var row = document.getElementById('plan-row');
  row.style.display = row.style.display === 'none' ? 'block' : 'none';
}

async function doChangePlan(newPlan) {
  var b = boutiques.find(function(x){ return x.id === selectedId; });
  var name = b ? b.name : 'this boutique';
  if (!confirm('Change plan for ' + name + ' to ' + newPlan.toUpperCase() + '?')) return;
  try {
    var res = await fetch('/api/admin/boutiques/' + selectedId + '/plan', {
      method: 'PATCH',
      headers: { 'x-admin-secret': secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan: newPlan })
    });
    if (!res.ok) { alert('Failed. Try again.'); return; }
    var idx = boutiques.findIndex(function(x){ return x.id === selectedId; });
    if (idx !== -1) boutiques[idx].plan = newPlan;
    document.getElementById('plan-row').style.display = 'none';
    updateStats(); renderList(); openModal(selectedId);
    alert(name + ' plan changed to ' + newPlan.toUpperCase() + '!');
  } catch(e) { alert('Connection error.'); }
}

function toggleResetRow() {
  const row = document.getElementById('reset-row');
  row.style.display = row.style.display === 'none' ? 'block' : 'none';
  if (row.style.display === 'block') document.getElementById('reset-pass-input').focus();
}

async function doResetPassword() {
  const newPass = document.getElementById('reset-pass-input').value.trim();
  if (!newPass) { alert('Enter a password first.'); return; }
  if (newPass.length < 8) { alert('Password must be at least 8 characters.'); return; }
  const b = boutiques.find(x => x.id === selectedId);
  try {
    const res = await fetch('/api/admin/boutiques/' + selectedId + '/reset-password', {
      method: 'PATCH',
      headers: { 'x-admin-secret': secret, 'Content-Type': 'application/json' },
      body: JSON.stringify({ newPassword: newPass })
    });
    if (!res.ok) { alert('Failed. Try again.'); return; }
    document.getElementById('reset-row').style.display = 'none';
    document.getElementById('reset-pass-input').value = '';
    alert('Password for ' + (b ? b.name : 'boutique') + ' has been reset to:\\n\\n' + newPass + '\\n\\nShare this with the owner.');
  } catch(e) { alert('Connection error.'); }
}

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'COPIED!';
    btn.style.background = '#2d8f6f';
    setTimeout(() => { btn.textContent = orig; btn.style.background = '#1a1a2e'; }, 1500);
  });
}


</script>
</body>
</html>`);
});

// List all boutiques (admin)
app.get('/api/admin/boutiques', adminAuth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, name, owner_name, email, phone, city, plan, is_active, is_free, expires_at, created_at
       FROM boutiques ORDER BY id ASC`
    );
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Renew subscription (admin)
app.patch('/api/admin/boutiques/:id/renew', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { months, amount, notes } = req.body;
    if (!months || months < 1) return res.status(400).json({ error: 'months required' });

    const plan = months >= 12 ? 'yearly' : 'monthly';

    const result = await db.query(
      `UPDATE boutiques
       SET expires_at = GREATEST(NOW(), COALESCE(expires_at, NOW())) + ($1 || ' months')::INTERVAL,
           is_active  = true,
           plan       = $3,
           updated_at = NOW()
       WHERE id = $2
       RETURNING id, name, is_active, expires_at, plan`,
      [months, id, plan]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Boutique not found' });

    // Auto-log the payment if amount provided
    if (amount && amount > 0) {
      await db.query(
        'INSERT INTO subscription_payments (boutique_id, amount, months, plan, notes) VALUES ($1,$2,$3,$4,$5)',
        [id, amount, months, plan, notes || '']
      );
    }

    res.json({ message: `Renewed for ${months} month(s) (${plan})`, boutique: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset boutique password (admin)
app.patch('/api/admin/boutiques/:id/reset-password', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const hash = await bcrypt.hash(newPassword, 12);
    const result = await db.query(
      'UPDATE boutiques SET password=$1, updated_at=NOW() WHERE id=$2 RETURNING id, name',
      [hash, id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Boutique not found' });
    res.json({ message: 'Password reset successfully', boutique: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Change plan (admin)
app.patch('/api/admin/boutiques/:id/plan', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { plan } = req.body;
    const allowed = ['free', 'monthly', 'yearly', 'pro'];
    if (!allowed.includes(plan)) return res.status(400).json({ error: 'Invalid plan' });
    const result = await db.query(
      'UPDATE boutiques SET plan=$1, updated_at=NOW() WHERE id=$2 RETURNING id, name, plan',
      [plan, id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Boutique not found' });
    res.json({ message: 'Plan updated to ' + plan, boutique: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Toggle free account (admin)
app.patch('/api/admin/boutiques/:id/free', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_free } = req.body;
    const result = await db.query(
      'UPDATE boutiques SET is_free=$1, updated_at=NOW() WHERE id=$2 RETURNING id, name, is_free',
      [is_free, id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Boutique not found' });
    res.json({ message: is_free ? 'Free access granted' : 'Free access removed', boutique: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Boutique activity stats (admin)
app.get('/api/admin/boutiques/:id/stats', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const [custRes, ordRes, invRes, boutRes] = await Promise.all([
      db.query('SELECT COUNT(*)::int as count FROM customers WHERE boutique_id=$1', [id]),
      db.query('SELECT COUNT(*)::int as count FROM orders WHERE boutique_id=$1', [id]),
      db.query('SELECT COUNT(*)::int as count, COALESCE(SUM(total_amount),0)::float as revenue FROM invoices WHERE boutique_id=$1', [id]),
      db.query('SELECT last_login_at FROM boutiques WHERE id=$1', [id]),
    ]);
    res.json({
      customers:    custRes.rows[0].count,
      orders:       ordRes.rows[0].count,
      invoices:     invRes.rows[0].count,
      app_revenue:  invRes.rows[0].revenue,
      last_login_at: boutRes.rows[0]?.last_login_at || null,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Subscription payment history (admin)
app.get('/api/admin/boutiques/:id/payments', adminAuth, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM subscription_payments WHERE boutique_id=$1 ORDER BY paid_at DESC',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Log a subscription payment (admin)
app.post('/api/admin/boutiques/:id/payments', adminAuth, async (req, res) => {
  try {
    const { amount, months, plan, notes } = req.body;
    const result = await db.query(
      'INSERT INTO subscription_payments (boutique_id, amount, months, plan, notes) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.params.id, amount || 0, months || 1, plan || 'monthly', notes || '']
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
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
//
//  Measurement storage — both columns are JSONB (schema-agnostic):
//
//  measurements_top   — male:   { "Chest": 40, "Shoulder": 16, ... }
//                     — female: { "blouse_Length": 16, "blouse_Chest 1": 36,
//                                 "dress_Length": 42, "dress_Waist": 28, ... }
//                       (prefix "blouse_" or "dress_" distinguishes garment type;
//                        legacy unprefixed female keys are treated as blouse)
//
//  measurements_bottom — male:   { "Waist": 34, "Inseam": 30, ... }
//                      — female: { "Salwar Length": 38, "Waist": 28, "Hip": 38,
//                                  "Thigh": 22, "Knee": 16 }
//
//  No schema migration needed — add any custom field on the client and it
//  persists transparently in the JSONB column.
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
    // Fetch current row first — use as fallback for any field not sent
    const old = await db.query(
      'SELECT * FROM orders WHERE id=$1 AND boutique_id=$2',
      [req.params.id, req.boutiqueId]
    );
    if (!old.rows.length) return res.status(404).json({ error: 'Not found' });
    const prev = old.rows[0];

    const b = req.body;
    const customer_id   = b.customer_id   ?? prev.customer_id;
    const customer_name = b.customer_name ?? prev.customer_name;
    const customer_phone= b.customer_phone?? prev.customer_phone;
    const garment       = b.garment       ?? prev.garment;
    const fabric        = b.fabric        ?? prev.fabric;
    const due_date      = 'due_date' in b ? b.due_date : prev.due_date;
    const amount        = b.amount        !== undefined ? b.amount        : (b.total_amount  !== undefined ? b.total_amount  : prev.amount);
    const advance       = b.advance       !== undefined ? b.advance       : (b.advance_paid  !== undefined ? b.advance_paid  : prev.advance);
    const stage         = b.stage         ?? b.status  ?? prev.stage;
    const notify        = b.notify        !== undefined ? b.notify !== false : prev.notify;
    const notes         = b.notes         ?? prev.notes;
    const bal           = Math.max(0, amount - advance);

    const result = await db.query(
      `UPDATE orders SET
         customer_id=$1, customer_name=$2, customer_phone=$3,
         garment=$4, fabric=$5, due_date=$6,
         amount=$7, advance=$8, balance=$9,
         stage=$10, notify=$11, notes=$12, updated_at=NOW()
       WHERE id=$13 AND boutique_id=$14 RETURNING *`,
      [customer_id, customer_name, customer_phone,
       garment, fabric, due_date,
       amount, advance, bal,
       stage, notify, notes,
       req.params.id, req.boutiqueId]
    );

    const order = result.rows[0];
    if (prev.stage !== 'ready' && (stage||'').toLowerCase() === 'ready' && prev.notify) {
      await autoNotify(req.boutiqueId, prev.customer_id, prev.customer_name, prev.garment);
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
    const inv = result.rows[0];

    // ── Sync the linked order's payment fields ──────────────────────────────
    // So the Orders screen always reflects the latest payment state.
    if (inv.order_id) {
      const newAdv = parseFloat(inv.advance) || 0;
      const newBal = parseFloat(inv.due_amount) || 0;
      await db.query(
        `UPDATE orders SET advance=$1, balance=$2, updated_at=NOW()
         WHERE id=$3 AND boutique_id=$4`,
        [newAdv, newBal, inv.order_id, req.boutiqueId]
      ).catch(() => {}); // silently ignore if order already deleted
    }

    res.json(inv);
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
    const inv = result.rows[0];

    // ── Sync the linked order ────────────────────────────────────────────────
    if (inv.order_id) {
      const fullAdv = parseFloat(inv.total_amount) || 0;
      await db.query(
        `UPDATE orders SET advance=$1, balance=0, updated_at=NOW()
         WHERE id=$2 AND boutique_id=$3`,
        [fullAdv, inv.order_id, req.boutiqueId]
      ).catch(() => {});
    }

    res.json(inv);
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
