// TailorX Backend — server.js
// Express + PostgreSQL REST API
// Run: node server.js

require('dotenv').config();
const express  = require('express');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');

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

pool.connect().then(() => console.log('✅ PostgreSQL connected')).catch(e => console.error('❌ DB error:', e.message));

const db = {
  query: (text, params) => pool.query(text, params),
};

// ─────────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));
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

// ─────────────────────────────────────────────
//  AUTH ROUTES
// ─────────────────────────────────────────────

// Register new boutique
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, ownerName, email, password, phone, city, address } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });

    const exists = await db.query('SELECT id FROM boutiques WHERE email = $1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const result = await db.query(
      `INSERT INTO boutiques (name, owner_name, email, password, phone, city, address)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, name, owner_name, email, phone, city, address, plan`,
      [name, ownerName || '', email, hash, phone || '', city || 'Surat', address || '']
    );
    const boutique = result.rows[0];
    const token = jwt.sign({ boutiqueId: boutique.id }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '30d' });
    res.status(201).json({ token, boutique });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await db.query('SELECT * FROM boutiques WHERE email = $1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid email or password' });

    const boutique = result.rows[0];
    const valid = await bcrypt.compare(password, boutique.password);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ boutiqueId: boutique.id }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '30d' });
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

// ─────────────────────────────────────────────
//  CUSTOMERS
// ─────────────────────────────────────────────

// Get all customers (with search)
app.get('/api/customers', auth, async (req, res) => {
  try {
    const { search, gender } = req.query;
    let query = 'SELECT * FROM customers WHERE boutique_id = $1';
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
    const result = await db.query(query, params);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single customer
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

// Create customer
app.post('/api/customers', auth, async (req, res) => {
  try {
    const { name, phone, email, city, gender, notify, notes, measurements_top, measurements_bottom } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const result = await db.query(
      `INSERT INTO customers (boutique_id, name, phone, email, city, gender, notify, notes, measurements_top, measurements_bottom)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.boutiqueId, name, phone||'', email||'', city||'Surat', gender||'', notify||'WhatsApp', notes||'',
       JSON.stringify(measurements_top||{}), JSON.stringify(measurements_bottom||{})]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update customer
app.put('/api/customers/:id', auth, async (req, res) => {
  try {
    const { name, phone, email, city, gender, notify, notes, measurements_top, measurements_bottom } = req.body;
    const result = await db.query(
      `UPDATE customers SET name=$1, phone=$2, email=$3, city=$4, gender=$5, notify=$6, notes=$7,
       measurements_top=$8, measurements_bottom=$9, updated_at=NOW()
       WHERE id=$10 AND boutique_id=$11 RETURNING *`,
      [name, phone||'', email||'', city||'Surat', gender||'', notify||'WhatsApp', notes||'',
       JSON.stringify(measurements_top||{}), JSON.stringify(measurements_bottom||{}),
       req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
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
    let query = 'SELECT * FROM orders WHERE boutique_id = $1';
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
    const result = await db.query(query, params);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders/:id', auth, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM orders WHERE id = $1 AND boutique_id = $2', [req.params.id, req.boutiqueId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    const { customer_id, customer_name, garment, fabric, due_date, amount, advance, stage, notify, notes } = req.body;
    if (!garment) return res.status(400).json({ error: 'Garment required' });
    const bal = Math.max(0, (amount||0) - (advance||0));
    const result = await db.query(
      `INSERT INTO orders (boutique_id, customer_id, customer_name, garment, fabric, due_date, amount, advance, balance, stage, notify, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.boutiqueId, customer_id||null, customer_name||'', garment, fabric||'',
       due_date||null, amount||0, advance||0, bal, stage||'received', notify!==false, notes||'']
    );
    const order = result.rows[0];
    // Auto notify if stage = ready
    if (stage === 'ready' && notify !== false) {
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
    const { customer_id, customer_name, garment, fabric, due_date, amount, advance, stage, notify, notes } = req.body;
    const bal = Math.max(0, (amount||0) - (advance||0));

    // Fetch old stage to detect stage change
    const old = await db.query('SELECT stage, customer_id, customer_name, garment, notify FROM orders WHERE id=$1 AND boutique_id=$2', [req.params.id, req.boutiqueId]);
    if (!old.rows.length) return res.status(404).json({ error: 'Not found' });

    const result = await db.query(
      `UPDATE orders SET customer_id=$1, customer_name=$2, garment=$3, fabric=$4, due_date=$5,
       amount=$6, advance=$7, balance=$8, stage=$9, notify=$10, notes=$11, updated_at=NOW()
       WHERE id=$12 AND boutique_id=$13 RETURNING *`,
      [customer_id||null, customer_name||'', garment, fabric||'', due_date||null,
       amount||0, advance||0, bal, stage||'received', notify!==false, notes||'',
       req.params.id, req.boutiqueId]
    );

    const order = result.rows[0];
    // If stage changed to ready → auto notify
    if (old.rows[0].stage !== 'ready' && stage === 'ready' && old.rows[0].notify) {
      await autoNotify(req.boutiqueId, old.rows[0].customer_id, old.rows[0].customer_name, old.rows[0].garment);
    }
    res.json(order);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update only the stage
app.patch('/api/orders/:id/stage', auth, async (req, res) => {
  try {
    const { stage } = req.body;
    const old = await db.query('SELECT * FROM orders WHERE id=$1 AND boutique_id=$2', [req.params.id, req.boutiqueId]);
    if (!old.rows.length) return res.status(404).json({ error: 'Not found' });
    const order = old.rows[0];

    await db.query('UPDATE orders SET stage=$1, updated_at=NOW() WHERE id=$2', [stage, req.params.id]);

    if (order.stage !== 'ready' && stage === 'ready' && order.notify) {
      await autoNotify(req.boutiqueId, order.customer_id, order.customer_name, order.garment);
    }
    res.json({ ...order, stage });
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
    let query = 'SELECT * FROM invoices WHERE boutique_id = $1';
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
    const result = await db.query(query, params);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/invoices/:id', auth, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM invoices WHERE id = $1 AND boutique_id = $2', [req.params.id, req.boutiqueId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/invoices', auth, async (req, res) => {
  try {
    const { customer_id, customer_name, customer_phone, order_id, garment, bill_date, items,
            subtotal, discount_pct, discount_amt, total_amount, advance, due_amount, remarks } = req.body;
    if (!customer_name || !garment) return res.status(400).json({ error: 'Customer and garment required' });
    const status = (due_amount <= 0) ? 'paid' : 'pending';
    const result = await db.query(
      `INSERT INTO invoices (boutique_id, customer_id, customer_name, customer_phone, order_id, garment, bill_date,
       items, subtotal, discount_pct, discount_amt, total_amount, advance, due_amount, remarks, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [req.boutiqueId, customer_id||null, customer_name, customer_phone||'', order_id||null,
       garment, bill_date||new Date(), JSON.stringify(items||[]),
       subtotal||0, discount_pct||0, discount_amt||0, total_amount||0, advance||0, due_amount||0, remarks||'', status]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/invoices/:id/pay', auth, async (req, res) => {
  try {
    const result = await db.query(
      'UPDATE invoices SET status=$1, due_amount=0, updated_at=NOW() WHERE id=$2 AND boutique_id=$3 RETURNING *',
      ['paid', req.params.id, req.boutiqueId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
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
    let query = 'SELECT * FROM notifications WHERE boutique_id = $1';
    const params = [req.boutiqueId];
    if (type && type !== 'all') {
      params.push(type);
      query += ` AND type = $${params.length}`;
    }
    query += ' ORDER BY created_at DESC LIMIT 100';
    const result = await db.query(query, params);
    res.json(result.rows);
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
    await db.query('UPDATE notifications SET is_read=TRUE WHERE boutique_id=$1', [req.boutiqueId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    await db.query('UPDATE notifications SET is_read=TRUE WHERE id=$1 AND boutique_id=$2', [req.params.id, req.boutiqueId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  DASHBOARD SUMMARY
// ─────────────────────────────────────────────
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const bid = req.boutiqueId;
    const [ordersRes, invoicesRes, customersRes, notifRes] = await Promise.all([
      db.query('SELECT stage, COUNT(*) as count, SUM(amount) as total FROM orders WHERE boutique_id=$1 GROUP BY stage', [bid]),
      db.query('SELECT status, COUNT(*) as count, SUM(due_amount) as pending_amt, SUM(total_amount) as total_amt FROM invoices WHERE boutique_id=$1 GROUP BY status', [bid]),
      db.query('SELECT COUNT(*) as count FROM customers WHERE boutique_id=$1', [bid]),
      db.query('SELECT COUNT(*) as count FROM notifications WHERE boutique_id=$1 AND is_read=FALSE', [bid]),
    ]);

    const stageCounts = {};
    let totalOrders = 0;
    ordersRes.rows.forEach(r => { stageCounts[r.stage] = parseInt(r.count); totalOrders += parseInt(r.count); });

    let pendingAmt = 0, paidAmt = 0, pendingCount = 0;
    invoicesRes.rows.forEach(r => {
      if (r.status === 'pending') { pendingAmt = parseFloat(r.pending_amt||0); pendingCount = parseInt(r.count); }
      if (r.status === 'paid')    { paidAmt = parseFloat(r.total_amt||0); }
    });

    res.json({
      orders: { total: totalOrders, stages: stageCounts, active: totalOrders - (stageCounts.dispensed||0) },
      invoices: { pendingAmt, pendingCount, paidAmt },
      customers: parseInt(customersRes.rows[0].count),
      unreadNotifications: parseInt(notifRes.rows[0].count),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  AUTO NOTIFY HELPER
// ─────────────────────────────────────────────
async function autoNotify(boutiqueId, customerId, customerName, garment) {
  try {
    let notifyChannel = 'whatsapp';
    if (customerId) {
      const cRes = await db.query('SELECT notify FROM customers WHERE id=$1', [customerId]);
      if (cRes.rows.length) notifyChannel = (cRes.rows[0].notify||'WhatsApp').toLowerCase();
    }
    await db.query(
      'INSERT INTO notifications (boutique_id, type, title, msg) VALUES ($1,$2,$3,$4)',
      [boutiqueId, notifyChannel,
       `Order Ready — ${customerName}`,
       `Your ${garment} is ready for pickup at Riya Boutique. Please collect at your convenience.`]
    );
  } catch (e) {
    console.error('Auto notify failed:', e.message);
  }
}

// ─────────────────────────────────────────────
//  HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// ─────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 TailorX API running on port ${PORT}`));
