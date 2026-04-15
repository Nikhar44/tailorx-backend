const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'tailorx-secret-change-in-prod';

function hash(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function mkToken(p, exp = 86400000) { const d = Buffer.from(JSON.stringify({ ...p, exp: Date.now() + exp })).toString('base64'); return `${d}.${crypto.createHmac('sha256', JWT_SECRET).update(d).digest('hex')}`; }
function chkToken(t) { if (!t) return null; t = t.replace('Bearer ', ''); const parts = t.split('.'); if (parts.length !== 2) return null; const [d, s] = parts; if (s !== crypto.createHmac('sha256', JWT_SECRET).update(d).digest('hex')) return null; try { const p = JSON.parse(Buffer.from(d, 'base64').toString()); return p.exp > Date.now() ? p : null; } catch { return null; } }
function auth(req, res, next) { const u = chkToken(req.headers.authorization); if (!u) return res.status(401).json({ error: 'Unauthorized' }); req.user = u; next(); }
function adminAuth(req, res, next) { const u = chkToken(req.headers.authorization); if (!u || u.role !== 'admin') return res.status(401).json({ error: 'Admin required' }); req.admin = u; next(); }
function genKey() { const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let k = ''; for (let i = 0; i < 16; i++) { if (i > 0 && i % 4 === 0) k += '-'; k += c[Math.floor(Math.random() * c.length)]; } return k; }

// Health
app.get('/api/health', (_, res) => res.json({ status: 'ok', v: '2.0.0' }));

// License verify
app.post('/api/license/verify', async (req, res) => {
  try {
    const { license_key } = req.body;
    if (!license_key) return res.json({ status: 'invalid' });
    const r = await pool.query('SELECT * FROM licenses WHERE license_key=$1', [license_key]);
    if (!r.rows.length) return res.json({ status: 'invalid' });
    const l = r.rows[0];
    if (l.expires_at && new Date(l.expires_at) < new Date()) {
      await pool.query("UPDATE licenses SET status='expired',updated_at=NOW() WHERE id=$1", [l.id]);
      return res.json({ status: 'expired' });
    }
    res.json({ status: l.status, boutique_name: l.boutique_name, plan: l.plan, expires_at: l.expires_at });
  } catch (e) { res.json({ status: 'error' }); }
});

// Auth
app.post('/api/auth/register', async (req, res) => {
  try {
    const { license_key, name, owner_name, email, password, phone, address } = req.body;
    if (!license_key) return res.status(400).json({ error: 'License key required' });
    const lr = await pool.query('SELECT * FROM licenses WHERE license_key=$1', [license_key]);
    if (!lr.rows.length) return res.status(400).json({ error: 'Invalid license key' });
    const l = lr.rows[0];
    if (l.status !== 'active') return res.status(403).json({ error: `License ${l.status}` });
    const ex = await pool.query('SELECT id FROM boutiques WHERE email=$1', [email]);
    if (ex.rows.length) return res.status(400).json({ error: 'Email already registered' });
    const r = await pool.query('INSERT INTO boutiques(license_id,name,owner_name,email,password,phone,address) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,owner_name,email',
      [l.id, name, owner_name, email, hash(password), phone || '', address || '']);
    const b = r.rows[0];
    res.json({ token: mkToken({ id: b.id, email: b.email, name: b.name, license_id: l.id }), boutique: b });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const r = await pool.query('SELECT b.*,l.status as ls,l.expires_at as le FROM boutiques b JOIN licenses l ON b.license_id=l.id WHERE b.email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const b = r.rows[0];
    if (b.password !== hash(password)) return res.status(401).json({ error: 'Invalid credentials' });
    if (b.ls === 'hold') return res.status(403).json({ error: 'Account on hold. Contact support.' });
    if (b.ls === 'expired' || (b.le && new Date(b.le) < new Date())) return res.status(403).json({ error: 'Subscription expired.' });
    res.json({ token: mkToken({ id: b.id, email: b.email, name: b.name, license_id: b.license_id }), boutique: { id: b.id, name: b.name, owner_name: b.owner_name, email: b.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ DASHBOARD ═══
// Columns: notifications.msg (not message), orders.stage (not status), orders.amount (not total_amount), orders.balance, orders.advance
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const id = req.user.id;
    const [c, o, p, r, ro, n] = await Promise.all([
      pool.query('SELECT COUNT(*)::int as c FROM customers WHERE boutique_id=$1', [id]),
      pool.query('SELECT COUNT(*)::int as c FROM orders WHERE boutique_id=$1', [id]),
      pool.query("SELECT COUNT(*)::int as c FROM orders WHERE boutique_id=$1 AND stage='Received'", [id]),
      pool.query('SELECT COALESCE(SUM(amount),0)::float as t FROM orders WHERE boutique_id=$1', [id]),
      pool.query('SELECT o.*, c.name as cust_name FROM orders o JOIN customers c ON o.customer_id=c.id WHERE o.boutique_id=$1 ORDER BY o.created_at DESC LIMIT 5', [id]),
      pool.query('SELECT * FROM notifications WHERE boutique_id=$1 AND is_read=false ORDER BY created_at DESC LIMIT 10', [id])
    ]);
    res.json({
      stats: {
        totalCustomers: c.rows[0].c,
        totalOrders: o.rows[0].c,
        pendingOrders: p.rows[0].c,
        totalRevenue: r.rows[0].t
      },
      recentOrders: ro.rows.map(o => ({
        ...o,
        customer_name: o.cust_name || o.customer_name,
        order_number: 'ORD-' + String(o.id).padStart(4, '0'),
        total_amount: o.amount,
        status: o.stage
      })),
      notifications: n.rows.map(nn => ({ ...nn, message: nn.msg }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ CUSTOMERS ═══
// Columns: id, boutique_id, name, phone, email, city, gender, notify, notes, measurements_top, measurements_bottom, created_at, updated_at, address, measurements, notification_pref
app.get('/api/customers', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM customers WHERE boutique_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/customers/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM customers WHERE id=$1 AND boutique_id=$2', [req.params.id, req.user.id]);
    r.rows.length ? res.json(r.rows[0]) : res.status(404).json({ error: 'Not found' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/customers', auth, async (req, res) => {
  try {
    const { name, phone, email, address, city, gender, notify, notes, measurements, measurements_top, measurements_bottom, notification_pref } = req.body;
    const r = await pool.query(
      'INSERT INTO customers(boutique_id,name,phone,email,address,city,gender,notify,notes,measurements,measurements_top,measurements_bottom,notification_pref) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *',
      [req.user.id, name, phone||'', email||'', address||'', city||'', gender||'', notify||'whatsapp', notes||'', measurements||'', measurements_top||'', measurements_bottom||'', notification_pref||'whatsapp']
    );
    // Notification
    try {
      await pool.query('INSERT INTO notifications(boutique_id,type,title,msg) VALUES($1,$2,$3,$4)',
        [req.user.id, 'customer', 'New Customer', name + ' added.']);
    } catch(ne) { /* ignore notification errors */ }
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/customers/:id', auth, async (req, res) => {
  try {
    const { name, phone, email, address, city, gender, notify, notes, measurements, measurements_top, measurements_bottom, notification_pref } = req.body;
    const r = await pool.query(
      'UPDATE customers SET name=$1,phone=$2,email=$3,address=$4,city=$5,gender=$6,notify=$7,notes=$8,measurements=$9,measurements_top=$10,measurements_bottom=$11,notification_pref=$12,updated_at=NOW() WHERE id=$13 AND boutique_id=$14 RETURNING *',
      [name, phone||'', email||'', address||'', city||'', gender||'', notify||'whatsapp', notes||'', measurements||'', measurements_top||'', measurements_bottom||'', notification_pref||'whatsapp', req.params.id, req.user.id]
    );
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/customers/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM customers WHERE id=$1 AND boutique_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'Deleted' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ ORDERS ═══
// Columns: id, boutique_id, customer_id, customer_name, garment, fabric, due_date, amount, advance, balance, stage, notify, notes, created_at, updated_at
app.get('/api/orders', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT o.*, c.name as cust_name FROM orders o JOIN customers c ON o.customer_id=c.id WHERE o.boutique_id=$1 ORDER BY o.created_at DESC',
      [req.user.id]);
    // Map to frontend expected format
    res.json(result.rows.map(o => ({
      ...o,
      customer_name: o.cust_name || o.customer_name,
      order_number: 'ORD-' + String(o.id).padStart(4, '0'),
      total_amount: o.amount,
      advance_paid: o.advance,
      balance_due: o.balance,
      status: o.stage,
      delivery_date: o.due_date
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    const { customer_id, items, total_amount, advance_paid, delivery_date, notes, garment, fabric } = req.body;
    const balance = (total_amount || 0) - (advance_paid || 0);

    // Get customer name
    const custResult = await pool.query('SELECT name FROM customers WHERE id=$1', [customer_id]);
    const customerName = custResult.rows[0]?.name || '';

    // Build garment string from items if not provided directly
    let garmentStr = garment || '';
    if (!garmentStr && items && items.length) {
      garmentStr = items.map(i => i.name + (i.qty > 1 ? ' x' + i.qty : '')).join(', ');
    }

    const r = await pool.query(
      "INSERT INTO orders(boutique_id,customer_id,customer_name,garment,fabric,due_date,amount,advance,balance,stage,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'Received',$10) RETURNING *",
      [req.user.id, customer_id, customerName, garmentStr, fabric||'', delivery_date||null, total_amount||0, advance_paid||0, balance, notes||'']
    );

    // Notification
    try {
      await pool.query('INSERT INTO notifications(boutique_id,type,title,msg) VALUES($1,$2,$3,$4)',
        [req.user.id, 'order', 'New Order', 'ORD-' + String(r.rows[0].id).padStart(4,'0') + ' for ' + customerName]);
    } catch(ne) {}

    const o = r.rows[0];
    res.json({
      ...o,
      customer_name: customerName,
      order_number: 'ORD-' + String(o.id).padStart(4, '0'),
      total_amount: o.amount,
      advance_paid: o.advance,
      balance_due: o.balance,
      status: o.stage,
      delivery_date: o.due_date
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/orders/:id', auth, async (req, res) => {
  try {
    const { items, total_amount, advance_paid, status, delivery_date, notes, garment, fabric } = req.body;
    const balance = (total_amount || 0) - (advance_paid || 0);

    let garmentStr = garment || '';
    if (!garmentStr && items && items.length) {
      garmentStr = items.map(i => i.name + (i.qty > 1 ? ' x' + i.qty : '')).join(', ');
    }

    // Map status back to stage
    const stage = status || 'Received';

    await pool.query(
      'UPDATE orders SET garment=$1,fabric=$2,due_date=$3,amount=$4,advance=$5,balance=$6,stage=$7,notes=$8,updated_at=NOW() WHERE id=$9 AND boutique_id=$10',
      [garmentStr, fabric||'', delivery_date||null, total_amount||0, advance_paid||0, balance, stage, notes||'', req.params.id, req.user.id]
    );
    const result = await pool.query('SELECT o.*, c.name as cust_name FROM orders o JOIN customers c ON o.customer_id=c.id WHERE o.id=$1', [req.params.id]);
    const o = result.rows[0];
    res.json({
      ...o,
      customer_name: o.cust_name || o.customer_name,
      order_number: 'ORD-' + String(o.id).padStart(4, '0'),
      total_amount: o.amount,
      advance_paid: o.advance,
      balance_due: o.balance,
      status: o.stage,
      delivery_date: o.due_date
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ INVOICES ═══
// Columns: id, boutique_id, customer_id, customer_name, customer_phone, order_id, garment, bill_date, items, subtotal, discount_pct, discount_amt, total_amount, advance, due_amount, remarks, status, created_at, updated_at
app.get('/api/invoices', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT i.*, c.name as cust_name FROM invoices i JOIN customers c ON i.customer_id=c.id WHERE i.boutique_id=$1 ORDER BY i.created_at DESC',
      [req.user.id]);
    res.json(result.rows.map(i => ({
      ...i,
      customer_name: i.cust_name || i.customer_name,
      invoice_number: 'INV-' + String(i.id).padStart(4, '0'),
      order_number: i.order_id ? 'ORD-' + String(i.order_id).padStart(4, '0') : '—',
      amount: i.subtotal || i.total_amount,
      tax: i.discount_amt || 0,
      total: i.total_amount
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/invoices', auth, async (req, res) => {
  try {
    const { order_id, customer_id, amount, tax, due_date, notes } = req.body;
    const total = (amount || 0) + (tax || 0);

    // Get customer info
    const custR = await pool.query('SELECT name, phone FROM customers WHERE id=$1', [customer_id]);
    const custName = custR.rows[0]?.name || '';
    const custPhone = custR.rows[0]?.phone || '';

    // Get garment from order
    let garment = '';
    if (order_id) {
      const ordR = await pool.query('SELECT garment FROM orders WHERE id=$1', [order_id]);
      garment = ordR.rows[0]?.garment || '';
    }

    const r = await pool.query(
      "INSERT INTO invoices(boutique_id,customer_id,customer_name,customer_phone,order_id,garment,bill_date,subtotal,discount_pct,discount_amt,total_amount,advance,due_amount,remarks,status) VALUES($1,$2,$3,$4,$5,$6,NOW(),$7,0,$8,$9,0,$9,$10,'unpaid') RETURNING *",
      [req.user.id, customer_id, custName, custPhone, order_id||null, garment, amount||0, tax||0, total, notes||'']
    );

    // Notification
    try {
      await pool.query('INSERT INTO notifications(boutique_id,type,title,msg) VALUES($1,$2,$3,$4)',
        [req.user.id, 'invoice', 'Invoice Created', 'INV-' + String(r.rows[0].id).padStart(4,'0') + ' generated.']);
    } catch(ne) {}

    const i = r.rows[0];
    res.json({
      ...i,
      invoice_number: 'INV-' + String(i.id).padStart(4, '0'),
      order_number: i.order_id ? 'ORD-' + String(i.order_id).padStart(4, '0') : '—',
      amount: i.subtotal,
      tax: i.discount_amt,
      total: i.total_amount
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/invoices/:id', auth, async (req, res) => {
  try {
    const { amount, tax, status, due_date, notes } = req.body;
    const total = (amount || 0) + (tax || 0);
    await pool.query(
      'UPDATE invoices SET subtotal=$1,discount_amt=$2,total_amount=$3,status=$4,remarks=$5,updated_at=NOW() WHERE id=$6 AND boutique_id=$7',
      [amount||0, tax||0, total, status||'unpaid', notes||'', req.params.id, req.user.id]
    );
    const result = await pool.query('SELECT i.*, c.name as cust_name FROM invoices i JOIN customers c ON i.customer_id=c.id WHERE i.id=$1', [req.params.id]);
    const i = result.rows[0];
    res.json({
      ...i,
      customer_name: i.cust_name || i.customer_name,
      invoice_number: 'INV-' + String(i.id).padStart(4, '0'),
      order_number: i.order_id ? 'ORD-' + String(i.order_id).padStart(4, '0') : '—',
      amount: i.subtotal,
      tax: i.discount_amt,
      total: i.total_amount
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ NOTIFICATIONS ═══
// Columns: id, boutique_id, type, title, msg (not message), is_read, created_at
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notifications WHERE boutique_id=$1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json(result.rows.map(n => ({ ...n, message: n.msg })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET is_read=true WHERE id=$1 AND boutique_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'Read' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bill delivery
app.post('/api/send-bill', auth, async (req, res) => {
  try {
    await pool.query('INSERT INTO notifications(boutique_id,type,title,msg) VALUES($1,$2,$3,$4)',
      [req.user.id, 'bill', 'Bill Delivery', 'Bill queued via ' + req.body.method]);
  } catch(e) {}
  res.json({ message: 'Queued for ' + req.body.method });
});

// ═══ ADMIN ═══
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const r = await pool.query('SELECT * FROM admin_users WHERE username=$1 AND password=$2', [username, password]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: mkToken({ role: 'admin', username }) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/licenses', adminAuth, async (_, res) => {
  try { res.json((await pool.query('SELECT * FROM licenses ORDER BY created_at DESC')).rows); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/licenses', adminAuth, async (req, res) => {
  try {
    const { boutique_name, owner_name, email, phone, plan, notes } = req.body;
    const k = genKey();
    let exp = null;
    if (plan === 'monthly') exp = new Date(Date.now() + 30 * 864e5);
    else if (plan === 'yearly') exp = new Date(Date.now() + 365 * 864e5);
    const r = await pool.query(
      "INSERT INTO licenses(license_key,boutique_name,owner_name,email,phone,status,plan,expires_at,notes) VALUES($1,$2,$3,$4,$5,'active',$6,$7,$8) RETURNING *",
      [k, boutique_name||'', owner_name||'', email||'', phone||'', plan||'monthly', exp, notes||'']);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/licenses/:id', adminAuth, async (req, res) => {
  try {
    const { status, plan, expires_at, notes } = req.body;
    const f=[],v=[];let i=1;
    if(status){f.push(`status=$${i++}`);v.push(status)}
    if(plan){f.push(`plan=$${i++}`);v.push(plan)}
    if(expires_at!==undefined){f.push(`expires_at=$${i++}`);v.push(expires_at)}
    if(notes!==undefined){f.push(`notes=$${i++}`);v.push(notes)}
    f.push('updated_at=NOW()');v.push(req.params.id);
    const r=await pool.query(`UPDATE licenses SET ${f.join(',')} WHERE id=$${i} RETURNING *`,v);
    res.json(r.rows[0]);
  } catch(e){res.status(500).json({error:e.message})}
});

app.delete('/api/admin/licenses/:id', adminAuth, async (req, res) => {
  try { await pool.query('DELETE FROM licenses WHERE id=$1', [req.params.id]); res.json({ message: 'Deleted' }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/licenses/:id/renew', adminAuth, async (req, res) => {
  try {
    const { plan } = req.body;
    let exp = null;
    if (plan === 'monthly') exp = new Date(Date.now() + 30 * 864e5);
    else if (plan === 'yearly') exp = new Date(Date.now() + 365 * 864e5);
    const r = await pool.query("UPDATE licenses SET status='active',plan=$1,expires_at=$2,updated_at=NOW() WHERE id=$3 RETURNING *", [plan||'monthly', exp, req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/boutiques', adminAuth, async (_, res) => {
  try {
    res.json((await pool.query("SELECT b.id,b.name,b.owner_name,b.email,b.phone,b.created_at,l.license_key,l.status as license_status,l.plan,(SELECT COUNT(*)::int FROM customers WHERE boutique_id=b.id) as customer_count,(SELECT COUNT(*)::int FROM orders WHERE boutique_id=b.id) as order_count FROM boutiques b JOIN licenses l ON b.license_id=l.id ORDER BY b.created_at DESC")).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`TailorX API on port ${PORT}`));
