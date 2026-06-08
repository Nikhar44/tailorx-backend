-- TailorX Database Schema
-- Run this file once in your PostgreSQL database to set up all tables

-- ─────────────────────────────────────────────
--  BOUTIQUES (one per subscription customer)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS boutiques (
  id          SERIAL PRIMARY KEY,
  name        VARCHAR(200) NOT NULL,
  owner_name  VARCHAR(200),
  phone       VARCHAR(20),
  email       VARCHAR(200) UNIQUE NOT NULL,
  password    VARCHAR(255) NOT NULL,      -- bcrypt hashed
  city        VARCHAR(100) DEFAULT 'Surat',
  address     TEXT,
  gstin       VARCHAR(20),
  plan        VARCHAR(20) DEFAULT 'free', -- free / starter / pro
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────
--  CUSTOMERS (belong to a boutique)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customers (
  id           SERIAL PRIMARY KEY,
  boutique_id  INTEGER NOT NULL REFERENCES boutiques(id) ON DELETE CASCADE,
  name         VARCHAR(200) NOT NULL,
  phone        VARCHAR(20),
  email        VARCHAR(200),
  city         VARCHAR(100) DEFAULT 'Surat',
  gender       VARCHAR(10),               -- male / female
  notify       VARCHAR(20) DEFAULT 'WhatsApp', -- WhatsApp / SMS / Email
  notes        TEXT,
  -- Measurements stored as JSONB for flexibility
  measurements_top    JSONB DEFAULT '{}',
  measurements_bottom JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────
--  ORDERS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS orders (
  id            SERIAL PRIMARY KEY,
  boutique_id   INTEGER NOT NULL REFERENCES boutiques(id) ON DELETE CASCADE,
  customer_id   INTEGER REFERENCES customers(id) ON DELETE SET NULL,
  customer_name VARCHAR(200),
  garment       VARCHAR(200) NOT NULL,
  fabric        VARCHAR(200),
  due_date      DATE,
  amount        NUMERIC(10,2) DEFAULT 0,
  advance       NUMERIC(10,2) DEFAULT 0,
  balance       NUMERIC(10,2) DEFAULT 0,
  stage         VARCHAR(30) DEFAULT 'received', -- received/cutting/stitching/ready/dispensed
  notify        BOOLEAN DEFAULT TRUE,
  notes         TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────
--  INVOICES
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invoices (
  id              SERIAL PRIMARY KEY,
  boutique_id     INTEGER NOT NULL REFERENCES boutiques(id) ON DELETE CASCADE,
  customer_id     INTEGER REFERENCES customers(id) ON DELETE SET NULL,
  customer_name   VARCHAR(200),
  customer_phone  VARCHAR(20),
  order_id        INTEGER REFERENCES orders(id) ON DELETE SET NULL,
  garment         VARCHAR(200),
  bill_date       DATE DEFAULT CURRENT_DATE,
  items           JSONB DEFAULT '[]',     -- [{desc, qty, rate, amt}]
  subtotal        NUMERIC(10,2) DEFAULT 0,
  discount_pct    NUMERIC(5,2) DEFAULT 0,
  discount_amt    NUMERIC(10,2) DEFAULT 0,
  total_amount    NUMERIC(10,2) DEFAULT 0,
  advance         NUMERIC(10,2) DEFAULT 0,
  due_amount      NUMERIC(10,2) DEFAULT 0,
  remarks         TEXT,
  status          VARCHAR(20) DEFAULT 'pending', -- pending / paid
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────
--  NOTIFICATIONS LOG
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
  id           SERIAL PRIMARY KEY,
  boutique_id  INTEGER NOT NULL REFERENCES boutiques(id) ON DELETE CASCADE,
  type         VARCHAR(20),   -- whatsapp / sms / email
  title        VARCHAR(300),
  msg          TEXT,
  is_read      BOOLEAN DEFAULT FALSE,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────
--  INDEXES for performance
-- ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_customers_boutique ON customers(boutique_id);
CREATE INDEX IF NOT EXISTS idx_orders_boutique    ON orders(boutique_id);
CREATE INDEX IF NOT EXISTS idx_orders_customer    ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_boutique  ON invoices(boutique_id);
CREATE INDEX IF NOT EXISTS idx_notifs_boutique    ON notifications(boutique_id);
CREATE INDEX IF NOT EXISTS idx_notifs_read        ON notifications(boutique_id, is_read);
