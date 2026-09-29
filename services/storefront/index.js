'use strict';
const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const db  = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME     || 'cartbreach',
  user:     process.env.DB_USER     || 'cart_user',
  password: process.env.DB_PASS     || 'cart_db_pass_2026!',
});

const STAGING_TOKEN = process.env.STAGING_TOKEN || 'cb_staging_9a8f2c3d4e5f';
const STAGE1_FLAG   = 'SLIIT{c4rt_br34ch_g1t_c0mm1t_l34k}';

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: 'cb-session-secret', resave: false, saveUninitialized: false }));

// Stage 4 forensic backup — accessible via directory enumeration
app.use('/static', express.static(path.join(__dirname, 'public', 'static')));

// Stage 1 flag: validates leaked Bearer token from git history
app.get('/api/v1/health', (req, res) => {
  const auth = req.headers['authorization'] || '';
  if (auth === `Bearer ${STAGING_TOKEN}`) {
    return res.json({ status: 'ok', flag: STAGE1_FLAG });
  }
  res.json({ status: 'ok' });
});

// Login — returns session cookie
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ message: 'Authenticated', username: user.username });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Stage 2 — BOLA/IDOR: no ownership check on order_id
app.get('/api/orders', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthenticated' });
  const { order_id } = req.query;
  if (!order_id) return res.status(400).json({ error: 'order_id required' });
  try {
    // ponytail: deliberate BOLA — no WHERE customer_id = $2 ownership check (stage 2 vulnerability)
    const result = await db.query('SELECT * FROM orders WHERE order_id = $1', [parseInt(order_id)]);
    if (!result.rows.length) return res.status(404).json({ error: 'Order not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// Simple storefront index page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html><html><head><title>CartBreach Logistics</title></head>
    <body>
      <h1>CartBreach Logistics Fulfillment Portal</h1>
      <p>API available at <code>/api/orders?order_id=&lt;id&gt;</code></p>
      <p>Login at <code>POST /login</code></p>
    </body></html>
  `);
});

app.listen(3000, () => console.log('storefront-web listening on :3000'));
