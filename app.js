const express = require('express');
const path    = require('path');
const bcrypt  = require('bcrypt');
const session = require('express-session');
require('dotenv').config()

const { Pool } = require('pg');


// ─── Database ──────────────────────────────────
// ───────────────────────────────

const pool = new Pool({
  host:     'localhost',
  port:     process.env.DB_PORT,  
  database: process.env.DB_NAME,   
  user:     process.env.DB_USER,   
  password: process.env.DB_PASSWORD 
});

pool.connect()
  .then(client => {
    console.log('✅ PostgreSQL connected');
    client.release();
  })
  .catch(err => {
    console.error('❌ PostgreSQL connection error:', err.message);
    process.exit(1);
  });

// ─── App Setup ────────────────────────────────────────────────────────────────

const app = express();
const SALT_ROUNDS = 12;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 } // 8 hours
}));

// Auth guard - redirects to /login if no session user
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/',       (_req, res) => res.render('home'));
app.get('/login',  (_req, res) => res.render('login',  { error: null }));

app.get('/signup', (_req, res) => res.render('signup', { error: null }));

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/signup', async (req, res) => {
  try {
    const { fullname, email, password, role, staffId } = req.body;

    if (!fullname || !email || !password || !role) {
      return res.render('signup', { error: 'All fields are required.' });
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = $1',
      [email.toLowerCase().trim()]
    );
    if (existing.rows.length > 0) {
      return res.render('signup', { error: 'An account with that email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    await pool.query(
      `INSERT INTO users (fullname, email, password_hash, role, staff_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [fullname, email.toLowerCase().trim(), passwordHash, role, staffId || null]
    );

    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    res.render('signup', { error: 'Something went wrong. Please try again.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.render('login', { error: 'Please fill in all fields.' });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = $1 AND is_active = TRUE',
      [email.toLowerCase().trim()]
    );
    const user = result.rows[0];

    if (!user) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    await pool.query(
      'UPDATE users SET last_login_at = NOW() WHERE id = $1',
      [user.id]
    );

    req.session.user = {
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      role: user.role
    };

    switch (user.role) {
      case 'admin':
        return res.redirect('/inventory');
      case 'director':
        return res.redirect('/dashboard');
      case 'sales_agent':
        return res.redirect('/agent');
      default:
        return res.redirect('/agent');
    }

  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Something went wrong. Please try again.' });
  }
});
app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;

    const stats = {
      totalRevenue: 0,
      revenueGrowth: 0,
      totalTransactions: 0,
      txGrowth: 0,
      avgSaleValue: 0,
      activeStaff: 0,
      branchCount: 0,
      lowStockCount: 0,
      grossProfit: 0,
      profitMargin: '0.0'
    };

    const salesChart = {
      labels:  ['Jan','Feb','Mar','Apr','May','Jun'],
      revenue: [0, 0, 0, 0, 0, 0],
      target:  [45, 45, 45, 45, 45, 45]
    };

    const branchSales      = [];
    const inventory        = [];
    const staffPerformance = [];
    const sales            = [];
    const topProducts      = [];

    res.render('dashboard-director', {
      user,
      stats,
      salesChart,
      branchSales,
      inventory,
      staffPerformance,
      sales,
      topProducts
    });

  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).send('<h2>Dashboard error: ' + err.message + '</h2>');
  }
});

// ─── Inventory Admin ──────────────────────────────────────────────────────────

async function loadInventoryData() {
  const productsResult = await pool.query(`
    SELECT
      p.id,
      p.name,
      p.cost_price    AS "costPrice",
      p.selling_price AS "sellingPrice",
      p.stock,
      p.reorder_level AS "reorder",
      c.id   AS "categoryId",
      COALESCE(c.name, 'Uncategorized') AS "categoryName"
    FROM products p
    LEFT JOIN categories c ON c.id = p.category_id
    ORDER BY p.name
  `);

  const products = productsResult.rows.map(p => ({
    ...p,
    costPrice: Number(p.costPrice),
    sellingPrice: Number(p.sellingPrice),
    low: p.stock <= p.reorder
  }));

  const categoriesResult = await pool.query(`
    SELECT
      c.id,
      c.name,
      COUNT(p.id)::int AS "productCount"
    FROM categories c
    LEFT JOIN products p ON p.category_id = c.id
    GROUP BY c.id, c.name
    ORDER BY c.name
  `);
  const categories = categoriesResult.rows;

  const movementsResult = await pool.query(`
    SELECT
      to_char(m.created_at, 'YYYY-MM-DD HH24:MI') AS date,
      p.name AS "productName",
      m.type,
      m.qty,
      COALESCE(m.note, '') AS note
    FROM stock_movements m
    JOIN products p ON p.id = m.product_id
    ORDER BY m.created_at DESC
    LIMIT 20
  `);
  const movements = movementsResult.rows;

  const salesResult = await pool.query(`
    SELECT
      to_char(s.created_at, 'YYYY-MM-DD HH24:MI') AS date,
      p.name AS "productName",
      s.qty,
      s.price,
      s.total
    FROM sales s
    JOIN products p ON p.id = s.product_id
    ORDER BY s.created_at DESC
    LIMIT 20
  `);
  const sales = salesResult.rows.map(s => ({
    ...s,
    price: Number(s.price),
    total: Number(s.total)
  }));

  const topProductsResult = await pool.query(`
    SELECT
      p.name,
      SUM(s.qty)::int AS qty,
      SUM(s.total) AS revenue
    FROM sales s
    JOIN products p ON p.id = s.product_id
    GROUP BY p.name
    ORDER BY revenue DESC
    LIMIT 5
  `);
  const topProducts = topProductsResult.rows.map(tp => ({
    ...tp,
    revenue: Number(tp.revenue)
  }));

  const lowStockProducts = products.filter(p => p.low);

  const totalsResult = await pool.query(`
    SELECT
      COALESCE(SUM(s.total), 0) AS "totalRevenue",
      COALESCE(SUM(s.qty * p.cost_price), 0) AS "totalCost"
    FROM sales s
    JOIN products p ON p.id = s.product_id
  `);
  const totals = totalsResult.rows[0];
  const totalRevenue = Number(totals.totalRevenue);
  const totalCost    = Number(totals.totalCost);

  const totalStockValue = products.reduce(
    (sum, p) => sum + p.stock * p.costPrice,
    0
  );

  const summary = {
    totalProducts:   products.length,
    totalStockValue,
    lowStockCount:   lowStockProducts.length,
    totalRevenue,
    totalCost,
    grossProfit:     totalRevenue - totalCost
  };

  return { products, categories, movements, sales, topProducts, lowStockProducts, summary };
}

app.get('/inventory', requireLogin, async (req, res) => {
  try {
    const data = await loadInventoryData();
    res.render('inventory-admin', { ...data, user: req.session.user });
  } catch (err) {
    console.error('Inventory page error:', err);
    res.status(500).send('<h2>Inventory error: ' + err.message + '</h2>');
  }
});

// ── Products ──────────────────────────────────────────────────────────────────

app.post('/products/add', requireLogin, async (req, res) => {
  try {
    const { name, categoryId, costPrice, sellingPrice, stock, reorder } = req.body;

    if (!name || !categoryId) {
      return res.redirect('/inventory');
    }

    await pool.query(
      `INSERT INTO products (name, category_id, cost_price, selling_price, stock, reorder_level)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        name.trim(),
        categoryId,
        Number(costPrice) || 0,
        Number(sellingPrice) || 0,
        parseInt(stock, 10) || 0,
        parseInt(reorder, 10) || 0
      ]
    );

    res.redirect('/inventory#products');
  } catch (err) {
    console.error('Add product error:', err);
    res.redirect('/inventory');
  }
});

app.post('/products/:id/price', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    const { sellingPrice } = req.body;

    await pool.query(
      'UPDATE products SET selling_price = $1 WHERE id = $2',
      [Number(sellingPrice) || 0, id]
    );

    res.redirect('/inventory#products');
  } catch (err) {
    console.error('Update price error:', err);
    res.redirect('/inventory');
  }
});

app.post('/products/:id/delete', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM products WHERE id = $1', [id]);
    res.redirect('/inventory#products');
  } catch (err) {
    console.error('Delete product error:', err);
    res.redirect('/inventory');
  }
});

// ── Categories ────────────────────────────────────────────────────────────────

app.post('/categories/add', requireLogin, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.redirect('/inventory#categories');

    await pool.query(
      `INSERT INTO categories (name) VALUES ($1)
       ON CONFLICT (name) DO NOTHING`,
      [name.trim()]
    );

    res.redirect('/inventory#categories');
  } catch (err) {
    console.error('Add category error:', err);
    res.redirect('/inventory');
  }
});

app.post('/categories/:id/delete', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;

    const inUse = await pool.query(
      'SELECT COUNT(*)::int AS count FROM products WHERE category_id = $1',
      [id]
    );
    if (inUse.rows[0].count > 0) {
      return res.redirect('/inventory#categories');
    }

    await pool.query('DELETE FROM categories WHERE id = $1', [id]);
    res.redirect('/inventory#categories');
  } catch (err) {
    console.error('Delete category error:', err);
    res.redirect('/inventory');
  }
});

// ── Stock & procurement ───────────────────────────────────────────────────────

app.post('/stock/procure', requireLogin, async (req, res) => {
  const client = await pool.connect();
  try {
    const { productId, qty, unitCost } = req.body;
    const quantity = parseInt(qty, 10);

    if (!productId || !quantity || quantity <= 0) {
      return res.redirect('/inventory#stock');
    }

    await client.query('BEGIN');

    if (unitCost !== '' && unitCost !== undefined && unitCost !== null) {
      await client.query(
        'UPDATE products SET stock = stock + $1, cost_price = $2 WHERE id = $3',
        [quantity, Number(unitCost), productId]
      );
    } else {
      await client.query(
        'UPDATE products SET stock = stock + $1 WHERE id = $2',
        [quantity, productId]
      );
    }

    await client.query(
      `INSERT INTO stock_movements (product_id, type, qty, note)
       VALUES ($1, 'procurement', $2, 'Stock received')`,
      [productId, quantity]
    );

    await client.query('COMMIT');
    res.redirect('/inventory#stock');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Procure stock error:', err);
    res.redirect('/inventory');
  } finally {
    client.release();
  }
});

app.post('/stock/adjust', requireLogin, async (req, res) => {
  const client = await pool.connect();
  try {
    const { productId, qty, reason } = req.body;
    const delta = parseInt(qty, 10);

    if (!productId || !delta) {
      return res.redirect('/inventory#stock');
    }

    await client.query('BEGIN');

    await client.query(
      'UPDATE products SET stock = GREATEST(stock + $1, 0) WHERE id = $2',
      [delta, productId]
    );

    await client.query(
      `INSERT INTO stock_movements (product_id, type, qty, note)
       VALUES ($1, 'adjustment', $2, $3)`,
      [productId, delta, reason || null]
    );

    await client.query('COMMIT');
    res.redirect('/inventory#stock');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Stock adjustment error:', err);
    res.redirect('/inventory');
  } finally {
    client.release();
  }
});

// ── Sales (shared by admin and agent) ────────────────────────────────────────

app.post('/sales/add', requireLogin, async (req, res) => {
  const client = await pool.connect();
  try {
    const productId = parseInt(req.body.productId, 10);
    const qty       = parseInt(req.body.qty, 10);
    const role      = req.session.user.role;
    const agentId   = req.session.user.id;
    const back      = role === 'admin' ? '/inventory#sales' : '/agent';

    if (!productId || !qty || qty <= 0) return res.redirect(back);

    await client.query('BEGIN');

    const { rows } = await client.query(
      'SELECT selling_price, stock FROM products WHERE id = $1 FOR UPDATE',
      [productId]
    );
    const product = rows[0];

    if (!product || product.stock < qty) {
      await client.query('ROLLBACK');
      return res.redirect(back);
    }

    const price = Number(product.selling_price);
    const total = price * qty;

    await client.query(
      `INSERT INTO sales (product_id, agent_id, qty, price, total)
       VALUES ($1, $2, $3, $4, $5)`,
      [productId, agentId, qty, price, total]
    );

    await client.query(
      'UPDATE products SET stock = stock - $1 WHERE id = $2',
      [qty, productId]
    );

    await client.query(
      `INSERT INTO stock_movements (product_id, type, qty, note)
       VALUES ($1, 'sale', $2, $3)`,
      [productId, -qty, `Sold by ${req.session.user.fullname}`]
    );

    await client.query('COMMIT');
    res.redirect(back);

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Record sale error:', err);
    res.redirect('/agent');
  } finally {
    client.release();
  }
});

// ─── Sales Agent Dashboard ────────────────────────────────────────────────────

app.get('/agent', requireLogin, async (req, res) => {
  try {
    const agentId   = req.session.user.id;
    const agentName = req.session.user.fullname;

    const productsResult = await pool.query(`
      SELECT
        p.id,
        p.name,
        p.selling_price AS "sellingPrice",
        p.stock,
        p.reorder_level AS "reorder",
        COALESCE(c.name, 'Uncategorized') AS "categoryName"
      FROM products p
      LEFT JOIN categories c ON c.id = p.category_id
      ORDER BY p.name
    `);
    const products = productsResult.rows.map(p => ({
      ...p,
      sellingPrice: Number(p.sellingPrice),
      low: p.stock <= p.reorder
    }));

    const salesResult = await pool.query(`
      SELECT
        to_char(s.created_at, 'YYYY-MM-DD HH24:MI') AS date,
        p.name AS "productName",
        s.qty,
        s.price,
        s.total
      FROM sales s
      JOIN products p ON p.id = s.product_id
      WHERE s.agent_id = $1
      ORDER BY s.created_at DESC
      LIMIT 50
    `, [agentId]);
    const sales = salesResult.rows.map(s => ({
      ...s,
      price: Number(s.price),
      total: Number(s.total)
    }));

    const todayResult = await pool.query(`
      SELECT
        COUNT(*)::int           AS "todaysSalesCount",
        COALESCE(SUM(total), 0) AS "todaysRevenue"
      FROM sales
      WHERE agent_id = $1 AND created_at::date = CURRENT_DATE
    `, [agentId]);

    const totalResult = await pool.query(`
      SELECT COUNT(*)::int AS "totalSalesCount"
      FROM sales WHERE agent_id = $1
    `, [agentId]);

    res.render('dashboard-agent', {
      agentName,
      products,
      sales,
      summary: {
        todaysSalesCount: todayResult.rows[0].todaysSalesCount,
        todaysRevenue:    Number(todayResult.rows[0].todaysRevenue),
        totalSalesCount:  totalResult.rows[0].totalSalesCount,
        lowStockCount:    products.filter(p => p.low).length
      }
    });

  } catch (err) {
    console.error('Agent dashboard error:', err);
    res.status(500).send('<h2>Agent dashboard error: ' + err.message + '</h2>');
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Good Choice running on http://localhost:${PORT}`));
