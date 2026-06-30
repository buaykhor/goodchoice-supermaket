const express = require('express');
const path    = require('path');
const bcrypt  = require('bcrypt');
const session = require('express-session');
require('dotenv').config()

const { Pool } = require('pg');


// ─── Database ──────────────────────────────────
// ───────────────────────────────

const pool = new Pool(
  process.env.DATABASE_URL
    ? { 
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
      }
    : {
        host:     'localhost',
        port:     process.env.DB_PORT,
        database: process.env.DB_NAME,
        user:     process.env.DB_USER,
        password: process.env.DB_PASSWORD
      }
);

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

async function ensureUserSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id             SERIAL        PRIMARY KEY,
      fullname       VARCHAR(100)  NOT NULL,
      email          VARCHAR(255)  NOT NULL UNIQUE,
      password_hash  TEXT          NOT NULL,
      role           VARCHAR(20)   NOT NULL,
      staff_id       VARCHAR(50)   DEFAULT NULL,
      is_active      BOOLEAN       NOT NULL DEFAULT TRUE,
      approval_status VARCHAR(20)  NOT NULL DEFAULT 'approved',
      last_login_at  TIMESTAMPTZ   DEFAULT NULL,
      created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      updated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'approved'
  `);

  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE
  `);

  await pool.query(`
    UPDATE users
    SET approval_status = COALESCE(approval_status, 'approved')
    WHERE approval_status IS NULL
  `);

  await pool.query(`
    UPDATE users
    SET is_active = COALESCE(is_active, TRUE)
    WHERE is_active IS NULL
  `);

  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'users_role_check'
      ) THEN
        ALTER TABLE users DROP CONSTRAINT users_role_check;
      END IF;
    END $$;
  `);

  await pool.query(`
    ALTER TABLE users
      ADD CONSTRAINT users_role_check
      CHECK (role IN ('admin', 'staff', 'manager', 'director', 'sales_agent'))
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email))
  `);

  await pool.query(`
    CREATE OR REPLACE FUNCTION set_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = NOW();
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
  `);

  await pool.query(`
    DROP TRIGGER IF EXISTS trg_users_updated_at ON users
  `);

  await pool.query(`
    CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at()
  `);
}

async function ensureDirectorAccount() {
  await ensureUserSchema();

  const directorEmail = process.env.DIRECTOR_EMAIL || 'buaydirector@gmail.com';
  const directorPassword = process.env.DIRECTOR_PASSWORD || 'khor2026';

  const passwordHash = await bcrypt.hash(directorPassword, SALT_ROUNDS);
  const normalizedEmail = directorEmail.toLowerCase().trim();

  const existingByEmail = await pool.query(
    'SELECT id FROM users WHERE LOWER(email) = $1',
    [normalizedEmail]
  );

  if (existingByEmail.rows.length > 0) {
    await pool.query(
      `UPDATE users
       SET fullname = $1,
           email = $2,
           password_hash = $3,
           role = 'director',
           is_active = TRUE,
           approval_status = 'approved'
       WHERE id = $4`,
      ['System Director', normalizedEmail, passwordHash, existingByEmail.rows[0].id]
    );
    return;
  }

  const existingDirector = await pool.query(
    'SELECT id FROM users WHERE role = $1 ORDER BY id LIMIT 1',
    ['director']
  );

  if (existingDirector.rows.length > 0) {
    await pool.query(
      `UPDATE users
       SET fullname = $1,
           email = $2,
           password_hash = $3,
           role = 'director',
           is_active = TRUE,
           approval_status = 'approved'
       WHERE id = $4`,
      ['System Director', normalizedEmail, passwordHash, existingDirector.rows[0].id]
    );
    return;
  }

  await pool.query(
    `INSERT INTO users (fullname, email, password_hash, role, is_active, approval_status)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    ['System Director', normalizedEmail, passwordHash, 'director', true, 'approved']
  );
}

async function initializeApp() {
  await ensureDirectorAccount();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Good Choice running on http://localhost:${PORT}`));
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/',       (_req, res) => res.render('home'));
app.get('/login',  (_req, res) => res.render('login',  { error: null, success: null }));

app.get('/signup', (_req, res) => res.render('signup', { error: null, success: null }));

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/signup', async (req, res) => {
  try {
    const { fullname, email, password, role, staffId } = req.body;
    const selectedRole = role === 'admin' ? 'admin' : 'sales_agent';

    if (!fullname || !email || !password) {
      return res.render('signup', { error: 'All fields are required.', success: null });
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = $1',
      [email.toLowerCase().trim()]
    );
    if (existing.rows.length > 0) {
      return res.render('signup', { error: 'An account with that email already exists.', success: null });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    await pool.query(
      `INSERT INTO users (fullname, email, password_hash, role, staff_id, is_active, approval_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [fullname, email.toLowerCase().trim(), passwordHash, selectedRole, staffId || null, false, 'pending']
    );

    return res.render('signup', {
      error: null,
      success: 'Account created successfully. Please wait for director approval before you can sign in.'
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.render('signup', { error: 'Something went wrong. Please try again.', success: null });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.render('login', { error: 'Please fill in all fields.', success: null });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = $1',
      [email.toLowerCase().trim()]
    );
    const user = result.rows[0];

    if (!user) {
      return res.render('login', { error: 'Invalid email or password.', success: null });
    }

    if (user.approval_status === 'pending' || user.is_active === false) {
      return res.render('login', {
        error: 'Your account is waiting for director approval.',
        success: null
      });
    }

    if (user.approval_status === 'rejected') {
      return res.render('login', {
        error: 'Your account was rejected by the director.',
        success: null
      });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid email or password.', success: null });
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
        return res.redirect('/director/owner-check');
      case 'sales_agent':
        return res.redirect('/agent');
      default:
        return res.redirect('/agent');
    }

  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Something went wrong. Please try again.', success: null });
  }
});
app.get('/director/approvals', requireLogin, async (req, res) => {
  try {
    if (req.session.user.role !== 'director') {
      return res.redirect('/dashboard');
    }

    const message = req.query.message ? req.query.message : null;
    const pendingUsersResult = await pool.query(`
      SELECT id, fullname, email, role, staff_id, created_at
      FROM users
      WHERE approval_status = 'pending'
      ORDER BY created_at DESC
    `);

    res.render('director-approvals', {
      user: req.session.user,
      pendingUsers: pendingUsersResult.rows,
      message
    });
  } catch (err) {
    console.error('Approvals page error:', err);
    res.status(500).send('<h2>Approvals error: ' + err.message + '</h2>');
  }
});

app.post('/director/approvals/:id/approve', requireLogin, async (req, res) => {
  try {
    if (req.session.user.role !== 'director') {
      return res.redirect('/dashboard');
    }

    await pool.query(
      `UPDATE users
       SET is_active = TRUE,
           approval_status = 'approved'
       WHERE id = $1`,
      [req.params.id]
    );

    return res.redirect('/director/approvals?message=' + encodeURIComponent('User approved successfully.'));
  } catch (err) {
    console.error('Approve user error:', err);
    return res.redirect('/director/approvals');
  }
});

app.post('/director/approvals/:id/reject', requireLogin, async (req, res) => {
  try {
    if (req.session.user.role !== 'director') {
      return res.redirect('/dashboard');
    }

    await pool.query(
      `UPDATE users
       SET is_active = FALSE,
           approval_status = 'rejected'
       WHERE id = $1`,
      [req.params.id]
    );

    return res.redirect('/director/approvals?message=' + encodeURIComponent('User rejected successfully.'));
  } catch (err) {
    console.error('Reject user error:', err);
    return res.redirect('/director/approvals');
  }
});

async function loadDirectorDashboardData() {
  const hasSalesTable = await pool.query(`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = 'sales'
    ) AS exists
  `);

  const hasProductsTable = await pool.query(`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = 'products'
    ) AS exists
  `);

  const hasUsersTable = await pool.query(`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = 'users'
    ) AS exists
  `);

  if (!hasSalesTable.rows[0].exists) {
    return {
      stats: {
        totalRevenue: 0,
        revenueGrowth: 0,
        totalTransactions: 0,
        txGrowth: 0,
        avgSaleValue: 0,
        activeStaff: hasUsersTable.rows[0].exists ? 0 : 0,
        branchCount: 0,
        lowStockCount: 0,
        grossProfit: 0,
        profitMargin: '0.0'
      },
      salesChart: { labels: ['Jan','Feb','Mar','Apr','May','Jun'], revenue: [0,0,0,0,0,0], target: [45,45,45,45,45,45] },
      branchSales: [],
      inventory: [],
      staffPerformance: [],
      sales: [],
      topProducts: []
    };
  }

  const totalsResult = await pool.query(`
    SELECT
      COALESCE(SUM(total), 0) AS "totalRevenue",
      COUNT(*)::int AS "totalTransactions"
    FROM sales
  `);
  const totals = totalsResult.rows[0];

  const previousRevenueResult = await pool.query(`
    SELECT COALESCE(SUM(total), 0) AS total
    FROM sales
    WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '1 month')
      AND created_at < DATE_TRUNC('month', CURRENT_DATE)
  `);
  const previousRevenue = Number(previousRevenueResult.rows[0].total) || 0;
  const totalRevenue = Number(totals.totalRevenue) || 0;
  const totalTransactions = Number(totals.totalTransactions) || 0;

  const previousTransactionsResult = await pool.query(`
    SELECT COUNT(*)::int AS count
    FROM sales
    WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '1 month')
      AND created_at < DATE_TRUNC('month', CURRENT_DATE)
  `);
  const previousTransactions = Number(previousTransactionsResult.rows[0].count) || 0;

  const revenueGrowth = previousRevenue === 0
    ? (totalRevenue > 0 ? 100 : 0)
    : ((totalRevenue - previousRevenue) / previousRevenue) * 100;

  const txGrowth = previousTransactions === 0
    ? (totalTransactions > 0 ? 100 : 0)
    : ((totalTransactions - previousTransactions) / previousTransactions) * 100;

  const salesChartResult = await pool.query(`
    SELECT
      TO_CHAR(DATE_TRUNC('month', created_at), 'Mon') AS label,
      COALESCE(SUM(total), 0) AS revenue
    FROM sales
    WHERE created_at >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '5 months')
    GROUP BY DATE_TRUNC('month', created_at)
    ORDER BY DATE_TRUNC('month', created_at)
  `);

  const salesChartMap = new Map(salesChartResult.rows.map(row => [row.label, Number(row.revenue)]));
  const salesChart = {
    labels: ['Jan','Feb','Mar','Apr','May','Jun'],
    revenue: [0,0,0,0,0,0],
    target: [45,45,45,45,45,45]
  };

  const monthLabels = ['Jan','Feb','Mar','Apr','May','Jun'];
  monthLabels.forEach((label, index) => {
    if (salesChartMap.has(label)) {
      salesChart.revenue[index] = salesChartMap.get(label);
    }
  });

  let inventory = [];
  if (hasProductsTable.rows[0].exists) {
    const inventoryResult = await pool.query(`
      SELECT
        COALESCE(c.name, 'Uncategorized') AS category,
        COUNT(p.id)::int AS "skuCount",
        COALESCE(SUM(p.stock * p.cost_price), 0) AS "stockValue",
        COUNT(CASE WHEN p.stock <= COALESCE(p.reorder_level, 0) THEN 1 END)::int AS "lowCount"
      FROM products p
      LEFT JOIN categories c ON c.id = p.category_id
      GROUP BY c.name
      ORDER BY c.name
    `);
    inventory = inventoryResult.rows.map(row => ({
      category: row.category,
      skuCount: Number(row.skuCount),
      stockValue: Number(row.stockValue),
      lowCount: Number(row.lowCount)
    }));
  }

  const salesResult = await pool.query(`
    SELECT
      TO_CHAR(s.created_at, 'YYYY-MM-DD HH24:MI') AS date,
      p.name AS "productName",
      s.qty,
      s.price,
      s.total
    FROM sales s
    LEFT JOIN products p ON p.id = s.product_id
    ORDER BY s.created_at DESC
    LIMIT 8
  `);
  const sales = salesResult.rows.map(row => ({
    date: row.date,
    productName: row.productName || 'Unknown product',
    qty: Number(row.qty),
    price: Number(row.price),
    total: Number(row.total)
  }));

  const topProductsResult = await pool.query(`
    SELECT
      p.name,
      SUM(s.qty)::int AS qty,
      SUM(s.total) AS revenue
    FROM sales s
    LEFT JOIN products p ON p.id = s.product_id
    GROUP BY p.name
    ORDER BY revenue DESC
    LIMIT 5
  `);
  const topProducts = topProductsResult.rows.map(row => ({
    name: row.name || 'Unknown product',
    qty: Number(row.qty),
    revenue: Number(row.revenue)
  }));

  let lowStockCount = 0;
  if (hasProductsTable.rows[0].exists) {
    const lowStockResult = await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM products
      WHERE stock <= COALESCE(reorder_level, 0)
    `);
    lowStockCount = Number(lowStockResult.rows[0].count) || 0;
  }

  const activeStaff = hasUsersTable.rows[0].exists
    ? (await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM users
        WHERE is_active = TRUE
          AND role IN ('director', 'admin', 'sales_agent', 'staff', 'manager')
      `)).rows[0].count
    : 0;

  const grossProfit = totalRevenue - (await (async () => {
    if (!hasProductsTable.rows[0].exists) return 0;
    const result = await pool.query(`
      SELECT COALESCE(SUM(s.qty * p.cost_price), 0) AS total
      FROM sales s
      JOIN products p ON p.id = s.product_id
    `);
    return Number(result.rows[0].total) || 0;
  })());

  const stats = {
    totalRevenue,
    revenueGrowth: Number(revenueGrowth.toFixed(1)),
    totalTransactions,
    txGrowth: Number(txGrowth.toFixed(1)),
    avgSaleValue: totalTransactions > 0 ? Number((totalRevenue / totalTransactions).toFixed(0)) : 0,
    activeStaff: Number(activeStaff) || 0,
    branchCount: 1,
    lowStockCount,
    grossProfit,
    profitMargin: totalRevenue > 0 ? Number(((grossProfit / totalRevenue) * 100).toFixed(1)).toString() : '0.0'
  };

  const branchSales = [];
  const staffPerformance = [];

  return { stats, salesChart, branchSales, inventory, staffPerformance, sales, topProducts };
}

app.get('/director/owner-check', requireLogin, (req, res) => {
  if (req.session.user.role !== 'director') {
    return res.redirect('/dashboard');
  }

  res.render('director-owner-check', {
    user: req.session.user,
    error: null
  });
});

app.post('/director/owner-check', requireLogin, (req, res) => {
  if (req.session.user.role !== 'director') {
    return res.redirect('/dashboard');
  }

  const answer = req.body.ownerDecision;
  if (answer === 'yes') {
    return res.redirect('/director/change-password');
  }

  return res.redirect('/dashboard');
});

app.get('/director/change-password', requireLogin, (req, res) => {
  if (req.session.user.role !== 'director') {
    return res.redirect('/dashboard');
  }

  res.render('director-change-password', {
    user: req.session.user,
    error: null,
    success: null
  });
});

app.post('/director/change-password', requireLogin, async (req, res) => {
  if (req.session.user.role !== 'director') {
    return res.redirect('/dashboard');
  }

  const { newPassword, confirmPassword } = req.body;

  if (!newPassword || !confirmPassword) {
    return res.render('director-change-password', {
      user: req.session.user,
      error: 'Please fill in both password fields.',
      success: null
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render('director-change-password', {
      user: req.session.user,
      error: 'Passwords do not match.',
      success: null
    });
  }

  const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  await pool.query(
    'UPDATE users SET password_hash = $1 WHERE id = $2',
    [passwordHash, req.session.user.id]
  );

  return res.render('director-change-password', {
    user: req.session.user,
    error: null,
    success: 'Password updated successfully. You can continue to the dashboard.'
  });
});

app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const data = await loadDirectorDashboardData();

    res.render('dashboard-director', {
      user,
      ...data
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

initializeApp().catch(err => {
  console.error('App initialization failed:', err);
  process.exit(1);
});
