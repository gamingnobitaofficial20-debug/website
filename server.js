const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { rateLimit } = require('express-rate-limit');

const app = express();
const port = Number(process.env.PORT || 4173);
const production = process.env.NODE_ENV === 'production';
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'northstar.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS admin_users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_login_at TEXT);
CREATE TABLE IF NOT EXISTS admin_sessions (id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'active', description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, sku TEXT UNIQUE NOT NULL, category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL, price REAL NOT NULL CHECK(price >= 0), sale_price REAL CHECK(sale_price IS NULL OR sale_price >= 0), cost_price REAL CHECK(cost_price IS NULL OR cost_price >= 0), stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0), low_stock_threshold INTEGER NOT NULL DEFAULT 5, status TEXT NOT NULL DEFAULT 'draft', featured INTEGER NOT NULL DEFAULT 0, description TEXT NOT NULL DEFAULT '', image_url TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'active', total_spent REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, order_number TEXT UNIQUE NOT NULL, customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL, status TEXT NOT NULL DEFAULT 'pending', payment_status TEXT NOT NULL DEFAULT 'pending', total REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, notes TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS order_items (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE SET NULL, quantity INTEGER NOT NULL, unit_price REAL NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL, action TEXT NOT NULL, record_type TEXT, record_id INTEGER, ip TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(status);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
`);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) { return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (error, key) => error ? reject(error) : resolve(`${salt}:${key.toString('hex')}`))); }
function verifyPassword(password, stored) { const [salt, key] = stored.split(':'); return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (error, derived) => { if (error) return reject(error); resolve(crypto.timingSafeEqual(Buffer.from(key, 'hex'), derived)); })); }
function randomToken() { return crypto.randomBytes(32).toString('base64url'); }
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function audit(user, action, type = null, recordId = null, req = null) { db.prepare('INSERT INTO activity_logs (user_id, action, record_type, record_id, ip) VALUES (?, ?, ?, ?, ?)').run(user?.id || null, action, type, recordId, req?.ip || null); }
function seed() {
  if (!db.prepare('SELECT id FROM admin_users LIMIT 1').get()) {
    const email = process.env.ADMIN_EMAIL || 'admin@northstar.local'; const password = process.env.ADMIN_PASSWORD || randomToken();
    hashPassword(password).then(passwordHash => { db.prepare('INSERT INTO admin_users (email, password_hash, role) VALUES (?, ?, ?)').run(email, passwordHash, 'super_admin'); console.log(`Admin account bootstrapped for ${email}. Password: ${password}`); console.log('Set ADMIN_EMAIL and ADMIN_PASSWORD before production deployment.'); });
  }
  if (!db.prepare('SELECT COUNT(*) AS count FROM categories').get().count) {
    const addCategory = db.prepare('INSERT INTO categories (name, slug, description) VALUES (?, ?, ?)'); ['Home', 'Carry', 'Objects'].forEach(name => addCategory.run(name, name.toLowerCase(), `Northstar ${name.toLowerCase()} collection`));
    const addProduct = db.prepare('INSERT INTO products (name, sku, category_id, price, stock, status, featured, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    addProduct.run('Mori Ceramic Mug', 'NS-MUG-001', 1, 38, 42, 'published', 1, 'https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?auto=format&fit=crop&w=700&q=80'); addProduct.run('Field Notes Tote', 'NS-TOTE-001', 2, 64, 8, 'published', 1, 'https://images.unsplash.com/photo-1544816155-12df9643f363?auto=format&fit=crop&w=700&q=80'); addProduct.run('Arc Candle Holder', 'NS-ARC-001', 3, 42, 0, 'published', 0, 'https://images.unsplash.com/photo-1602874801006-e26d8bfe35d3?auto=format&fit=crop&w=700&q=80'); addProduct.run('Stillness Throw', 'NS-THROW-001', 1, 110, 17, 'draft', 0, 'https://images.unsplash.com/photo-1584100936595-c0654b55a2e2?auto=format&fit=crop&w=700&q=80');
  }
}
seed();

app.set('trust proxy', 1); app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false })); app.use(express.json({ limit: '1mb' })); app.use(express.urlencoded({ extended: false, limit: '20kb' })); app.use(cookieParser());
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many login attempts. Try again later.' } });
function requireAuth(req, res, next) { const token = req.cookies.northstar_admin; const session = token && db.prepare('SELECT s.*, u.email, u.role, u.active FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?').get(tokenHash(token), Date.now()); if (!session || !session.active) return req.path.startsWith('/api/') ? res.status(401).json({ error: 'Authentication required.' }) : res.redirect('/admin/login'); req.admin = { id: session.user_id, email: session.email, role: session.role, sessionId: session.id, csrfToken: session.csrf_token }; next(); }
function requireCsrf(req, res, next) { if (!req.admin || req.get('x-csrf-token') !== req.admin.csrfToken) return res.status(403).json({ error: 'Invalid security token.' }); next(); }
function requireRole(...roles) { return (req, res, next) => roles.includes(req.admin.role) ? next() : res.status(403).json({ error: 'Insufficient permissions.' }); }
function cleanText(value, max = 5000) { return String(value ?? '').trim().slice(0, max); }
function adminFile(file) { return path.join(__dirname, 'admin', file); }

app.get('/admin', (req, res) => res.redirect(req.cookies.northstar_admin ? '/admin/dashboard' : '/admin/login'));
app.get('/admin/login', (req, res) => res.sendFile(adminFile('login.html')));
app.get('/admin/dashboard', requireAuth, (req, res) => res.sendFile(adminFile('dashboard.html')));
app.use('/admin/assets', express.static(path.join(__dirname, 'admin', 'assets'), { maxAge: production ? '1d' : 0 }));

app.post('/api/admin/login', loginLimiter, async (req, res) => { const email = cleanText(req.body.email, 200).toLowerCase(); const password = String(req.body.password || ''); const user = db.prepare('SELECT * FROM admin_users WHERE email = ?').get(email); const valid = user && user.active && password.length <= 200 && await verifyPassword(password, user.password_hash).catch(() => false); if (!valid) return res.status(401).json({ error: 'Invalid email or password.' }); db.prepare('DELETE FROM admin_sessions WHERE expires_at <= ? OR user_id = ?').run(Date.now(), user.id); const token = randomToken(); const csrfToken = randomToken(); db.prepare('INSERT INTO admin_sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)').run(tokenHash(token), user.id, csrfToken, Date.now() + 8 * 60 * 60 * 1000); db.prepare('UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id); audit(user, 'login', null, null, req); res.cookie('northstar_admin', token, { httpOnly: true, secure: production, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000, path: '/' }); res.json({ ok: true, csrfToken, redirect: '/admin/dashboard' }); });
app.post('/api/admin/logout', requireAuth, requireCsrf, (req, res) => { audit(req.admin, 'logout', null, null, req); db.prepare('DELETE FROM admin_sessions WHERE id = ?').run(req.admin.sessionId); res.clearCookie('northstar_admin', { httpOnly: true, secure: production, sameSite: 'lax', path: '/' }); res.json({ ok: true }); });
app.get('/api/admin/session', requireAuth, (req, res) => res.json({ user: { email: req.admin.email, role: req.admin.role }, csrfToken: req.admin.csrfToken }));

app.get('/api/admin/dashboard', requireAuth, (req, res) => { const totals = db.prepare(`SELECT (SELECT COALESCE(SUM(total),0) FROM orders WHERE status != 'cancelled') AS sales, (SELECT COUNT(*) FROM orders) AS orders, (SELECT COUNT(*) FROM customers) AS customers, (SELECT COUNT(*) FROM products) AS products, (SELECT COUNT(*) FROM products WHERE stock > 0 AND stock <= low_stock_threshold) AS lowStock, (SELECT COUNT(*) FROM products WHERE stock = 0) AS outOfStock, (SELECT COUNT(*) FROM categories) AS categories`).get(); const statuses = db.prepare('SELECT status, COUNT(*) AS count FROM orders GROUP BY status').all(); const products = db.prepare('SELECT p.*, c.name AS category FROM products p LEFT JOIN categories c ON c.id = p.category_id ORDER BY p.updated_at DESC LIMIT 100').all(); const orders = db.prepare('SELECT o.*, c.name AS customer FROM orders o LEFT JOIN customers c ON c.id = o.customer_id ORDER BY o.created_at DESC LIMIT 10').all(); const activity = db.prepare('SELECT action, record_type, record_id, created_at FROM activity_logs ORDER BY created_at DESC LIMIT 10').all(); res.json({ totals, statuses, products, orders, activity }); });
app.get('/api/admin/products', requireAuth, (req, res) => res.json({ products: db.prepare('SELECT p.*, c.name AS category FROM products p LEFT JOIN categories c ON c.id = p.category_id ORDER BY p.created_at DESC').all(), categories: db.prepare('SELECT * FROM categories ORDER BY name').all() }));
app.post('/api/admin/products', requireAuth, requireCsrf, requireRole('super_admin', 'admin', 'product_manager'), (req, res) => { const data = req.body; const name = cleanText(data.name, 160); const sku = cleanText(data.sku, 80).toUpperCase(); if (!name || !sku || !Number.isFinite(Number(data.price))) return res.status(400).json({ error: 'Name, SKU and a valid price are required.' }); try { const result = db.prepare('INSERT INTO products (name, sku, category_id, price, sale_price, cost_price, stock, low_stock_threshold, status, featured, description, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(name, sku, data.categoryId || null, Number(data.price), data.salePrice ? Number(data.salePrice) : null, data.costPrice ? Number(data.costPrice) : null, Math.max(0, Number(data.stock) || 0), Math.max(0, Number(data.lowStockThreshold) || 5), data.status === 'published' ? 'published' : 'draft', data.featured ? 1 : 0, cleanText(data.description), cleanText(data.imageUrl, 500)); audit(req.admin, 'product_created', 'product', result.lastInsertRowid, req); res.status(201).json({ id: result.lastInsertRowid }); } catch (error) { res.status(400).json({ error: error.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'SKU already exists.' : 'Unable to create product.' }); } });
app.patch('/api/admin/products/:id', requireAuth, requireCsrf, requireRole('super_admin', 'admin', 'product_manager'), (req, res) => { const id = Number(req.params.id); const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id); if (!existing) return res.status(404).json({ error: 'Product not found.' }); const next = { ...existing, ...req.body }; db.prepare('UPDATE products SET name=?, sku=?, category_id=?, price=?, sale_price=?, cost_price=?, stock=?, low_stock_threshold=?, status=?, featured=?, description=?, image_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(cleanText(next.name,160), cleanText(next.sku,80).toUpperCase(), next.category_id || null, Number(next.price), next.sale_price ? Number(next.sale_price) : null, next.cost_price ? Number(next.cost_price) : null, Math.max(0, Number(next.stock)), Math.max(0, Number(next.low_stock_threshold)), next.status === 'published' ? 'published' : 'draft', next.featured ? 1 : 0, cleanText(next.description), cleanText(next.image_url,500), id); audit(req.admin, 'product_updated', 'product', id, req); res.json({ ok: true }); });
app.delete('/api/admin/products/:id', requireAuth, requireCsrf, requireRole('super_admin', 'admin', 'product_manager'), (req, res) => { const id = Number(req.params.id); const result = db.prepare('DELETE FROM products WHERE id = ?').run(id); if (!result.changes) return res.status(404).json({ error: 'Product not found.' }); audit(req.admin, 'product_deleted', 'product', id, req); res.json({ ok: true }); });
app.get('/api/admin/orders', requireAuth, (req, res) => res.json({ orders: db.prepare('SELECT o.*, c.name AS customer, c.email FROM orders o LEFT JOIN customers c ON c.id = o.customer_id ORDER BY o.created_at DESC').all() }));
app.patch('/api/admin/orders/:id', requireAuth, requireCsrf, requireRole('super_admin', 'admin', 'order_manager'), (req, res) => { const statuses = ['pending','confirmed','processing','packed','shipped','out_for_delivery','delivered','cancelled','returned','refunded']; if (!statuses.includes(req.body.status)) return res.status(400).json({ error: 'Invalid order status.' }); const result = db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(req.body.status, Number(req.params.id)); if (!result.changes) return res.status(404).json({ error: 'Order not found.' }); audit(req.admin, 'order_status_changed', 'order', Number(req.params.id), req); res.json({ ok: true }); });
app.get('/api/admin/customers', requireAuth, (req, res) => res.json({ customers: db.prepare('SELECT id, name, email, status, total_spent, created_at FROM customers ORDER BY created_at DESC').all() }));
app.get('/api/admin/categories', requireAuth, (req, res) => res.json({ categories: db.prepare('SELECT * FROM categories ORDER BY name').all() }));
app.get('/api/admin/settings', requireAuth, requireRole('super_admin', 'admin'), (req, res) => res.json({ settings: db.prepare('SELECT key, value FROM settings').all() }));
app.put('/api/admin/settings', requireAuth, requireCsrf, requireRole('super_admin', 'admin'), (req, res) => {
  const save = db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  const updateSettings = db.transaction(entries => {
    entries.forEach(([key, value]) => save.run(cleanText(key, 80), cleanText(value, 1000)));
  });
  updateSettings(Object.entries(req.body));
  audit(req.admin, 'settings_updated', 'settings', null, req);
  res.json({ ok: true });
});
app.get('/api/admin/activity', requireAuth, (req, res) => res.json({ activity: db.prepare('SELECT a.*, u.email FROM activity_logs a LEFT JOIN admin_users u ON u.id = a.user_id ORDER BY a.created_at DESC LIMIT 100').all() }));

app.use(express.static(__dirname, { index: 'index.html', dotfiles: 'deny', maxAge: production ? '1d' : 0 }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Internal server error.' }); });
app.listen(port, () => console.log(`Northstar server listening on http://localhost:${port}`));