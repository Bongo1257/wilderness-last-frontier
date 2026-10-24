const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('neon.tech') ? { rejectUnauthorized: false } : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
const PORT = process.env.PORT || 10000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://wilderness-last-frontier.onrender.com';

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origin === FRONTEND_ORIGIN || /^https:\/\/[a-z0-9-]+\.onrender\.com$/i.test(origin) || /^http:\/\/localhost(:\d+)?$/i.test(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '2mb' }));

const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('base64url');
const emailOk = email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;

async function auth(req, res, next) {
  try {
    const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!raw || raw.length > 200) return res.status(401).json({ error: 'Please sign in.' });
    const result = await pool.query(
      'SELECT u.id, u.email, u.username FROM game_sessions s JOIN game_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at > now()',
      [hashToken(raw)]
    );
    if (!result.rowCount) return res.status(401).json({ error: 'Your session expired. Please sign in again.' });
    req.user = result.rows[0];
    req.rawTokenHash = hashToken(raw);
    next();
  } catch (e) { next(e); }
}

app.get('/api/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, app: 'Wilderness Last Frontier API' }); }
  catch (_) { res.status(503).json({ ok: false }); }
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const username = String(req.body.username || '').trim().slice(0, 32);
    const password = String(req.body.password || '');
    if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (username.length < 2) return res.status(400).json({ error: 'Username must be at least 2 characters.' });
    if (password.length < 10 || password.length > 200) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
    const id = crypto.randomUUID();
    const passHash = await bcrypt.hash(password, 12);
    let user;
    try {
      const result = await pool.query('INSERT INTO game_users(id,email,username,password_hash) VALUES($1,$2,$3,$4) RETURNING id,email,username', [id,email,username,passHash]);
      user = result.rows[0];
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'That email address already has an account. Try signing in.' });
      throw e;
    }
    const token = newToken();
    await pool.query("INSERT INTO game_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')", [hashToken(token), user.id]);
    res.status(201).json({ token, user });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const result = await pool.query('SELECT id,email,username,password_hash FROM game_users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    const token = newToken();
    await pool.query("INSERT INTO game_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')", [hashToken(token), user.id]);
    res.json({ token, user: { id: user.id, email: user.email, username: user.username } });
  } catch (e) { next(e); }
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));
app.post('/api/auth/logout', auth, async (req, res, next) => {
  try { await pool.query('DELETE FROM game_sessions WHERE token_hash=$1', [req.rawTokenHash]); res.json({ ok: true }); }
  catch (e) { next(e); }
});

app.get('/api/worlds', auth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT world_id,name,seed,created_at,updated_at,state FROM game_world_saves WHERE user_id=$1 ORDER BY updated_at DESC', [req.user.id]);
    res.json({ worlds: result.rows.map(w => ({ id:w.world_id, name:w.name, seed:w.seed, created:w.created_at, updated:w.updated_at, state:w.state })) });
  } catch (e) { next(e); }
});

app.put('/api/worlds/:id', auth, async (req, res, next) => {
  try {
    const id = String(req.params.id || '');
    const name = String(req.body.name || '').trim().slice(0, 32);
    const seed = Number(req.body.seed);
    const state = req.body.state;
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id) || !name || !Number.isFinite(seed) || !state || typeof state !== 'object' || Array.isArray(state)) return res.status(400).json({ error: 'Invalid world save.' });
    const count = await pool.query('SELECT count(*)::int AS count FROM game_world_saves WHERE user_id=$1', [req.user.id]);
    const existing = await pool.query('SELECT 1 FROM game_world_saves WHERE user_id=$1 AND world_id=$2', [req.user.id,id]);
    if (!existing.rowCount && count.rows[0].count >= 30) return res.status(400).json({ error: 'Account limit reached: maximum 30 worlds.' });
    await pool.query(
      'INSERT INTO game_world_saves(user_id,world_id,name,seed,state,updated_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(user_id,world_id) DO UPDATE SET name=EXCLUDED.name,seed=EXCLUDED.seed,state=EXCLUDED.state,updated_at=now()',
      [req.user.id,id,name,seed,JSON.stringify(state)]
    );
    res.json({ ok: true, id, updated: new Date().toISOString() });
  } catch (e) { next(e); }
});

app.delete('/api/worlds/:id', auth, async (req, res, next) => {
  try {
    await pool.query('DELETE FROM game_world_saves WHERE user_id=$1 AND world_id=$2', [req.user.id,String(req.params.id)]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.use((err, req, res, next) => {
  console.error('API error:', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});
app.listen(PORT, () => console.log('Wilderness API listening on ' + PORT));
