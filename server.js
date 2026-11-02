'use strict';
/* ============================================================
   server.js  —  পুরো backend এক ফাইলে। কোনো npm install লাগে না।
   (Node 22.13+ এর built-in sqlite ও crypto ব্যবহার করা হয়েছে)
   ============================================================ */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const scrypt = promisify(crypto.scrypt);
const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const SESSION_DAYS = 30;
const MAX_BODY = 30 * 1024 * 1024; // ছবিসহ ডেটা রাখার জন্য 30MB

/* ---------- Database ---------- */
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new DatabaseSync(path.join(__dirname, 'data', 'app.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    salt TEXT NOT NULL,
    hash TEXT NOT NULL,
    created INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions(
    token TEXT PRIMARY KEY,          -- token এর sha256 (আসল token শুধু cookie তে)
    user_id INTEGER NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS app_data(
    user_id INTEGER PRIMARY KEY,
    json TEXT NOT NULL,
    updated INTEGER NOT NULL
  );
`);

const q = {
  findUser: db.prepare('SELECT * FROM users WHERE username = ?'),
  addUser: db.prepare('INSERT INTO users(username,salt,hash,created) VALUES(?,?,?,?)'),
  addSession: db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)'),
  getSession: db.prepare(
    'SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?'
  ),
  delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  cleanSessions: db.prepare('DELETE FROM sessions WHERE expires <= ?'),
  getData: db.prepare('SELECT json, updated FROM app_data WHERE user_id = ?'),
  putData: db.prepare(
    `INSERT INTO app_data(user_id,json,updated) VALUES(?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET json = excluded.json, updated = excluded.updated`
  ),
};

/* ---------- Helpers ---------- */
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function hashPassword(password, salt) {
  return (await scrypt(password, salt, 64)).toString('hex');
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function getUser(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  return q.getSession.get(sha(token), Date.now()) || null;
}

function sendJSON(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('too_large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function readJSON(req) {
  if (!(req.headers['content-type'] || '').includes('application/json')) throw new Error('bad_type');
  return JSON.parse((await readBody(req)) || '{}');
}

function setSessionCookie(res, token, maxAgeSec) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${secure}`;
}

async function startSession(res, userId, extra) {
  const token = crypto.randomBytes(32).toString('hex');
  q.addSession.run(sha(token), userId, Date.now() + SESSION_DAYS * 864e5);
  return setSessionCookie(res, token, SESSION_DAYS * 86400);
}

/* সহজ rate limit: একই IP থেকে ১৫ মিনিটে সর্বোচ্চ ১০ বার login/register চেষ্টা */
const attempts = new Map();
function tooMany(ip) {
  const now = Date.now();
  const a = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  a.push(now);
  attempts.set(ip, a);
  return a.length > 10;
}

/* ---------- API ---------- */
async function handleAPI(req, res, url) {
  const route = req.method + ' ' + url.pathname;
  const ip = req.socket.remoteAddress || 'x';

  try {
    if (route === 'POST /api/register') {
      if (tooMany(ip)) return sendJSON(res, 429, { error: 'অনেকবার চেষ্টা করেছেন, একটু পরে আবার চেষ্টা করুন' });
      const { username = '', password = '' } = await readJSON(req);
      const u = String(username).trim();
      if (!/^[A-Za-z0-9_.]{3,20}$/.test(u))
        return sendJSON(res, 400, { error: 'ইউজারনেম ৩-২০ অক্ষরের হতে হবে (ইংরেজি অক্ষর, সংখ্যা, _ বা .)' });
      if (String(password).length < 6 || String(password).length > 100)
        return sendJSON(res, 400, { error: 'পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে' });
      if (q.findUser.get(u)) return sendJSON(res, 409, { error: 'এই ইউজারনেম আগে থেকেই আছে' });

      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await hashPassword(String(password), salt);
      const info = q.addUser.run(u, salt, hash, Date.now());
      const cookie = await startSession(res, Number(info.lastInsertRowid));
      return sendJSON(res, 201, { ok: true, username: u }, { 'Set-Cookie': cookie });
    }

    if (route === 'POST /api/login') {
      if (tooMany(ip)) return sendJSON(res, 429, { error: 'অনেকবার চেষ্টা করেছেন, একটু পরে আবার চেষ্টা করুন' });
      const { username = '', password = '' } = await readJSON(req);
      const user = q.findUser.get(String(username).trim());
      // user না থাকলেও hash হিসাব করি, যাতে সময় দেখে কেউ বুঝতে না পারে
      const salt = user ? user.salt : 'x'.repeat(32);
      const hash = await hashPassword(String(password), salt);
      const ok =
        user &&
        crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.hash, 'hex'));
      if (!ok) return sendJSON(res, 401, { error: 'ইউজারনেম বা পাসওয়ার্ড ভুল' });
      q.cleanSessions.run(Date.now());
      const cookie = await startSession(res, user.id);
      return sendJSON(res, 200, { ok: true, username: user.username }, { 'Set-Cookie': cookie });
    }

    if (route === 'POST /api/logout') {
      const token = parseCookies(req).sid;
      if (token) q.delSession.run(sha(token));
      return sendJSON(res, 200, { ok: true }, { 'Set-Cookie': setSessionCookie(res, '', 0) });
    }

    // নিচের সব route এ login দরকার
    const user = getUser(req);
    if (!user) return sendJSON(res, 401, { error: 'login করুন' });

    if (route === 'GET /api/me') return sendJSON(res, 200, { username: user.username });

    if (route === 'GET /api/data') {
      const row = q.getData.get(user.id);
      return sendJSON(res, 200, { data: row ? JSON.parse(row.json) : null, updated: row ? row.updated : null });
    }

    // sendBeacon শুধু POST পাঠায়, তাই POST ও PUT দুটোই চলবে
    if (route === 'PUT /api/data' || route === 'POST /api/data') {
      const body = await readJSON(req);
      if (!body || typeof body.data !== 'object') return sendJSON(res, 400, { error: 'ভুল ডেটা' });
      q.putData.run(user.id, JSON.stringify(body.data), Date.now());
      return sendJSON(res, 200, { ok: true });
    }

    return sendJSON(res, 404, { error: 'not found' });
  } catch (e) {
    if (e.message === 'too_large') return sendJSON(res, 413, { error: 'ডেটা অনেক বড়' });
    if (e.message === 'bad_type' || e instanceof SyntaxError) return sendJSON(res, 400, { error: 'ভুল অনুরোধ' });
    console.error(e);
    return sendJSON(res, 500, { error: 'সার্ভারে সমস্যা হয়েছে' });
  }
}

/* ---------- Static files ---------- */
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function redirect(res, to) {
  res.writeHead(302, { Location: to, 'Cache-Control': 'no-store' });
  res.end();
}

function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);

  if (p === '/') return redirect(res, getUser(req) ? '/app.html' : '/login.html');
  // মূল অ্যাপ শুধু login করা ব্যবহারকারীর জন্য
  if (p === '/app.html' && !getUser(req)) return redirect(res, '/login.html');
  // login করা থাকলে login পেজ আর দেখাবো না
  if (p === '/login.html' && getUser(req)) return redirect(res, '/app.html');

  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC + path.sep)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(file, (err, buf) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('পেজ পাওয়া যায়নি');
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': p === '/app.html' ? 'no-store' : 'no-cache',
    });
    res.end(buf);
  });
}

/* ---------- Server ---------- */
http
  .createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) return handleAPI(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405);
      return res.end();
    }
    serveStatic(req, res, url);
  })
  .listen(PORT, () => console.log(`✅ চালু হয়েছে: http://localhost:${PORT}`));
