const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const STATIC_DIR = path.resolve(process.env.STATIC_DIR || path.join(__dirname, 'public'));
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const DB_FILE = path.join(DATA_DIR, 'vip-db.json');
const GEMINI_API_KEY = String(process.env.GEMINI_API_KEY || '').trim();
const DEFAULT_GEMINI_MODEL = String(process.env.DEFAULT_GEMINI_MODEL || 'gemini-2.5-flash').trim();
const ALLOWED_MODELS = new Set(
  String(process.env.ALLOWED_GEMINI_MODELS || 'gemini-2.5-flash,gemini-2.5-flash-lite,gemini-2.0-flash')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);
const SESSION_TTL_DAYS = Math.max(1, Number(process.env.SESSION_TTL_DAYS || 90));
const JSON_LIMIT = String(process.env.JSON_LIMIT || '35mb');
const RATE_WINDOW_MS = Math.max(1000, Number(process.env.RATE_WINDOW_MS || 10 * 60 * 1000));
const RATE_LIMIT = Math.max(1, Number(process.env.RATE_LIMIT || 40));
const rateBuckets = new Map();

function ensureDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ version: 1, codes: [], sessions: [] }, null, 2));
  }
}

function loadDb() {
  ensureDb();
  const raw = fs.readFileSync(DB_FILE, 'utf8');
  const db = JSON.parse(raw || '{}');
  if (!Array.isArray(db.codes)) db.codes = [];
  if (!Array.isArray(db.sessions)) db.sessions = [];
  if (!db.version) db.version = 1;
  return db;
}

function saveDb(db) {
  ensureDb();
  const tempFile = DB_FILE + '.tmp';
  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
  fs.renameSync(tempFile, DB_FILE);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

function addDays(days) {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString();
}

function minExpiry(a, b) {
  if (!a) return b || null;
  if (!b) return a || null;
  return new Date(a).getTime() <= new Date(b).getTime() ? a : b;
}

function normalizeCode(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function sanitizeDeviceId(value) {
  return String(value || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80);
}

function getBearerToken(req) {
  const auth = String(req.headers.authorization || '');
  if (!/^Bearer\s+/i.test(auth)) return '';
  return auth.replace(/^Bearer\s+/i, '').trim();
}

function cleanupDb(db) {
  const now = Date.now();
  db.sessions = db.sessions.filter(session => {
    if (session.revokedAt) return false;
    if (session.expiresAt && new Date(session.expiresAt).getTime() <= now) return false;
    return true;
  });
}

function validateSession(req, db) {
  cleanupDb(db);
  const token = getBearerToken(req);
  const deviceId = sanitizeDeviceId(req.headers['x-device-id']);
  if (!token) return { ok: false, status: 401, message: 'VIP session is missing.' };

  const session = db.sessions.find(s => s.tokenHash === sha256(token));
  if (!session) return { ok: false, status: 401, message: 'VIP session not found or expired.' };
  if (session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now()) {
    return { ok: false, status: 401, message: 'VIP session expired.' };
  }
  if (deviceId && session.deviceId && deviceId !== session.deviceId) {
    return { ok: false, status: 401, message: 'VIP session does not match this device.' };
  }

  const code = db.codes.find(c => c.id === session.codeId);
  if (!code) return { ok: false, status: 403, message: 'VIP code no longer exists.' };
  if (code.revokedAt) return { ok: false, status: 403, message: 'VIP code was revoked.' };
  if (code.expiresAt && new Date(code.expiresAt).getTime() <= Date.now()) {
    return { ok: false, status: 403, message: 'VIP code expired.' };
  }

  session.lastSeenAt = nowIso();
  return { ok: true, session, code };
}

function takeRateSlot(key) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + RATE_WINDOW_MS };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  return {
    allowed: bucket.count <= RATE_LIMIT,
    remaining: Math.max(0, RATE_LIMIT - bucket.count),
    resetAt: bucket.resetAt
  };
}

app.disable('x-powered-by');
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store');
  }
  next();
});
app.use(express.json({ limit: JSON_LIMIT }));
app.use(express.static(STATIC_DIR, { extensions: ['html'] }));

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    keyConfigured: Boolean(GEMINI_API_KEY),
    defaultModel: DEFAULT_GEMINI_MODEL,
    time: nowIso()
  });
});

app.post('/api/vip/redeem', (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: { message: 'Server Gemini key is not configured yet.' } });
  }

  const codeInput = normalizeCode(req.body.code);
  const deviceId = sanitizeDeviceId(req.body.deviceId);

  if (!codeInput || codeInput.length < 6) {
    return res.status(400).json({ error: { message: 'Activation code is too short.' } });
  }
  if (!deviceId) {
    return res.status(400).json({ error: { message: 'Device ID is required.' } });
  }

  const db = loadDb();
  cleanupDb(db);

  const code = db.codes.find(item => item.codeHash === sha256(codeInput));
  if (!code || code.revokedAt) {
    saveDb(db);
    return res.status(403).json({ error: { message: 'Invalid activation code.' } });
  }
  if (code.expiresAt && new Date(code.expiresAt).getTime() <= Date.now()) {
    saveDb(db);
    return res.status(403).json({ error: { message: 'Activation code has expired.' } });
  }

  if (!Array.isArray(code.redemptions)) code.redemptions = [];
  let redemption = code.redemptions.find(item => item.deviceId === deviceId);
  const usedDevices = new Set(code.redemptions.map(item => item.deviceId).filter(Boolean));
  const maxUses = Math.max(1, Number(code.maxUses || 1));

  if (!redemption && usedDevices.size >= maxUses) {
    saveDb(db);
    return res.status(403).json({ error: { message: 'This code reached its device limit.' } });
  }

  if (!redemption) {
    redemption = { deviceId, firstRedeemedAt: nowIso(), lastRedeemedAt: nowIso() };
    code.redemptions.push(redemption);
  } else {
    redemption.lastRedeemedAt = nowIso();
  }

  db.sessions = db.sessions.filter(session => !(session.codeId === code.id && session.deviceId === deviceId));
  const rawToken = crypto.randomBytes(32).toString('base64url');
  const expiresAt = minExpiry(addDays(SESSION_TTL_DAYS), code.expiresAt || null);

  db.sessions.push({
    id: crypto.randomUUID(),
    tokenHash: sha256(rawToken),
    deviceId,
    codeId: code.id,
    label: code.label || code.codePreview || 'VIP',
    createdAt: nowIso(),
    lastSeenAt: nowIso(),
    expiresAt,
    revokedAt: null
  });

  saveDb(db);
  res.json({
    ok: true,
    token: rawToken,
    label: code.label || code.codePreview || 'VIP',
    expiresAt,
    model: DEFAULT_GEMINI_MODEL
  });
});

app.get('/api/vip/status', (req, res) => {
  const db = loadDb();
  const auth = validateSession(req, db);
  if (!auth.ok) {
    saveDb(db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }
  saveDb(db);
  res.json({
    ok: true,
    label: auth.code.label || auth.code.codePreview || 'VIP',
    expiresAt: auth.session.expiresAt || null,
    model: DEFAULT_GEMINI_MODEL,
    redeemedDevices: Array.isArray(auth.code.redemptions) ? auth.code.redemptions.length : 0
  });
});

app.post('/api/vip/logout', (req, res) => {
  const db = loadDb();
  const token = getBearerToken(req);
  if (!token) {
    return res.json({ ok: true });
  }
  const tokenHash = sha256(token);
  db.sessions = db.sessions.filter(session => session.tokenHash !== tokenHash);
  saveDb(db);
  res.json({ ok: true });
});

app.post('/api/gemini/generate', async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: { message: 'Server Gemini key is not configured yet.' } });
  }

  const db = loadDb();
  const auth = validateSession(req, db);
  if (!auth.ok) {
    saveDb(db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }

  const rate = takeRateSlot(auth.session.id || auth.session.tokenHash);
  res.setHeader('X-RateLimit-Remaining', String(rate.remaining));
  res.setHeader('X-RateLimit-Reset', String(rate.resetAt));
  if (!rate.allowed) {
    saveDb(db);
    return res.status(429).json({ error: { message: 'VIP request limit reached. Try again later.' } });
  }

  const requestedModel = String(req.body.model || '').trim();
  const model = ALLOWED_MODELS.has(requestedModel) ? requestedModel : DEFAULT_GEMINI_MODEL;
  const payload = req.body.payload;

  if (!payload || typeof payload !== 'object') {
    saveDb(db);
    return res.status(400).json({ error: { message: 'Invalid Gemini payload.' } });
  }

  try {
    const upstream = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': GEMINI_API_KEY
        },
        body: JSON.stringify(payload)
      }
    );

    const text = await upstream.text();
    saveDb(db);
    res.status(upstream.status);
    res.type(upstream.headers.get('content-type') || 'application/json');
    res.send(text);
  } catch (error) {
    saveDb(db);
    res.status(502).json({ error: { message: `Gemini proxy failed: ${error.message}` } });
  }
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

app.use((error, _req, res, _next) => {
  if (error && error.type === 'entity.too.large') {
    return res.status(413).json({ error: { message: 'Request payload is too large.' } });
  }
  console.error('Server error:', error);
  res.status(500).json({ error: { message: 'Internal server error.' } });
});

app.listen(PORT, () => {
  console.log(`Daly Alpha VIP server running on http://localhost:${PORT}`);
  console.log(`Static dir: ${STATIC_DIR}`);
  console.log(`DB file   : ${DB_FILE}`);
});
