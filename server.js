const express = require('express');
const path = require('path');
const crypto = require('crypto');
try { require('dotenv').config(); } catch (_error) {}

const {
  loadDb,
  saveDb,
  sha256,
  nowIso,
  addDays,
  addHours,
  minExpiry,
  normalizeCode,
  sanitizeDeviceId,
  cleanupDb,
  createCode,
  listCodes,
  revokeCode,
  removeDeviceFromCode,
} = require('./lib/vip-store');

const app = express();

const PORT = Math.max(1, Number(process.env.PORT || 3000));
const STATIC_DIR = path.resolve(process.env.STATIC_DIR || path.join(__dirname, 'public'));
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const DB_FILE = path.join(DATA_DIR, 'vip-db.json');
const GEMINI_API_KEY = String(process.env.GEMINI_API_KEY || '').trim();
const DEFAULT_GEMINI_MODEL = String(process.env.DEFAULT_GEMINI_MODEL || 'gemini-2.5-flash').trim();
const ALLOWED_MODELS = new Set(
  String(process.env.ALLOWED_GEMINI_MODELS || 'gemini-2.5-flash,gemini-2.5-flash-lite,gemini-2.0-flash')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
);
const SESSION_TTL_DAYS = Math.max(1, Number(process.env.SESSION_TTL_DAYS || 90));
const JSON_LIMIT = String(process.env.JSON_LIMIT || '35mb');
const RATE_WINDOW_MS = Math.max(1000, Number(process.env.RATE_WINDOW_MS || 10 * 60 * 1000));
const RATE_LIMIT = Math.max(1, Number(process.env.RATE_LIMIT || 40));
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '').trim();
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || 'owner').trim();
const ADMIN_SESSION_HOURS = Math.max(1, Number(process.env.ADMIN_SESSION_HOURS || 12));
const COOKIE_NAME = String(process.env.ADMIN_COOKIE_NAME || 'daly_admin').trim() || 'daly_admin';
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || '0') === '1';
const TRUST_PROXY = String(process.env.TRUST_PROXY || '0') === '1';
const rateBuckets = new Map();

if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.ip || req.socket.remoteAddress || 'unknown';
}

function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  const out = {};
  if (!raw) return out;
  for (const chunk of raw.split(';')) {
    const idx = chunk.indexOf('=');
    if (idx === -1) continue;
    const key = chunk.slice(0, idx).trim();
    const value = chunk.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch (_error) {
      out[key] = value;
    }
  }
  return out;
}

function serializeCookie(name, value, options) {
  const parts = [`${name}=${encodeURIComponent(String(value || ''))}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.trunc(options.maxAge))}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push('Secure');
  return parts.join('; ');
}

function setAdminCookie(res, token) {
  res.setHeader('Set-Cookie', serializeCookie(COOKIE_NAME, token, {
    maxAge: ADMIN_SESSION_HOURS * 60 * 60,
    path: '/',
    httpOnly: true,
    sameSite: 'Strict',
    secure: COOKIE_SECURE,
  }));
}

function clearAdminCookie(res) {
  res.setHeader('Set-Cookie', serializeCookie(COOKIE_NAME, '', {
    maxAge: 0,
    path: '/',
    httpOnly: true,
    sameSite: 'Strict',
    secure: COOKIE_SECURE,
  }));
}

function getBearerToken(req) {
  const auth = String(req.headers.authorization || '');
  if (!/^Bearer\s+/i.test(auth)) return '';
  return auth.replace(/^Bearer\s+/i, '').trim();
}

function secureCompareText(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
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
    resetAt: bucket.resetAt,
  };
}

function validateVipSession(req, db) {
  cleanupDb(db);
  const token = getBearerToken(req);
  const deviceId = sanitizeDeviceId(req.headers['x-device-id']);
  if (!token) return { ok: false, status: 401, message: 'VIP session is missing.' };

  const session = (db.sessions || []).find((item) => item.tokenHash === sha256(token));
  if (!session) return { ok: false, status: 401, message: 'VIP session not found or expired.' };
  if (session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now()) {
    return { ok: false, status: 401, message: 'VIP session expired.' };
  }
  if (deviceId && session.deviceId && deviceId !== session.deviceId) {
    return { ok: false, status: 401, message: 'VIP session does not match this device.' };
  }

  const code = (db.codes || []).find((item) => item.id === session.codeId);
  if (!code) return { ok: false, status: 403, message: 'VIP code no longer exists.' };
  if (code.revokedAt) return { ok: false, status: 403, message: 'VIP code was revoked.' };
  if (code.expiresAt && new Date(code.expiresAt).getTime() <= Date.now()) {
    return { ok: false, status: 403, message: 'VIP code expired.' };
  }

  session.lastSeenAt = nowIso();
  return { ok: true, session, code };
}

function validateAdminSession(req, db) {
  cleanupDb(db);
  const cookies = parseCookies(req);
  const token = String(cookies[COOKIE_NAME] || '').trim();
  if (!token) return { ok: false, status: 401, message: 'Admin session is missing.' };
  const session = (db.adminSessions || []).find((item) => item.tokenHash === sha256(token));
  if (!session) return { ok: false, status: 401, message: 'Admin session not found or expired.' };
  if (session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now()) {
    return { ok: false, status: 401, message: 'Admin session expired.' };
  }
  session.lastSeenAt = nowIso();
  return { ok: true, session };
}

function adminSummary(db) {
  cleanupDb(db);
  const now = Date.now();
  const codes = db.codes || [];
  const sessions = db.sessions || [];
  const activeCodes = codes.filter((code) => !code.revokedAt && !(code.expiresAt && new Date(code.expiresAt).getTime() <= now)).length;
  const revokedCodes = codes.filter((code) => code.revokedAt).length;
  const expiredCodes = codes.filter((code) => !code.revokedAt && code.expiresAt && new Date(code.expiresAt).getTime() <= now).length;
  return {
    totalCodes: codes.length,
    activeCodes,
    revokedCodes,
    expiredCodes,
    activeVipSessions: sessions.length,
    keyConfigured: Boolean(GEMINI_API_KEY),
    defaultModel: DEFAULT_GEMINI_MODEL,
    adminConfigured: Boolean(ADMIN_PASSWORD),
    serverTime: nowIso(),
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

app.get('/admin', (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'admin.html'));
});

app.get('/api/health', (_req, res) => {
  const db = loadDb(DB_FILE);
  res.json({ ok: true, ...adminSummary(db) });
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

  const db = loadDb(DB_FILE);
  cleanupDb(db);

  const code = (db.codes || []).find((item) => item.codeHash === sha256(codeInput));
  if (!code || code.revokedAt) {
    saveDb(DB_FILE, db);
    return res.status(403).json({ error: { message: 'Invalid activation code.' } });
  }
  if (code.expiresAt && new Date(code.expiresAt).getTime() <= Date.now()) {
    saveDb(DB_FILE, db);
    return res.status(403).json({ error: { message: 'Activation code has expired.' } });
  }

  if (!Array.isArray(code.redemptions)) code.redemptions = [];
  let redemption = code.redemptions.find((item) => item.deviceId === deviceId);
  const usedDevices = new Set(code.redemptions.map((item) => item.deviceId).filter(Boolean));
  const maxUses = Math.max(1, Number(code.maxUses || 1));

  if (!redemption && usedDevices.size >= maxUses) {
    saveDb(DB_FILE, db);
    return res.status(403).json({ error: { message: 'This code reached its device limit.' } });
  }

  if (!redemption) {
    redemption = { deviceId, firstRedeemedAt: nowIso(), lastRedeemedAt: nowIso() };
    code.redemptions.push(redemption);
  } else {
    redemption.lastRedeemedAt = nowIso();
  }

  db.sessions = (db.sessions || []).filter((session) => !(session.codeId === code.id && session.deviceId === deviceId));
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
    revokedAt: null,
  });

  saveDb(DB_FILE, db);
  res.json({
    ok: true,
    token: rawToken,
    label: code.label || code.codePreview || 'VIP',
    expiresAt,
    model: DEFAULT_GEMINI_MODEL,
  });
});

app.get('/api/vip/status', (req, res) => {
  const db = loadDb(DB_FILE);
  const auth = validateVipSession(req, db);
  if (!auth.ok) {
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }
  saveDb(DB_FILE, db);
  res.json({
    ok: true,
    label: auth.code.label || auth.code.codePreview || 'VIP',
    expiresAt: auth.session.expiresAt || null,
    model: DEFAULT_GEMINI_MODEL,
    redeemedDevices: Array.isArray(auth.code.redemptions) ? auth.code.redemptions.length : 0,
  });
});

app.post('/api/vip/logout', (req, res) => {
  const db = loadDb(DB_FILE);
  const token = getBearerToken(req);
  if (!token) {
    return res.json({ ok: true });
  }
  const tokenHash = sha256(token);
  db.sessions = (db.sessions || []).filter((session) => session.tokenHash !== tokenHash);
  saveDb(DB_FILE, db);
  res.json({ ok: true });
});

app.post('/api/gemini/generate', async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: { message: 'Server Gemini key is not configured yet.' } });
  }

  const db = loadDb(DB_FILE);
  const auth = validateVipSession(req, db);
  if (!auth.ok) {
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }

  const rate = takeRateSlot(`vip:${auth.session.id || auth.session.tokenHash}`);
  res.setHeader('X-RateLimit-Remaining', String(rate.remaining));
  res.setHeader('X-RateLimit-Reset', String(rate.resetAt));
  if (!rate.allowed) {
    saveDb(DB_FILE, db);
    return res.status(429).json({ error: { message: 'VIP request limit reached. Try again later.' } });
  }

  const requestedModel = String(req.body.model || '').trim();
  const model = ALLOWED_MODELS.has(requestedModel) ? requestedModel : DEFAULT_GEMINI_MODEL;
  const payload = req.body.payload;

  if (!payload || typeof payload !== 'object') {
    saveDb(DB_FILE, db);
    return res.status(400).json({ error: { message: 'Invalid Gemini payload.' } });
  }

  try {
    const upstream = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': GEMINI_API_KEY,
        },
        body: JSON.stringify(payload),
      }
    );

    const text = await upstream.text();
    saveDb(DB_FILE, db);
    res.status(upstream.status);
    res.type(upstream.headers.get('content-type') || 'application/json');
    res.send(text);
  } catch (error) {
    saveDb(DB_FILE, db);
    res.status(502).json({ error: { message: `Gemini proxy failed: ${error.message}` } });
  }
});

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ error: { message: 'ADMIN_PASSWORD is not configured yet.' } });
  }

  const ip = getClientIp(req);
  const rate = takeRateSlot(`admin-login:${ip}`);
  if (!rate.allowed) {
    return res.status(429).json({ error: { message: 'Too many login attempts. Try again later.' } });
  }

  const password = String(req.body.password || '');
  if (!secureCompareText(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: { message: 'Invalid admin password.' } });
  }

  const db = loadDb(DB_FILE);
  cleanupDb(db);
  const rawToken = crypto.randomBytes(32).toString('base64url');
  const expiresAt = addHours(ADMIN_SESSION_HOURS);
  db.adminSessions.push({
    id: crypto.randomUUID(),
    tokenHash: sha256(rawToken),
    createdAt: nowIso(),
    lastSeenAt: nowIso(),
    expiresAt,
    revokedAt: null,
    ipHint: ip,
  });
  saveDb(DB_FILE, db);
  setAdminCookie(res, rawToken);
  res.json({ ok: true, username: ADMIN_USERNAME, expiresAt, summary: adminSummary(db) });
});

app.post('/api/admin/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = String(cookies[COOKIE_NAME] || '').trim();
  const db = loadDb(DB_FILE);
  if (token) {
    db.adminSessions = (db.adminSessions || []).filter((session) => session.tokenHash !== sha256(token));
    saveDb(DB_FILE, db);
  }
  clearAdminCookie(res);
  res.json({ ok: true });
});

app.get('/api/admin/session', (req, res) => {
  const db = loadDb(DB_FILE);
  const auth = validateAdminSession(req, db);
  if (!auth.ok) {
    clearAdminCookie(res);
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message }, summary: adminSummary(db) });
  }
  saveDb(DB_FILE, db);
  res.json({ ok: true, username: ADMIN_USERNAME, expiresAt: auth.session.expiresAt, summary: adminSummary(db) });
});

app.get('/api/admin/codes', (req, res) => {
  const db = loadDb(DB_FILE);
  const auth = validateAdminSession(req, db);
  if (!auth.ok) {
    clearAdminCookie(res);
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }
  const items = listCodes(db);
  saveDb(DB_FILE, db);
  res.json({ ok: true, items, summary: adminSummary(db) });
});

app.post('/api/admin/codes', (req, res) => {
  const db = loadDb(DB_FILE);
  const auth = validateAdminSession(req, db);
  if (!auth.ok) {
    clearAdminCookie(res);
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }

  const maxUses = Math.max(1, Math.min(999, Number(req.body.maxUses || 1)));
  const days = Math.max(0, Math.min(3650, Number(req.body.days || 0)));
  const label = String(req.body.label || '').trim().slice(0, 120);
  const notes = String(req.body.notes || '').trim().slice(0, 500);

  const created = createCode(db, { label, notes, maxUses, days });
  saveDb(DB_FILE, db);
  res.json({
    ok: true,
    code: created.rawCode,
    item: listCodes(db).find((item) => item.id === created.code.id) || null,
    summary: adminSummary(db),
  });
});

app.post('/api/admin/codes/:id/revoke', (req, res) => {
  const db = loadDb(DB_FILE);
  const auth = validateAdminSession(req, db);
  if (!auth.ok) {
    clearAdminCookie(res);
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }
  const reason = String(req.body.reason || '').trim().slice(0, 200);
  const code = revokeCode(db, req.params.id, reason);
  if (!code) {
    saveDb(DB_FILE, db);
    return res.status(404).json({ error: { message: 'Activation code not found.' } });
  }
  saveDb(DB_FILE, db);
  res.json({ ok: true, item: listCodes(db).find((item) => item.id === code.id) || null, summary: adminSummary(db) });
});

app.post('/api/admin/codes/:id/remove-device', (req, res) => {
  const db = loadDb(DB_FILE);
  const auth = validateAdminSession(req, db);
  if (!auth.ok) {
    clearAdminCookie(res);
    saveDb(DB_FILE, db);
    return res.status(auth.status).json({ error: { message: auth.message } });
  }
  const deviceId = sanitizeDeviceId(req.body.deviceId);
  if (!deviceId) {
    saveDb(DB_FILE, db);
    return res.status(400).json({ error: { message: 'Device ID is required.' } });
  }
  const code = removeDeviceFromCode(db, req.params.id, deviceId);
  if (!code) {
    saveDb(DB_FILE, db);
    return res.status(404).json({ error: { message: 'Activation code not found.' } });
  }
  saveDb(DB_FILE, db);
  res.json({ ok: true, item: listCodes(db).find((item) => item.id === code.id) || null, summary: adminSummary(db) });
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
  console.log(`Static dir : ${STATIC_DIR}`);
  console.log(`DB file    : ${DB_FILE}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
});
