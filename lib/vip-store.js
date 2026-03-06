const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function ensureDbFile(dbFile) {
  fs.mkdirSync(path.dirname(dbFile), { recursive: true });
  if (!fs.existsSync(dbFile)) {
    fs.writeFileSync(dbFile, JSON.stringify({ version: 2, codes: [], sessions: [], adminSessions: [] }, null, 2));
  }
}

function normalizeDb(db) {
  if (!db || typeof db !== 'object') db = {};
  db.version = Number(db.version || 2);
  if (!Array.isArray(db.codes)) db.codes = [];
  if (!Array.isArray(db.sessions)) db.sessions = [];
  if (!Array.isArray(db.adminSessions)) db.adminSessions = [];

  db.codes = db.codes.map((code) => ({
    id: String(code.id || crypto.randomUUID()),
    codeHash: String(code.codeHash || ''),
    codePreview: String(code.codePreview || ''),
    label: String(code.label || ''),
    notes: String(code.notes || ''),
    maxUses: Math.max(1, Number(code.maxUses || 1)),
    createdAt: String(code.createdAt || nowIso()),
    expiresAt: code.expiresAt ? String(code.expiresAt) : null,
    revokedAt: code.revokedAt ? String(code.revokedAt) : null,
    revokedReason: code.revokedReason ? String(code.revokedReason) : '',
    redemptions: Array.isArray(code.redemptions)
      ? code.redemptions
          .map((item) => ({
            deviceId: sanitizeDeviceId(item.deviceId),
            firstRedeemedAt: item.firstRedeemedAt ? String(item.firstRedeemedAt) : null,
            lastRedeemedAt: item.lastRedeemedAt ? String(item.lastRedeemedAt) : null,
          }))
          .filter((item) => item.deviceId)
      : [],
  }));

  db.sessions = db.sessions.map((session) => ({
    id: String(session.id || crypto.randomUUID()),
    tokenHash: String(session.tokenHash || ''),
    deviceId: sanitizeDeviceId(session.deviceId),
    codeId: String(session.codeId || ''),
    label: String(session.label || ''),
    createdAt: String(session.createdAt || nowIso()),
    lastSeenAt: String(session.lastSeenAt || session.createdAt || nowIso()),
    expiresAt: session.expiresAt ? String(session.expiresAt) : null,
    revokedAt: session.revokedAt ? String(session.revokedAt) : null,
  })).filter((session) => session.tokenHash && session.codeId);

  db.adminSessions = db.adminSessions.map((session) => ({
    id: String(session.id || crypto.randomUUID()),
    tokenHash: String(session.tokenHash || ''),
    createdAt: String(session.createdAt || nowIso()),
    lastSeenAt: String(session.lastSeenAt || session.createdAt || nowIso()),
    expiresAt: session.expiresAt ? String(session.expiresAt) : null,
    revokedAt: session.revokedAt ? String(session.revokedAt) : null,
    ipHint: String(session.ipHint || ''),
  })).filter((session) => session.tokenHash);

  return db;
}

function loadDb(dbFile) {
  ensureDbFile(dbFile);
  const raw = fs.readFileSync(dbFile, 'utf8');
  let db;
  try {
    db = JSON.parse(raw || '{}');
  } catch (_error) {
    db = { version: 2, codes: [], sessions: [], adminSessions: [] };
  }
  return normalizeDb(db);
}

function saveDb(dbFile, db) {
  ensureDbFile(dbFile);
  const tmp = dbFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(normalizeDb(db), null, 2));
  fs.renameSync(tmp, dbFile);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function nowIso() {
  return new Date().toISOString();
}

function addDays(days) {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + Number(days || 0));
  return date.toISOString();
}

function addHours(hours) {
  const date = new Date();
  date.setTime(date.getTime() + Number(hours || 0) * 60 * 60 * 1000);
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

function formatCode(value) {
  const cleaned = normalizeCode(value);
  return cleaned ? cleaned.match(/.{1,4}/g).join('-') : '';
}

function codePreviewFromRaw(rawCode) {
  const cleaned = normalizeCode(rawCode);
  if (!cleaned) return '';
  const head = cleaned.slice(0, 4);
  const tail = cleaned.slice(-4);
  return `${head}-****-${tail}`;
}

function sanitizeDeviceId(value) {
  return String(value || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80);
}

function cleanupDb(db) {
  const now = Date.now();
  db.sessions = (db.sessions || []).filter((session) => {
    if (session.revokedAt) return false;
    if (session.expiresAt && new Date(session.expiresAt).getTime() <= now) return false;
    return true;
  });
  db.adminSessions = (db.adminSessions || []).filter((session) => {
    if (session.revokedAt) return false;
    if (session.expiresAt && new Date(session.expiresAt).getTime() <= now) return false;
    return true;
  });
  return db;
}

function parseIntSafe(value, fallback) {
  const num = Number(value);
  return Number.isFinite(num) ? Math.trunc(num) : fallback;
}

function generateRawCode(db) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for (let attempt = 0; attempt < 20; attempt += 1) {
    let cleaned = '';
    for (let i = 0; i < 12; i += 1) {
      const idx = crypto.randomInt(0, alphabet.length);
      cleaned += alphabet[idx];
    }
    const hash = sha256(cleaned);
    if (!(db.codes || []).some((code) => code.codeHash === hash)) {
      return formatCode(cleaned);
    }
  }
  throw new Error('Could not generate a unique activation code.');
}

function createCode(db, options) {
  cleanupDb(db);
  const rawCode = generateRawCode(db);
  const cleaned = normalizeCode(rawCode);
  const maxUses = Math.max(1, parseIntSafe(options.maxUses, 1));
  const days = Math.max(0, parseIntSafe(options.days, 0));
  const code = {
    id: crypto.randomUUID(),
    codeHash: sha256(cleaned),
    codePreview: codePreviewFromRaw(cleaned),
    label: String(options.label || '').trim(),
    notes: String(options.notes || '').trim(),
    maxUses,
    createdAt: nowIso(),
    expiresAt: days > 0 ? addDays(days) : null,
    revokedAt: null,
    revokedReason: '',
    redemptions: [],
  };
  db.codes.push(code);
  return { rawCode: formatCode(cleaned), code };
}

function summarizeCode(db, code) {
  const now = Date.now();
  const usedDevices = new Set((code.redemptions || []).map((item) => sanitizeDeviceId(item.deviceId)).filter(Boolean)).size;
  const activeSessions = (db.sessions || []).filter((session) => {
    if (session.codeId !== code.id) return false;
    if (session.revokedAt) return false;
    if (session.expiresAt && new Date(session.expiresAt).getTime() <= now) return false;
    return true;
  }).length;
  const expired = Boolean(code.expiresAt && new Date(code.expiresAt).getTime() <= now);
  const status = code.revokedAt ? 'revoked' : expired ? 'expired' : 'active';
  let lastRedeemedAt = null;
  for (const redemption of code.redemptions || []) {
    const ts = redemption.lastRedeemedAt || redemption.firstRedeemedAt || null;
    if (ts && (!lastRedeemedAt || new Date(ts).getTime() > new Date(lastRedeemedAt).getTime())) {
      lastRedeemedAt = ts;
    }
  }
  return {
    id: code.id,
    label: code.label || '',
    notes: code.notes || '',
    codePreview: code.codePreview || '',
    maxUses: Math.max(1, Number(code.maxUses || 1)),
    usedDevices,
    remainingDevices: Math.max(0, Math.max(1, Number(code.maxUses || 1)) - usedDevices),
    createdAt: code.createdAt || null,
    expiresAt: code.expiresAt || null,
    revokedAt: code.revokedAt || null,
    revokedReason: code.revokedReason || '',
    activeSessions,
    status,
    lastRedeemedAt,
    redemptions: (code.redemptions || []).map((item) => ({
      deviceId: sanitizeDeviceId(item.deviceId),
      firstRedeemedAt: item.firstRedeemedAt || null,
      lastRedeemedAt: item.lastRedeemedAt || null,
    })),
  };
}

function listCodes(db) {
  cleanupDb(db);
  return (db.codes || [])
    .map((code) => summarizeCode(db, code))
    .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
}

function revokeCode(db, codeId, reason) {
  cleanupDb(db);
  const code = (db.codes || []).find((item) => item.id === String(codeId || ''));
  if (!code) return null;
  if (!code.revokedAt) {
    code.revokedAt = nowIso();
    code.revokedReason = String(reason || '').trim();
  }
  db.sessions = (db.sessions || []).filter((session) => session.codeId !== code.id);
  return code;
}

function removeDeviceFromCode(db, codeId, deviceId) {
  cleanupDb(db);
  const code = (db.codes || []).find((item) => item.id === String(codeId || ''));
  const cleanDevice = sanitizeDeviceId(deviceId);
  if (!code || !cleanDevice) return null;
  code.redemptions = (code.redemptions || []).filter((item) => sanitizeDeviceId(item.deviceId) !== cleanDevice);
  db.sessions = (db.sessions || []).filter((session) => !(session.codeId === code.id && sanitizeDeviceId(session.deviceId) === cleanDevice));
  return code;
}

module.exports = {
  ensureDbFile,
  loadDb,
  saveDb,
  sha256,
  nowIso,
  addDays,
  addHours,
  minExpiry,
  normalizeCode,
  formatCode,
  codePreviewFromRaw,
  sanitizeDeviceId,
  cleanupDb,
  createCode,
  summarizeCode,
  listCodes,
  revokeCode,
  removeDeviceFromCode,
};
