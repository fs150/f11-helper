#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DATA_DIR, 'vip-db.json');

function ensureDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ version: 1, codes: [], sessions: [] }, null, 2));
  }
}

function loadDb() {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!Array.isArray(db.codes)) db.codes = [];
  if (!Array.isArray(db.sessions)) db.sessions = [];
  return db;
}

function saveDb(db) {
  const temp = DB_FILE + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(db, null, 2));
  fs.renameSync(temp, DB_FILE);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function normalizeCode(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function randomChunk(length) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  while (out.length < length) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (!item.startsWith('--')) continue;
    const key = item.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = 'true';
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const prefix = normalizeCode(args.prefix || 'DLYA').slice(0, 4) || 'DLYA';
const label = String(args.label || 'Friend').trim();
const maxUses = Math.max(1, Number(args.uses || 1));
const days = Number(args.days || 0);
const notes = String(args.notes || '').trim();
const plainCode = [prefix, randomChunk(4), randomChunk(4)].join('-');
const normalized = normalizeCode(plainCode);
const expiresAt = Number.isFinite(days) && days > 0
  ? (() => { const d = new Date(); d.setUTCDate(d.getUTCDate() + days); return d.toISOString(); })()
  : null;

const db = loadDb();
db.codes.push({
  id: crypto.randomUUID(),
  codeHash: sha256(normalized),
  codePreview: `${prefix}-****-${normalized.slice(-4)}`,
  label,
  maxUses,
  createdAt: new Date().toISOString(),
  expiresAt,
  revokedAt: null,
  notes,
  redemptions: []
});
saveDb(db);

console.log(JSON.stringify({
  ok: true,
  code: plainCode,
  label,
  maxUses,
  expiresAt,
  notes
}, null, 2));
