#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, '..', 'data', 'vip-db.json');
if (!fs.existsSync(DB_FILE)) {
  console.error('VIP database not found.');
  process.exit(1);
}

const id = process.argv.slice(2).join(' ').trim();
if (!id) {
  console.error('Usage: node tools/revoke-vip-code.js <code-id>');
  process.exit(1);
}

const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const code = (db.codes || []).find(item => item.id === id);
if (!code) {
  console.error('Code ID not found.');
  process.exit(1);
}

code.revokedAt = new Date().toISOString();
db.sessions = (db.sessions || []).filter(session => session.codeId !== code.id);
fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
console.log(`Revoked: ${code.codePreview || code.id}`);
