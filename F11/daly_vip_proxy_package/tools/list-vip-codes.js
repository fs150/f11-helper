#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, '..', 'data', 'vip-db.json');
if (!fs.existsSync(DB_FILE)) {
  console.log('No VIP database found yet.');
  process.exit(0);
}

const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const now = Date.now();
const rows = (db.codes || []).map(code => {
  const used = Array.isArray(code.redemptions) ? code.redemptions.length : 0;
  const expired = code.expiresAt && new Date(code.expiresAt).getTime() <= now;
  const status = code.revokedAt ? 'revoked' : (expired ? 'expired' : 'active');
  return {
    id: code.id,
    preview: code.codePreview || 'hidden',
    label: code.label || '',
    uses: `${used}/${code.maxUses || 1}`,
    status,
    expiresAt: code.expiresAt || 'never'
  };
});
console.table(rows);
