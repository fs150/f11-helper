#!/usr/bin/env node
const path = require('path');
try { require('dotenv').config(); } catch (_error) {}

const {
  loadDb,
  saveDb,
  createCode,
  listCodes,
  revokeCode,
  removeDeviceFromCode,
} = require('../lib/vip-store');

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
const DB_FILE = path.join(DATA_DIR, 'vip-db.json');

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (!value.startsWith('--')) {
      out._.push(value);
      continue;
    }
    const key = value.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      out[key] = true;
    } else {
      out[key] = next;
      i += 1;
    }
  }
  return out;
}

function printHelp() {
  console.log(`Usage:
  node scripts/vip-codes.js create --label "Ahmad" --uses 1 --days 90 --notes "optional"
  node scripts/vip-codes.js list
  node scripts/vip-codes.js revoke CODE_ID
  node scripts/vip-codes.js remove-device CODE_ID DEVICE_ID
`);
}

const argv = process.argv.slice(2);
const command = argv[0];
const flags = parseArgs(argv.slice(1));

if (!command || command === 'help' || command === '--help' || command === '-h') {
  printHelp();
  process.exit(0);
}

const db = loadDb(DB_FILE);

if (command === 'create') {
  const label = String(flags.label || '').trim();
  const notes = String(flags.notes || '').trim();
  const maxUses = Math.max(1, Number(flags.uses || flags.maxUses || 1));
  const days = Math.max(0, Number(flags.days || 0));
  const created = createCode(db, { label, notes, maxUses, days });
  saveDb(DB_FILE, db);
  const item = listCodes(db).find((entry) => entry.id === created.code.id);
  console.log(JSON.stringify({ ok: true, code: created.rawCode, item }, null, 2));
  process.exit(0);
}

if (command === 'list') {
  console.log(JSON.stringify({ ok: true, items: listCodes(db) }, null, 2));
  process.exit(0);
}

if (command === 'revoke') {
  const codeId = flags._[0];
  if (!codeId) {
    console.error('Missing CODE_ID');
    process.exit(1);
  }
  const code = revokeCode(db, codeId, String(flags.reason || '').trim());
  if (!code) {
    console.error('Activation code not found.');
    process.exit(1);
  }
  saveDb(DB_FILE, db);
  console.log(JSON.stringify({ ok: true, item: listCodes(db).find((entry) => entry.id === code.id) || null }, null, 2));
  process.exit(0);
}

if (command === 'remove-device') {
  const codeId = flags._[0];
  const deviceId = flags._[1];
  if (!codeId || !deviceId) {
    console.error('Missing CODE_ID or DEVICE_ID');
    process.exit(1);
  }
  const code = removeDeviceFromCode(db, codeId, deviceId);
  if (!code) {
    console.error('Activation code not found.');
    process.exit(1);
  }
  saveDb(DB_FILE, db);
  console.log(JSON.stringify({ ok: true, item: listCodes(db).find((entry) => entry.id === code.id) || null }, null, 2));
  process.exit(0);
}

printHelp();
process.exit(1);
