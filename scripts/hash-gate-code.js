#!/usr/bin/env node
/**
 * Generate ACCESS_CODE_BCRYPT for Vercel / Neon gate.
 * Usage: node scripts/hash-gate-code.js YOURCODE
 * Same normalization as the server: trim, uppercase, strip non-alphanumeric.
 */
const bcrypt = require('bcryptjs');
const { MIN_CODE_LEN, MAX_CODE_LEN } = require('../lib/gate-backend.js');

const raw = process.argv[2];
if (!raw) {
    console.error('Usage: node scripts/hash-gate-code.js <access-code>');
    process.exit(1);
}

const normalized = String(raw)
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
if (normalized.length < MIN_CODE_LEN) {
    console.error(
        `Code must be at least ${MIN_CODE_LEN} letters/digits after normalization (max ${MAX_CODE_LEN}).`,
    );
    process.exit(1);
}

const hash = bcrypt.hashSync(normalized, 12);
console.log('\nAdd to Vercel (or .env for vercel dev):\n');
console.log('ACCESS_CODE_BCRYPT=' + hash);
console.log('\nAlso set GATE_SESSION_SECRET to a random string of at least 32 characters.');
console.log('Example: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n');
