#!/usr/bin/env node
// Generates the TEST issuer's RSA-2048 keypair under .keys/ (gitignored).
// sign_credential.js creates one on first use, so this is only needed to rotate.
// Refuses to overwrite existing keys unless --force.

const path = require('path');
const { writeTestKeys, modulusHex, KEY_DIR, PUBLIC_EXPONENT } = require('./keys');

function main() {
  const started = Date.now();
  const { publicKey } = writeTestKeys({ force: process.argv.includes('--force') });
  const hex = modulusHex(publicKey);

  console.log(`[KEYGEN] TEST-ONLY RSA keypair: ${hex.length * 4}-bit, e=${PUBLIC_EXPONENT}, ${Date.now() - started}ms`);
  console.log(`[KEYGEN] Wrote ${path.relative(process.cwd(), KEY_DIR)}/ (private key mode 0600, gitignored)`);
  console.log(`[KEYGEN] Modulus (first 32 hex chars): ${hex.substring(0, 32)}...`);
  console.log('[KEYGEN] Never add this key to a trusted-issuer list. Next: node sign_credential.js');
}

try {
  main();
} catch (err) {
  console.error(`[KEYGEN] ${err.message}`);
  process.exit(1);
}
