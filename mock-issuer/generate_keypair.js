#!/usr/bin/env node
// Generates the mock issuer's RSA-2048 keypair.
// Refuses to overwrite existing keys unless --force: rotating the key invalidates
// every signed credential and circuit input.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_BITS = 2048;
// Hardcoded by RSAVerifier65537 in the circuit.
const PUBLIC_EXPONENT = 65537;

const PRIVATE_KEY_PATH = path.join(__dirname, 'mock_issuer_private.pem');
const PUBLIC_KEY_PATH = path.join(__dirname, 'mock_issuer_public.pem');

function main() {
  const force = process.argv.includes('--force');

  const existing = [PRIVATE_KEY_PATH, PUBLIC_KEY_PATH].filter((p) => fs.existsSync(p));
  if (existing.length > 0 && !force) {
    console.error('[KEYGEN] Refusing to overwrite existing key material:');
    existing.forEach((p) => console.error(`[KEYGEN]   ${path.basename(p)}`));
    console.error('[KEYGEN]');
    console.error('[KEYGEN] Re-run with --force only if you intend to ROTATE the issuer key.');
    console.error('[KEYGEN] Rotation invalidates signed_credential.json and circuit_inputs.json;');
    console.error('[KEYGEN] re-run sign_credential.js immediately afterwards.');
    process.exit(1);
  }

  console.log(`[KEYGEN] Generating RSA keypair: ${KEY_BITS}-bit, e=${PUBLIC_EXPONENT}`);
  const started = Date.now();

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: KEY_BITS,
    publicExponent: PUBLIC_EXPONENT,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  console.log(`[KEYGEN] Generated in ${Date.now() - started}ms`);

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);

  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  const modulusHex = Buffer.from(jwk.n, 'base64url').toString('hex');

  console.log(`[KEYGEN] Wrote ${path.basename(PRIVATE_KEY_PATH)} (mode 0600)`);
  console.log(`[KEYGEN] Wrote ${path.basename(PUBLIC_KEY_PATH)}`);
  console.log(`[KEYGEN] Modulus (first 32 hex chars): ${modulusHex.substring(0, 32)}...`);
  console.log(`[KEYGEN] Modulus length: ${modulusHex.length / 2} bytes`);
  console.log('[KEYGEN] Next: node sign_credential.js');
}

main();
